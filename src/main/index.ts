import { app, type BrowserWindow, dialog, nativeTheme, net, safeStorage, shell } from 'electron';
import path from 'node:path';
import type { AuthPrompt, Language, ProfileInput, Settings, SystemInfo, VpnState } from '../shared/ipc';
import { IPC } from '../shared/ipc';
import { fetchPrelogin } from './auth/prelogin';
import { clearSamlPartition, runSamlLogin } from './auth/saml-window';
import { setLaunchAtLogin, startedHidden } from './autostart';
import { registerIpcHandlers } from './ipc/handlers';
import { Logger } from './logging/logger';
import { locateOpenconnect } from './openconnect/locate';
import { createTrustCache, verifyTrustedFile } from './openconnect/trust';
import { createDiscoveryReporter, openconnectSystemInfo, type DiscoveryResult } from './openconnect/discovery-log';
import { readOpenconnectVersion } from './openconnect/version';
import { appIconPath, bundledBinDir, logsDir, trayIconDir, userDataFile } from './paths';
import { createPlatformSpawner } from './process/create-spawner';
import { blockWebviews, hardenDefaultSession, type RendererLocation } from './security';
import { ProfilesStore, type SecretCipher } from './store/profiles-store';
import { confirmDialogText, type ConfirmItem, type ConfirmKind } from './store/confirm-dialog';
import { ConfirmedSettingsGuard } from './store/confirmed-settings';
import { sensitiveChanges, showSettingValue } from './store/sensitive-settings';
import { SettingsStore } from './store/settings-store';
import { notConfirmedError } from './store/validation';
import { AppTray } from './tray';
import { VpnEngine } from './vpn/engine';
import { VpnError } from './vpn/errors';
import { applyThemeToWindow, createMainWindow, showWindow } from './window';

const isDev = !app.isPackaged;
const platform = process.platform as SystemInfo['platform'];

let mainWindow: BrowserWindow | null = null;
let tray: AppTray | null = null;
let quitting = false;

function safeStorageCipher(): SecretCipher {
  return {
    isAvailable: () => {
      if (!safeStorage.isEncryptionAvailable()) return false;
      // On Linux without a keyring Chromium falls back to a hard-coded key: not acceptable.
      if (process.platform === 'linux') {
        const backend = safeStorage.getSelectedStorageBackend();
        return backend !== 'basic_text' && backend !== 'unknown';
      }
      return true;
    },
    encrypt: (plain) => safeStorage.encryptString(plain),
    decrypt: (data) => safeStorage.decryptString(data),
  };
}

function send(channel: string, payload: unknown): void {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
}

async function bootstrap(): Promise<void> {
  const logger = new Logger(logsDir());
  logger.info(
    'app',
    `GP Connect ${app.getVersion()} on ${process.platform} ${process.arch}, Electron ${process.versions.electron}`,
  );

  const settingsStore = new SettingsStore(userDataFile('settings.json'), (m) => logger.warn('settings', m));
  const profiles = new ProfilesStore(userDataFile('profiles.json'), safeStorageCipher(), (m) =>
    logger.warn('profiles', m),
  );
  nativeTheme.themeSource = settingsStore.get().theme;

  // ---- openconnect discovery (cached; refreshed on demand and on settings change)
  // Discovery is logged only when its result changes (it runs on startup, system.info and connect).
  const reportDiscovery = createDiscoveryReporter((l) => logger[l.level]('openconnect', l.msg));
  // Discovery only (system.info, locate); elevation always re-checks uncached.
  const discoveryTrust = createTrustCache({ platform: process.platform });
  let located: Promise<DiscoveryResult> | null = null;
  const findOpenconnect = (refresh = false): Promise<DiscoveryResult> => {
    if (!located || refresh) {
      located = (async () => {
        const found = await locateOpenconnect({
          platform: process.platform,
          configuredPath: settingsStore.get().openconnectPath,
          bundledBinDir: bundledBinDir(),
          envPath: process.env.PATH,
          isTrusted: discoveryTrust,
        });
        const version = found ? await readOpenconnectVersion(found.path) : undefined;
        reportDiscovery(found, version);
        return found ? { path: found.path, version, trusted: found.trusted } : { path: null };
      })();
    }
    return located;
  };

  // ---- confirmation of elevation-relevant settings (openconnectPath, hipScriptPath, extraArgs)
  const confirmedGuard = new ConfirmedSettingsGuard(userDataFile('confirmed-settings.json'), safeStorageCipher(), (m) =>
    logger.warn('settings', m),
  );
  const confirmElevationSettings = async (
    kind: ConfirmKind,
    lang: Language,
    items: readonly ConfirmItem[],
  ): Promise<boolean> => {
    const text = confirmDialogText(kind, lang, items);
    const opts: Electron.MessageBoxOptions = {
      type: 'warning',
      buttons: text.buttons,
      defaultId: 0, // Cancel
      cancelId: 0,
      noLink: true,
      title: text.title,
      message: text.message,
      detail: text.detail,
    };
    const owner = mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined;
    const { response } = owner ? await dialog.showMessageBox(owner, opts) : await dialog.showMessageBox(opts);
    return response === 1;
  };
  /** Values changed on disk (not via the confirmed IPC path) must be confirmed before elevation. */
  const ensureSettingsConfirmed = async (): Promise<void> => {
    const s = settingsStore.get();
    const unconfirmed = confirmedGuard.unconfirmedFields(s);
    if (unconfirmed.length === 0) return;
    const ok = await confirmElevationSettings(
      'external',
      s.language,
      unconfirmed.map((key) => ({ key, value: s[key], external: true })),
    );
    if (!ok) {
      logger.warn(
        'settings',
        `Externally changed elevation settings were not confirmed: ${unconfirmed
          .map((k) => `${k}=${showSettingValue(s[k])}`)
          .join('; ')}`,
      );
      const err = new VpnError('PRIVILEGES_DENIED', 'Changed openconnect settings were not confirmed');
      err.hint = 'settings_not_confirmed';
      throw err;
    }
    confirmedGuard.confirm(s, unconfirmed);
  };

  const renderer: RendererLocation = {
    devUrl: isDev ? process.env.ELECTRON_RENDERER_URL : undefined,
    indexHtml: path.join(__dirname, '../renderer/index.html'),
  };

  const engine = new VpnEngine({
    platform: process.platform,
    getProfile: (id) => profiles.get(id),
    getSavedPassword: (id) => profiles.getPassword(id),
    getSettings: () => settingsStore.get(),
    prelogin: (portalUrl, signal) =>
      fetchPrelogin(portalUrl, {
        platform: process.platform,
        signal,
        fetch: (input, init) => net.fetch(input, init),
      }),
    samlLogin: (profile, prelogin, signal) =>
      runSamlLogin({
        profileId: profile.id,
        prelogin,
        signal,
        logger,
        parent: null,
        title: `${profile.name} — SSO`,
        allowedHosts: [new URL(profile.portalUrl).host],
      }),
    locateOpenconnect: async () => (await findOpenconnect(true)).path,
    verifyElevatedFiles: async ({ binary, hipScriptPath }) => {
      await ensureSettingsConfirmed();
      return {
        binary: await verifyTrustedFile(binary, { platform: process.platform }),
        hipScriptPath:
          hipScriptPath === undefined
            ? undefined
            : await verifyTrustedFile(hipScriptPath, { platform: process.platform }),
      };
    },
    spawner: createPlatformSpawner(process.platform, (m) => logger.info('vpn', m)),
    logger,
  });

  hardenDefaultSession(renderer, () => (mainWindow && !mainWindow.isDestroyed() ? mainWindow.webContents : null));
  blockWebviews();

  mainWindow = createMainWindow({
    preload: path.join(__dirname, '../preload/index.js'),
    renderer,
    icon: process.platform === 'linux' ? appIconPath() : undefined,
    isDev,
    show: !startedHidden(),
  });
  const win = mainWindow;
  win.on('close', (event) => {
    if (!quitting) {
      event.preventDefault();
      win.hide();
    }
  });
  win.on('closed', () => {
    mainWindow = null;
  });
  // A reloaded renderer must still be able to answer an open prompt.
  win.webContents.on('did-finish-load', () => {
    for (const p of engine.getPendingPrompts()) send(IPC.vpn.prompt, p);
  });

  // ---- tray
  const refreshTray = (state: VpnState = engine.getState()): void => {
    const s = settingsStore.get();
    tray?.update({
      state,
      profiles: profiles.list(),
      selectedProfileId: state.profileId ?? s.lastProfileId,
      language: s.language,
    });
  };

  const connect = async (profileId: string, opts: { gateway?: string; password?: string } = {}): Promise<void> => {
    await engine.connect(profileId, opts);
    if (settingsStore.get().lastProfileId !== profileId) settingsStore.set({ lastProfileId: profileId });
  };

  tray = new AppTray(trayIconDir(), {
    connect: (id) => void connect(id).catch((err: unknown) => logger.error('tray', 'Connect failed', err)),
    disconnect: () => void engine.disconnect(),
    selectProfile: (id) => {
      settingsStore.set({ lastProfileId: id });
      refreshTray();
    },
    show: () => showWindow(mainWindow),
    quit: () => app.quit(),
  });
  refreshTray();

  // ---- engine → renderer / tray
  engine.onState((state) => {
    send(IPC.vpn.state, state);
    refreshTray(state);
  });
  engine.onPrompt((prompt: AuthPrompt) => {
    showWindow(mainWindow);
    send(IPC.vpn.prompt, prompt);
  });
  logger.onLine((line) => send(IPC.logs.line, line));

  // ---- theme
  nativeTheme.on('updated', () => {
    const dark = nativeTheme.shouldUseDarkColors;
    if (mainWindow) applyThemeToWindow(mainWindow, dark);
    send(IPC.system.themeChanged, dark);
  });

  settingsStore.onChange((next: Settings, prev: Settings) => {
    if (next.theme !== prev.theme) nativeTheme.themeSource = next.theme;
    if (next.launchAtLogin !== prev.launchAtLogin) {
      try {
        setLaunchAtLogin(next.launchAtLogin);
      } catch (err) {
        logger.error('settings', 'Failed to update launch at login', err);
      }
    }
    if (next.openconnectPath !== prev.openconnectPath) void findOpenconnect(true);
    if (next.language !== prev.language) {
      refreshTray();
      engine.relocalize(); // existing error message follows the new language
    }
  });

  registerIpcHandlers({
    logger,
    renderer,
    trustedContents: () => (mainWindow && !mainWindow.isDestroyed() ? mainWindow.webContents : null),
    backend: {
      listProfiles: () => profiles.list(),
      saveProfile: (p: ProfileInput, password?: string) => {
        const saved = profiles.save(p, password);
        refreshTray();
        return saved;
      },
      removeProfile: async (id) => {
        profiles.remove(id);
        await clearSamlPartition(id).catch((err: unknown) =>
          logger.warn('profiles', `Failed to clear SSO data: ${err instanceof Error ? err.message : String(err)}`),
        );
        if (settingsStore.get().lastProfileId === id) settingsStore.set({ lastProfileId: undefined });
        refreshTray();
      },
      connect: (id, opts) => connect(id, opts),
      disconnect: () => engine.disconnect(),
      getState: () => engine.getState(),
      answerPrompt: (id, value) => engine.answerPrompt(id, value),
      getPendingPrompts: () => engine.getPendingPrompts(),
      getLogs: () => logger.lines(),
      openLogsFolder: async () => {
        const err = await shell.openPath(logsDir());
        if (err) throw new Error(err);
      },
      getSettings: () => settingsStore.get(),
      setSettings: async (patch) => {
        const current = settingsStore.get();
        const changes = sensitiveChanges(current, patch);
        if (changes.length > 0) {
          // Also show (and only then confirm) guarded values that were edited on
          // disk and never confirmed, so they cannot ride along silently.
          const prospective: Settings = { ...current, ...patch };
          const changedKeys = changes.map((c) => c.key);
          const extra = confirmedGuard.unconfirmedFields(prospective).filter((k) => !changedKeys.includes(k));
          const lines = [
            ...changes.map((c) => `${c.key}: ${c.value}`),
            ...extra.map((k) => `${k}: ${showSettingValue(prospective[k])} (changed outside GP Connect)`),
          ];
          const ok = await confirmElevationSettings('change', prospective.language, [
            ...changedKeys.map((key) => ({ key, value: prospective[key] })),
            ...extra.map((key) => ({ key, value: prospective[key], external: true })),
          ]);
          if (!ok) {
            logger.warn('settings', `Change of ${[...changedKeys, ...extra].join(', ')} was not confirmed`);
            throw notConfirmedError();
          }
          logger.info('settings', `Confirmed: ${lines.join('; ')}`);
          const next = settingsStore.set(patch);
          confirmedGuard.confirm(next, [...changedKeys, ...extra]);
          return next;
        }
        return settingsStore.set(patch);
      },
      systemInfo: async () => {
        const oc = await findOpenconnect(true);
        return {
          platform,
          ...openconnectSystemInfo(oc),
          appVersion: app.getVersion(),
          shouldUseDarkColors: nativeTheme.shouldUseDarkColors,
        };
      },
      openExternal: (url) => shell.openExternal(url),
      minimizeWindow: () => mainWindow?.minimize(),
      closeWindow: () => mainWindow?.close(),
    },
  });

  // ---- lifecycle
  app.on('second-instance', () => showWindow(mainWindow));
  app.on('activate', () => showWindow(mainWindow));
  app.on('window-all-closed', () => {
    // Tray app: keep running.
  });
  let shutdownDone = false;
  app.on('before-quit', (event) => {
    quitting = true;
    if (shutdownDone) return;
    event.preventDefault();
    void engine
      .shutdown()
      .catch((err: unknown) => logger.error('app', 'Shutdown failed', err))
      .finally(() => {
        shutdownDone = true;
        tray?.destroy();
        logger.info('app', 'Bye');
        logger.close();
        app.quit();
      });
  });

  const s = settingsStore.get();
  if (s.connectOnStartup && s.lastProfileId && profiles.get(s.lastProfileId)) {
    void connect(s.lastProfileId).catch((err: unknown) => logger.error('app', 'Connect on startup failed', err));
  } else {
    void findOpenconnect();
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.setAppUserModelId('com.gpconnect.app');
  void app
    .whenReady()
    .then(bootstrap)
    .catch((err: unknown) => {
      console.error('GP Connect failed to start', err);
      app.exit(1);
    });
}
