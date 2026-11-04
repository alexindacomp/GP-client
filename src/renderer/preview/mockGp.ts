/**
 * DEV-ONLY in-browser mock of `window.gp` for design review (`npm run preview:web`).
 * Loaded only by preview/index.html, which is not an input of the Electron build
 * (electron.vite.config.ts builds src/renderer/index.html only), and it refuses to
 * install when the real preload API is present.
 *
 * Query parameters:
 *   theme=system|light|dark   settings.theme            dark=1           OS dark mode for theme=system
 *   platform=win32|darwin|linux                          lang=ru|en|uk
 *   state=disconnected|connecting|connected|reconnecting|stop-failed|error|prompt-password|prompt-otp|prompt-select|prompt-text
 *   error=<VpnErrorCode>      error for state=error and for the next connect (fail=… also works)
 *   hint=untrusted_binary|untrusted_homebrew|settings_not_confirmed   cause-specific error (code PRIVILEGES_DENIED)
 *   profiles=0                no profiles (onboarding)  openconnect=0    openconnect not found
 *   trusted=0                 openconnect found but in an unprotected folder (system.info().openconnectTrusted=false)
 *   frame=0                   no 380×600 window frame
 */
import type {
  AuthPrompt,
  GpApi,
  Profile,
  ProfileInput,
  Settings,
  SystemInfo,
  Language,
  VpnErrorCode,
  VpnErrorHint,
  VpnState,
} from '@shared/ipc';
import { DEFAULT_SETTINGS } from '@shared/ipc';
import {
  checkExtraArgs,
  formatIpcError,
  isAbsolutePath,
  isOpenconnectBinaryPath,
  type IpcErrorInfo,
} from '@shared/validation';

type Listener<T> = (v: T) => void;

function emitter<T>() {
  const set = new Set<Listener<T>>();
  return {
    on(cb: Listener<T>) {
      set.add(cb);
      return () => void set.delete(cb);
    },
    emit(v: T) {
      for (const cb of [...set]) cb(structuredClone(v));
    },
  };
}

/** Rejection as Electron delivers main's marked errors: `…: Error: [field:f][code:c] message`. */
const ipcError = (channel: string, info: IpcErrorInfo): Error =>
  new Error(`Error invoking remote method '${channel}': Error: ${formatIpcError(info)}`);
const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

type Lang = Language;

/** Where main would find openconnect (`trusted=0` pretends it's an unprotected location). */
const DEFAULT_OC_PATH: Record<SystemInfo['platform'], string> = {
  win32: 'C:\\Program Files\\OpenConnect-GUI\\openconnect.exe',
  darwin: '/opt/homebrew/bin/openconnect',
  linux: '/usr/sbin/openconnect',
};
type Platform = SystemInfo['platform'];

/** Same `message` texts as src/main/vpn/messages.ts. */
const MESSAGES: Record<Lang, Record<VpnErrorCode, string>> = {
  ru: {
    OPENCONNECT_NOT_FOUND: 'Установите OpenConnect или укажите путь к нему в настройках.',
    AUTH_FAILED: 'Проверьте логин, пароль или одноразовый код и попробуйте снова.',
    AUTH_CANCELLED: 'Нажмите «Подключить», чтобы войти снова.',
    PORTAL_UNREACHABLE: 'Проверьте адрес портала и подключение к сети.',
    TLS_ERROR:
      'Сервер предъявил неизвестный сертификат. Если вы доверяете ему, добавьте в доп. аргументы --servercert=pin-sha256:<…> — значение pin есть в журнале.',
    PRIVILEGES_DENIED: 'Подтвердите запрос прав администратора при подключении.',
    TUNNEL_FAILED: 'Попробуйте подключиться снова; подробности — в журнале.',
    UNKNOWN: 'Попробуйте подключиться снова; подробности — в журнале.',
  },
  en: {
    OPENCONNECT_NOT_FOUND: 'Install OpenConnect or set its path in Settings.',
    AUTH_FAILED: 'Check your username, password or one-time code and try again.',
    AUTH_CANCELLED: 'Press Connect to sign in again.',
    PORTAL_UNREACHABLE: 'Check the portal address and your network connection.',
    TLS_ERROR:
      'The server presented an unknown certificate. If you trust it, add --servercert=pin-sha256:<…> to extra arguments — the pin value is in the log.',
    PRIVILEGES_DENIED: 'Approve the administrator prompt when connecting.',
    TUNNEL_FAILED: 'Try connecting again; see the log for details.',
    UNKNOWN: 'Try connecting again; see the log for details.',
  },
  uk: {
    OPENCONNECT_NOT_FOUND: 'Встановіть OpenConnect або вкажіть шлях до нього в налаштуваннях.',
    AUTH_FAILED: 'Перевірте логін, пароль або одноразовий код і спробуйте ще раз.',
    AUTH_CANCELLED: 'Натисніть «Підключити», щоб увійти знову.',
    PORTAL_UNREACHABLE: 'Перевірте адресу порталу та підключення до мережі.',
    TLS_ERROR:
      'Сервер надав невідомий сертифікат. Якщо ви йому довіряєте, додайте в додаткові аргументи --servercert=pin-sha256:<…> — значення pin є в журналі.',
    PRIVILEGES_DENIED: 'Підтвердьте запит прав адміністратора під час підключення.',
    TUNNEL_FAILED: 'Спробуйте підключитися ще раз; подробиці — у журналі.',
    UNKNOWN: 'Спробуйте підключитися ще раз; подробиці — у журналі.',
  },
};

const UNTRUSTED_BINARY: Record<Lang, Record<Platform, string>> = {
  ru: {
    win32:
      'Установите OpenConnect в «Program Files» (через установщик OpenConnect-GUI) — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
    darwin:
      'Установите OpenConnect через MacPorts: sudo port install openconnect — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
    linux:
      'Установите OpenConnect из репозитория (sudo apt install openconnect — он окажется в /usr/sbin или /usr/bin) — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
  },
  en: {
    win32:
      'Install OpenConnect into “Program Files” (with the OpenConnect-GUI installer) — the client only runs openconnect from folders that only an administrator can change.',
    darwin:
      'Install OpenConnect with MacPorts: sudo port install openconnect — the client only runs openconnect from folders that only an administrator can change.',
    linux:
      'Install OpenConnect from your distribution (sudo apt install openconnect — it goes to /usr/sbin or /usr/bin) — the client only runs openconnect from folders that only an administrator can change.',
  },
  uk: {
    win32:
      'Встановіть OpenConnect у «Program Files» (через інсталятор OpenConnect-GUI) — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
    darwin:
      'Встановіть OpenConnect через MacPorts: sudo port install openconnect — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
    linux:
      'Встановіть OpenConnect із репозиторію (sudo apt install openconnect — він опиниться в /usr/sbin або /usr/bin) — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
  },
};

const OTHER_HINTS: Record<Lang, Record<Exclude<VpnErrorHint, 'untrusted_binary'>, string>> = {
  ru: {
    untrusted_homebrew:
      'OpenConnect из Homebrew может изменить любая программа пользователя. Установите его через MacPorts: sudo port install openconnect.',
    stop_failed:
      'VPN может быть ещё активен: для остановки openconnect нужна авторизация администратора. Нажмите «Отключить» ещё раз.',
    settings_not_confirmed:
      'Подключитесь снова и подтвердите изменённые настройки openconnect или исправьте их в настройках.',
  },
  en: {
    untrusted_homebrew:
      'Homebrew’s OpenConnect can be modified by any of your programs. Install it with MacPorts: sudo port install openconnect.',
    stop_failed:
      'The VPN may still be active: stopping openconnect needs administrator authorization. Press Disconnect again.',
    settings_not_confirmed: 'Connect again and confirm the changed openconnect settings, or correct them in Settings.',
  },
  uk: {
    untrusted_homebrew:
      'OpenConnect із Homebrew може змінити будь-яка програма користувача. Встановіть його через MacPorts: sudo port install openconnect.',
    stop_failed:
      'VPN може бути ще активним: для зупинки openconnect потрібна авторизація адміністратора. Натисніть «Відключити» ще раз.',
    settings_not_confirmed:
      'Підключіться знову й підтвердьте змінені налаштування openconnect або виправте їх у налаштуваннях.',
  },
};

/** Sample technical causes (untranslated, like main's `detail`). */
const DETAILS: Partial<Record<VpnErrorCode | VpnErrorHint, string>> = {
  AUTH_FAILED: 'Login failed. (gateway auth: 512 Invalid username or password)',
  PORTAL_UNREACHABLE: 'getaddrinfo ENOTFOUND vpn.example.com',
  TLS_ERROR: 'Server certificate verify failed: signer not found',
  TUNNEL_FAILED: 'vpnc-script exited with status 1',
  untrusted_binary: 'C:\\Users\\ivan\\Downloads\\openconnect\\openconnect.exe is writable by non-administrators',
  untrusted_homebrew: '/opt/homebrew/bin/openconnect is owned by uid 501',
};

function vpnError(
  code: VpnErrorCode,
  lang: Lang,
  platform: Platform,
  hint?: VpnErrorHint,
): NonNullable<VpnState['error']> {
  const message =
    hint === 'untrusted_binary'
      ? UNTRUSTED_BINARY[lang][platform]
      : hint
        ? OTHER_HINTS[lang][hint]
        : MESSAGES[lang][code];
  const detail = DETAILS[hint ?? code];
  return { code, message, ...(hint ? { hint } : {}), ...(detail ? { detail } : {}) };
}

export function installMockGp(): void {
  if ((window as Partial<Window>).gp) return; // real preload present: never mock
  const q = new URLSearchParams(window.location.search);
  const platform = (q.get('platform') as SystemInfo['platform'] | null) ?? 'win32';
  const scenario = q.get('state') ?? 'disconnected';
  const failHint = (q.get('hint') as VpnErrorHint | null) ?? undefined;
  const failCode =
    ((q.get('fail') ?? q.get('error')) as VpnErrorCode | null) ?? (failHint ? 'PRIVILEGES_DENIED' : null);
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let osDark = q.has('dark') ? q.get('dark') === '1' : media.matches;

  const profiles: Profile[] =
    q.get('profiles') === '0'
      ? []
      : [
          {
            id: '6f1c2a3e-1111-4a6b-9c1d-000000000001',
            name: 'Работа',
            portalUrl: 'https://vpn.example.com',
            username: 'i.ivanov',
            authMode: 'auto',
            savePassword: false,
          },
          {
            id: '6f1c2a3e-1111-4a6b-9c1d-000000000002',
            name: 'Филиал Новосибирск',
            portalUrl: 'https://gp.branch.example.org:4443',
            authMode: 'saml',
            preferredGateway: 'nsk-gw1',
            savePassword: false,
          },
        ];
  const savedPasswords = new Set<string>();
  let settings: Settings = {
    ...DEFAULT_SETTINGS,
    theme: (q.get('theme') as Settings['theme'] | null) ?? 'system',
    language: (q.get('lang') as Settings['language'] | null) ?? 'ru',
    lastProfileId: profiles[0]?.id,
  };
  let openconnectFound = q.get('openconnect') !== '0';
  const trusted = q.get('trusted') !== '0';

  const states = emitter<VpnState>();
  const prompts = emitter<AuthPrompt>();
  const lines = emitter<string>();
  const themes = emitter<boolean>();
  const logBuffer: string[] = [];
  const log = (msg: string): void => {
    const line = `${new Date().toISOString()} [info] ${msg}`;
    logBuffer.push(line);
    if (logBuffer.length > 2000) logBuffer.shift();
    lines.emit(line);
  };

  const gateways = [
    { name: 'msk-gw1', address: 'gw1.example.com', priority: 1 },
    { name: 'msk-gw2', address: 'gw2.example.com', priority: 2 },
  ];
  const first = profiles[0]?.id;
  let state: VpnState = { status: 'disconnected', profileId: first };
  const pending = new Map<string, { prompt: AuthPrompt; resolve: (v: string | null) => void }>();
  let attempt = 0;

  const setState = (next: VpnState): void => {
    state = next;
    log(`state → ${next.status}`);
    states.emit(state);
  };
  const ask = (p: Omit<AuthPrompt, 'id'>): Promise<string | null> =>
    new Promise((resolve) => {
      const prompt = { ...p, id: crypto.randomUUID() };
      pending.set(prompt.id, { prompt, resolve });
      prompts.emit(prompt);
    });
  const effectiveDark = (): boolean => (settings.theme === 'system' ? osDark : settings.theme === 'dark');

  media.addEventListener('change', (e) => {
    osDark = e.matches;
    if (settings.theme === 'system') themes.emit(osDark);
  });

  const connected = (profileId: string): VpnState => ({
    status: 'connected',
    profileId,
    gateway: gateways[0],
    gateways,
    assignedIp: '10.24.17.203',
    connectedAt: Date.now() - 754_000,
  });

  async function run(profileId: string, gateway: string | undefined, id: number): Promise<void> {
    const alive = (): boolean => id === attempt;
    const fail = (code: VpnErrorCode): void => {
      if (alive())
        setState({
          status: 'error',
          profileId,
          gateways,
          error: vpnError(code, settings.language, platform, code === failCode ? failHint : undefined),
        });
    };
    setState({ status: 'prelogin', profileId });
    await delay(700);
    if (!alive()) return;
    setState({ status: 'authenticating', profileId });
    const profile = profiles.find((p) => p.id === profileId);
    if (profile?.authMode !== 'saml' && !savedPasswords.has(profileId)) {
      const pw = await ask({ kind: 'password', message: 'Введите учётные данные\nПароль' });
      if (!alive()) return;
      if (pw === null) return fail('AUTH_CANCELLED');
      const otp = await ask({ kind: 'otp', message: 'Введите код из приложения-аутентификатора\nКод' });
      if (!alive()) return;
      if (otp === null) return fail('AUTH_CANCELLED');
    } else {
      await delay(900);
    }
    if (!alive()) return;
    setState({ status: 'connecting', profileId, gateways });
    await delay(1000);
    if (!alive()) return;
    if (failCode) return fail(failCode);
    const gw = gateways.find((g) => g.name === gateway) ?? gateways[0];
    setState({ ...connected(profileId), gateway: gw, connectedAt: Date.now() });
  }

  const api: GpApi = {
    profiles: {
      list: async () => structuredClone(profiles),
      save: async (p: ProfileInput, password?: string) => {
        await delay(250);
        const saved: Profile = { ...p, id: p.id ?? crypto.randomUUID() } as Profile;
        const i = profiles.findIndex((x) => x.id === saved.id);
        if (i === -1) profiles.push(saved);
        else profiles[i] = saved;
        if (!saved.savePassword || saved.authMode === 'saml') savedPasswords.delete(saved.id);
        else if (password) savedPasswords.add(saved.id);
        log(`profile saved: ${saved.name}`);
        return structuredClone(saved);
      },
      remove: async (id: string) => {
        await delay(250);
        const i = profiles.findIndex((x) => x.id === id);
        if (i !== -1) profiles.splice(i, 1);
        savedPasswords.delete(id);
        log('profile removed (password and SSO cookies cleared)');
      },
    },
    vpn: {
      connect: async (profileId, opts) => {
        if (state.status !== 'disconnected' && state.status !== 'error') {
          throw ipcError('gp:vpn:connect', { code: 'busy', message: `Cannot connect while ${state.status}` });
        }
        if (!profiles.some((p) => p.id === profileId))
          throw ipcError('gp:vpn:connect', { code: 'not_found', message: 'Profile not found' });
        if (!openconnectFound) {
          setState({
            status: 'error',
            profileId,
            error: vpnError('OPENCONNECT_NOT_FOUND', settings.language, platform),
          });
          return;
        }
        attempt += 1;
        void run(profileId, opts?.gateway, attempt);
      },
      disconnect: async () => {
        attempt += 1;
        for (const p of pending.values()) p.resolve(null);
        pending.clear();
        if (state.status === 'disconnected') return;
        if (state.status === 'connected' || state.status === 'reconnecting') {
          setState({ ...state, status: 'disconnecting' });
          await delay(800);
        }
        setState({ status: 'disconnected', profileId: state.profileId, gateways: state.gateways });
      },
      getState: async () => structuredClone(state),
      getPendingPrompts: async () => [...pending.values()].map((p) => structuredClone(p.prompt)),
      answerPrompt: async (id, value) => {
        const entry = pending.get(id);
        if (!entry) {
          throw ipcError('gp:vpn:answerPrompt', {
            field: 'promptId',
            code: 'prompt_expired',
            message: 'Unknown or expired prompt',
          });
        }
        if (value !== null && /[\r\n\0]/.test(value))
          throw ipcError('gp:vpn:answerPrompt', {
            field: 'value',
            code: 'invalid_chars',
            message: 'Answer must be a single line',
          });
        pending.delete(id);
        entry.resolve(value);
      },
      onState: (cb) => states.on(cb),
      onPrompt: (cb) => prompts.on(cb),
    },
    logs: {
      get: async () => [...logBuffer],
      onLine: (cb) => lines.on(cb),
      openFolder: async () => {
        log('(mock) open logs folder');
      },
    },
    settings: {
      get: async () => structuredClone(settings),
      set: async (patch) => {
        if ('extraArgs' in patch && patch.extraArgs) {
          const r = checkExtraArgs(patch.extraArgs);
          if (!r.ok) {
            throw ipcError('gp:settings:set', {
              field: 'extraArgs',
              code: r.code,
              message: `Invalid extra argument "${r.arg}"`,
            });
          }
        }
        for (const key of ['openconnectPath', 'hipScriptPath'] as const) {
          const v = patch[key];
          if (v && !isAbsolutePath(v)) {
            throw ipcError('gp:settings:set', {
              field: key,
              code: 'not_absolute',
              message: `${key} must be an absolute path`,
            });
          }
          if (key === 'openconnectPath' && v && !isOpenconnectBinaryPath(v)) {
            throw ipcError('gp:settings:set', {
              field: key,
              code: 'not_openconnect',
              message: 'openconnectPath must point to the openconnect binary (openconnect / openconnect.exe)',
            });
          }
        }
        const sensitive = (['openconnectPath', 'hipScriptPath', 'extraArgs'] as const).filter(
          (k) => k in patch && JSON.stringify(patch[k] ?? '') !== JSON.stringify(settings[k] ?? ''),
        );
        if (sensitive.length > 0) {
          // Simulates main's native confirmation dialog (the promise stays pending meanwhile).
          await delay(400);
          if (!window.confirm(`(mock native dialog) Apply change of ${sensitive.join(', ')}?`)) {
            throw ipcError('gp:settings:set', { code: 'not_confirmed', message: 'The change was not confirmed' });
          }
        }
        const prevTheme = effectiveDark();
        const prevLang = settings.language;
        settings = { ...settings, ...patch };
        if (settings.language !== prevLang && state.error) {
          // Like main: re-localize the error message and re-emit the state.
          const e = state.error;
          setState({ ...state, error: { ...vpnError(e.code, settings.language, platform, e.hint), detail: e.detail } });
        }
        for (const k of ['openconnectPath', 'hipScriptPath'] as const) if (settings[k] === '') delete settings[k];
        if ('openconnectPath' in patch) openconnectFound = Boolean(settings.openconnectPath) || openconnectFound;
        if (effectiveDark() !== prevTheme) themes.emit(effectiveDark());
        return structuredClone(settings);
      },
    },
    system: {
      info: async () => {
        await delay(150);
        return {
          platform,
          openconnectFound,
          openconnectVersion: openconnectFound ? 'v9.12' : undefined,
          openconnectPath: openconnectFound ? (settings.openconnectPath ?? DEFAULT_OC_PATH[platform]) : undefined,
          openconnectTrusted: openconnectFound ? trusted : undefined,
          appVersion: '0.1.0-preview',
          shouldUseDarkColors: effectiveDark(),
        };
      },
      onThemeChange: (cb) => themes.on(cb),
      openExternal: async (url) => {
        window.open(url, '_blank', 'noopener');
      },
    },
    window: {
      minimize: () => log('(mock) minimize'),
      close: () => log('(mock) close'),
    },
  };

  // Initial scenario.
  log('GP Connect preview with mocked window.gp');
  const pid = first ?? '';
  switch (scenario) {
    case 'connected':
      state = connected(pid);
      break;
    case 'connecting':
      state = { status: 'connecting', profileId: pid, gateways };
      break;
    case 'reconnecting':
      state = {
        status: 'reconnecting',
        profileId: pid,
        gateway: gateways[0],
        gateways,
        error: {
          ...vpnError('TUNNEL_FAILED', settings.language, platform),
          detail: 'DPD timeout: no response from gw1.example.com',
        },
      };
      break;
    case 'stop-failed':
      // Main could not stop openconnect: still connected, Disconnect must stay available.
      state = { ...connected(pid), error: vpnError('PRIVILEGES_DENIED', settings.language, platform, 'stop_failed') };
      break;
    case 'error': {
      const code = failCode ?? 'AUTH_FAILED';
      state = {
        status: 'error',
        profileId: pid,
        gateways,
        error: vpnError(code, settings.language, platform, failHint),
      };
      break;
    }
    case 'prompt-password':
    case 'prompt-otp':
    case 'prompt-select':
    case 'prompt-text': {
      state = { status: 'authenticating', profileId: pid };
      const kind = scenario.slice('prompt-'.length) as AuthPrompt['kind'];
      const message = {
        password: 'Введите учётные данные\nПароль',
        otp: 'Введите код из приложения-аутентификатора\nКод',
        select: 'Выберите группу входа\nГруппа',
        text: 'Имя пользователя',
      }[kind];
      // Like main after a reload: the pending prompt is (re)sent once the UI subscribed.
      setTimeout(() => {
        attempt += 1;
        void ask({ kind, message, options: kind === 'select' ? ['Сотрудники', 'Подрядчики', 'ИТ'] : undefined }).then(
          (v) =>
            setState(
              v === null
                ? {
                    status: 'error',
                    profileId: pid,
                    error: vpnError('AUTH_CANCELLED', settings.language, platform),
                  }
                : connected(pid),
            ),
        );
      }, 500);
      break;
    }
  }

  (window as unknown as { gp: GpApi }).gp = api;
}
