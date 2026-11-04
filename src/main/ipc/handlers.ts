import { ipcMain, type IpcMainEvent, type IpcMainInvokeEvent, type WebContents } from 'electron';
import {
  IPC,
  type AuthPrompt,
  type ConnectOptions,
  type Profile,
  type Settings,
  type SystemInfo,
  type VpnState,
} from '../../shared/ipc';
import { formatIpcError } from '../../shared/validation';
import type { Logger } from '../logging/logger';
import { isTrustedSender, type RendererLocation } from '../security';
import {
  validateConnectOptions,
  validateExternalUrl,
  validateId,
  validatePassword,
  validateProfileInput,
  validateSettingsPatch,
  ValidationError,
} from '../store/validation';
import type { ProfileInput } from '../../shared/ipc';

/** Operations the IPC layer delegates to; implemented in index.ts. */
export interface IpcBackend {
  listProfiles(): Profile[];
  saveProfile(p: ProfileInput, password?: string): Profile;
  removeProfile(id: string): void | Promise<void>;
  connect(profileId: string, opts: ConnectOptions): Promise<void>;
  disconnect(): Promise<void>;
  getState(): VpnState;
  answerPrompt(id: string, value: string | null): Promise<void>;
  getPendingPrompts(): AuthPrompt[];
  getLogs(): string[];
  openLogsFolder(): Promise<void>;
  getSettings(): Settings;
  /** May ask the user to confirm security-relevant changes; rejects with ValidationError if declined. */
  setSettings(patch: Partial<Settings>): Settings | Promise<Settings>;
  systemInfo(): Promise<SystemInfo>;
  openExternal(url: string): Promise<void>;
  minimizeWindow(): void;
  closeWindow(): void;
}

export interface IpcContext {
  backend: IpcBackend;
  logger: Logger;
  renderer: RendererLocation;
  /** The main window's webContents (the only trusted IPC peer). */
  trustedContents(): WebContents | null;
}

/** Engine errors that are safe to show, with their machine-readable markers. */
const PUBLIC_ENGINE_ERRORS: { re: RegExp; field?: string; code: string }[] = [
  { re: /^Profile not found/, field: 'profileId', code: 'not_found' },
  { re: /^Cannot connect while/, code: 'busy' },
  { re: /^Unknown or expired prompt/, field: 'promptId', code: 'prompt_expired' },
  { re: /^(Invalid answer|Answer must)/, field: 'answer', code: 'invalid' },
];

/** Errors whose message is safe and useful to show to the user (with `[field:][code:]` markers). */
export function publicError(err: unknown): Error {
  if (err instanceof ValidationError) return new Error(err.message);
  if (err instanceof Error) {
    const known = PUBLIC_ENGINE_ERRORS.find((e) => e.re.test(err.message));
    if (known) return new Error(formatIpcError({ field: known.field, code: known.code, message: err.message }));
  }
  return new Error(formatIpcError({ code: 'internal', message: 'Internal error, see the log for details' }));
}

export function registerIpcHandlers(ctx: IpcContext): void {
  const { backend, logger } = ctx;

  const handle = <A extends unknown[], R>(channel: string, fn: (...args: A) => R | Promise<R>): void => {
    ipcMain.handle(channel, async (event: IpcMainInvokeEvent, ...args: unknown[]) => {
      if (!isTrustedSender(event, ctx.trustedContents(), ctx.renderer)) {
        logger.warn('ipc', `Rejected ${channel} from untrusted sender`);
        throw new Error('Untrusted sender');
      }
      try {
        return await fn(...(args as A));
      } catch (err) {
        if (!(err instanceof ValidationError)) logger.error('ipc', `${channel} failed`, err);
        throw publicError(err);
      }
    });
  };

  const on = (channel: string, fn: () => void): void => {
    ipcMain.on(channel, (event: IpcMainEvent) => {
      if (!isTrustedSender(event, ctx.trustedContents(), ctx.renderer)) return;
      fn();
    });
  };

  handle(IPC.profiles.list, () => backend.listProfiles());
  handle(IPC.profiles.save, (p: unknown, password: unknown) =>
    backend.saveProfile(validateProfileInput(p), validatePassword(password)),
  );
  handle(IPC.profiles.remove, (id: unknown) => backend.removeProfile(validateId(id, 'profile id', 'profileId')));

  handle(IPC.vpn.connect, (profileId: unknown, opts: unknown) =>
    backend.connect(validateId(profileId, 'profile id', 'profileId'), validateConnectOptions(opts)),
  );
  handle(IPC.vpn.disconnect, () => backend.disconnect());
  handle(IPC.vpn.getState, () => backend.getState());
  handle(IPC.vpn.getPendingPrompts, () => backend.getPendingPrompts());
  handle(IPC.vpn.answerPrompt, (id: unknown, value: unknown) => {
    if (value !== null && typeof value !== 'string') {
      throw new ValidationError('Answer must be a string or null', { field: 'answer', code: 'invalid_type' });
    }
    return backend.answerPrompt(validateId(id, 'prompt id', 'promptId'), value);
  });

  handle(IPC.logs.get, () => backend.getLogs());
  handle(IPC.logs.openFolder, () => backend.openLogsFolder());

  handle(IPC.settings.get, () => backend.getSettings());
  handle(IPC.settings.set, (patch: unknown) => backend.setSettings(validateSettingsPatch(patch)));

  handle(IPC.system.info, () => backend.systemInfo());
  handle(IPC.system.openExternal, (url: unknown) => backend.openExternal(validateExternalUrl(url)));

  on(IPC.window.minimize, () => backend.minimizeWindow());
  on(IPC.window.close, () => backend.closeWindow());
}
