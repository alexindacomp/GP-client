/**
 * `window.gp` on top of Tauri 2 (see docs/ARCHITECTURE-TAURI.md, "Contract between renderer and
 * backend"). Commands are snake_case `area_action` with camelCase args; events keep their names.
 */
import { invoke as tauriInvoke, type InvokeArgs } from '@tauri-apps/api/core';
import { listen as tauriListen, type EventCallback, type UnlistenFn } from '@tauri-apps/api/event';
import type {
  AuthPrompt,
  ConnectOptions,
  GpApi,
  Profile,
  ProfileInput,
  Settings,
  SystemInfo,
  Unsubscribe,
  VpnState,
} from '@shared/ipc';

export const TAURI_EVENTS = {
  vpnState: 'gp:vpn:state',
  vpnPrompt: 'gp:vpn:prompt',
  logLine: 'gp:logs:line',
  themeChanged: 'gp:system:themeChanged',
} as const;

export interface TauriDeps {
  invoke: <T>(cmd: string, args?: InvokeArgs) => Promise<T>;
  listen: <T>(event: string, handler: EventCallback<T>) => Promise<UnlistenFn>;
}

const defaultDeps: TauriDeps = { invoke: tauriInvoke, listen: tauriListen };

/** Drops `undefined` values so optional Rust args are simply absent. */
function args(values: Record<string, unknown>): InvokeArgs {
  return Object.fromEntries(Object.entries(values).filter(([, v]) => v !== undefined));
}

export function createTauriGp(deps: TauriDeps = defaultDeps): GpApi {
  /**
   * Commands reject with a plain string (`Err(String)`, `[field:…][code:…] message`). Wrap it in an
   * Error so callers can rely on `.message`; `parseIpcError` reads the markers from it unchanged.
   */
  const call = async <T>(cmd: string, a?: Record<string, unknown>): Promise<T> => {
    try {
      return await deps.invoke<T>(cmd, a ? args(a) : undefined);
    } catch (err) {
      throw err instanceof Error ? err : new Error(typeof err === 'string' ? err : JSON.stringify(err));
    }
  };

  /**
   * `listen` resolves asynchronously; the returned unsubscribe is synchronous and also works
   * before the listener is registered (it then unlistens as soon as registration completes).
   */
  const subscribe = <T>(event: string, cb: (payload: T) => void): Unsubscribe => {
    let active = true;
    let unlisten: UnlistenFn | null = null;
    deps
      .listen<T>(event, (e) => {
        if (active) cb(e.payload);
      })
      .then(
        (fn) => {
          if (active) unlisten = fn;
          else fn();
        },
        (err: unknown) => console.error(`Failed to listen to ${event}`, err),
      );
    return () => {
      if (!active) return;
      active = false;
      unlisten?.();
      unlisten = null;
    };
  };

  return {
    profiles: {
      list: () => call<Profile[]>('profiles_list'),
      save: (profile: ProfileInput, password?: string) => call<Profile>('profiles_save', { profile, password }),
      remove: (id: string) => call<void>('profiles_remove', { id }),
    },
    vpn: {
      connect: (profileId: string, opts?: ConnectOptions) => call<void>('vpn_connect', { profileId, opts }),
      disconnect: () => call<void>('vpn_disconnect'),
      getState: () => call<VpnState>('vpn_get_state'),
      answerPrompt: (id: string, value: string | null) => call<void>('vpn_answer_prompt', { id, value }),
      getPendingPrompts: () => call<AuthPrompt[]>('vpn_get_pending_prompts'),
      onState: (cb) => subscribe<VpnState>(TAURI_EVENTS.vpnState, cb),
      onPrompt: (cb) => subscribe<AuthPrompt>(TAURI_EVENTS.vpnPrompt, cb),
    },
    logs: {
      get: () => call<string[]>('logs_get'),
      onLine: (cb) => subscribe<string>(TAURI_EVENTS.logLine, cb),
      openFolder: () => call<void>('logs_open_folder'),
    },
    settings: {
      get: () => call<Settings>('settings_get'),
      set: (patch: Partial<Settings>) => call<Settings>('settings_set', { patch }),
    },
    system: {
      info: () => call<SystemInfo>('system_info'),
      onThemeChange: (cb) => subscribe<boolean>(TAURI_EVENTS.themeChanged, cb),
      openExternal: (url: string) => call<void>('system_open_external', { url }),
    },
  };
}
