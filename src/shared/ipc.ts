/**
 * IPC contract between the main process and the renderer.
 * Single source of truth (see docs/SPEC.md, section "IPC-контракт").
 * The preload script exposes an object implementing {@link GpApi} as `window.gp`.
 */

export type AuthMode = 'auto' | 'password' | 'saml';

export interface Profile {
  id: string;
  name: string;
  portalUrl: string;
  username?: string;
  authMode: AuthMode;
  preferredGateway?: string;
  savePassword: boolean;
}

/** Input of `profiles.save`: `id` absent → create, present → update. */
export type ProfileInput = Omit<Profile, 'id'> & { id?: string };

export type VpnStatus =
  | 'disconnected'
  | 'prelogin'
  | 'authenticating'
  | 'connecting'
  | 'connected'
  | 'disconnecting'
  | 'reconnecting'
  | 'error';

export interface Gateway {
  name: string;
  address: string;
  priority?: number;
}

export type VpnErrorCode =
  | 'OPENCONNECT_NOT_FOUND'
  | 'AUTH_FAILED'
  | 'AUTH_CANCELLED'
  | 'PORTAL_UNREACHABLE'
  | 'TLS_ERROR'
  | 'PRIVILEGES_DENIED'
  | 'TUNNEL_FAILED'
  | 'UNKNOWN';

/**
 * Specific cause behind an error code, so the UI can pick an accurate title:
 * - `untrusted_binary`: openconnect / HIP script is not in an admin-only location (code PRIVILEGES_DENIED)
 * - `untrusted_homebrew`: same, macOS Homebrew install (code PRIVILEGES_DENIED)
 * - `stop_failed`: openconnect could not be stopped; the VPN may still be up (code PRIVILEGES_DENIED,
 *   status is not `error`)
 * - `settings_not_confirmed`: settings changed outside the app were not confirmed (code PRIVILEGES_DENIED)
 */
export type VpnErrorHint = 'untrusted_binary' | 'untrusted_homebrew' | 'stop_failed' | 'settings_not_confirmed';

export interface VpnState {
  status: VpnStatus;
  profileId?: string;
  gateway?: Gateway;
  assignedIp?: string;
  connectedAt?: number;
  /**
   * `message`: localized next step for the user (no technical suffix).
   * `detail`: raw technical cause (e.g. "Login failed", "getaddrinfo ENOTFOUND"),
   * secrets masked, untranslated, ≤ ~300 chars; absent when unknown.
   * `hint`: specific cause (see {@link VpnErrorHint}); `message` follows the settings language.
   */
  error?: { code: VpnErrorCode; message: string; detail?: string; hint?: VpnErrorHint };
  gateways?: Gateway[];
}

export interface AuthPrompt {
  id: string;
  kind: 'password' | 'otp' | 'text' | 'select';
  message: string;
  options?: string[];
}

export type Theme = 'system' | 'light' | 'dark';
export type Language = 'ru' | 'en' | 'uk';

export interface Settings {
  theme: Theme;
  launchAtLogin: boolean;
  connectOnStartup: boolean;
  autoReconnect: boolean;
  openconnectPath?: string;
  extraArgs: string[];
  hipScriptPath?: string;
  language: Language;
  lastProfileId?: string;
}

export interface SystemInfo {
  platform: 'win32' | 'darwin' | 'linux';
  openconnectVersion?: string;
  openconnectFound: boolean;
  /** Path of the openconnect binary that will be used (configured or detected); absent when not found. */
  openconnectPath?: string;
  /**
   * Whether that binary passed the admin-only-location trust check (discovery result,
   * may be cached ~30 s). `false` → found, but in an unprotected folder: connecting
   * will be refused. Absent when not found.
   */
  openconnectTrusted?: boolean;
  appVersion: string;
  shouldUseDarkColors: boolean;
}

export interface ConnectOptions {
  gateway?: string;
  password?: string;
}

/** Function returned by `on*` subscriptions; call it to unsubscribe. */
export type Unsubscribe = () => void;

export interface GpApi {
  profiles: {
    list(): Promise<Profile[]>;
    save(p: ProfileInput, password?: string): Promise<Profile>;
    remove(id: string): Promise<void>;
  };
  vpn: {
    connect(profileId: string, opts?: ConnectOptions): Promise<void>;
    disconnect(): Promise<void>;
    getState(): Promise<VpnState>;
    /** `null` cancels the prompt (and the connection attempt). */
    answerPrompt(id: string, value: string | null): Promise<void>;
    /**
     * Prompts currently waiting for an answer. Call after subscribing with
     * `onPrompt` (and on startup) so a prompt pushed before the subscription is
     * not lost. Prompts may be delivered both ways: de-duplicate by `id`.
     */
    getPendingPrompts(): Promise<AuthPrompt[]>;
    onState(cb: (s: VpnState) => void): Unsubscribe;
    onPrompt(cb: (p: AuthPrompt) => void): Unsubscribe;
  };
  logs: {
    get(): Promise<string[]>;
    onLine(cb: (line: string) => void): Unsubscribe;
    openFolder(): Promise<void>;
  };
  settings: {
    get(): Promise<Settings>;
    set(patch: Partial<Settings>): Promise<Settings>;
  };
  system: {
    info(): Promise<SystemInfo>;
    onThemeChange(cb: (dark: boolean) => void): Unsubscribe;
    openExternal(url: string): Promise<void>;
  };
  /** For the custom title bar. Fire-and-forget. */
  window: {
    minimize(): void;
    close(): void;
  };
}

/** IPC channel names, `gp:<area>:<action>`. */
export const IPC = {
  profiles: {
    list: 'gp:profiles:list',
    save: 'gp:profiles:save',
    remove: 'gp:profiles:remove',
  },
  vpn: {
    connect: 'gp:vpn:connect',
    disconnect: 'gp:vpn:disconnect',
    getState: 'gp:vpn:getState',
    answerPrompt: 'gp:vpn:answerPrompt',
    getPendingPrompts: 'gp:vpn:getPendingPrompts',
    /** main → renderer event: VpnState */
    state: 'gp:vpn:state',
    /** main → renderer event: AuthPrompt */
    prompt: 'gp:vpn:prompt',
  },
  logs: {
    get: 'gp:logs:get',
    /** main → renderer event: string */
    line: 'gp:logs:line',
    openFolder: 'gp:logs:openFolder',
  },
  settings: {
    get: 'gp:settings:get',
    set: 'gp:settings:set',
  },
  system: {
    info: 'gp:system:info',
    /** main → renderer event: boolean (shouldUseDarkColors) */
    themeChanged: 'gp:system:themeChanged',
    openExternal: 'gp:system:openExternal',
  },
  window: {
    minimize: 'gp:window:minimize',
    close: 'gp:window:close',
  },
} as const;

export const DEFAULT_SETTINGS: Settings = {
  theme: 'system',
  launchAtLogin: false,
  connectOnStartup: false,
  autoReconnect: true,
  extraArgs: [],
  language: 'ru',
};
