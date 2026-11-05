import { act } from '@testing-library/react';
import { vi, type Mocked } from 'vitest';
import {
  DEFAULT_SETTINGS,
  type AuthPrompt,
  type GpApi,
  type Profile,
  type Settings,
  type SystemInfo,
  type VpnState,
} from '@shared/ipc';

export const PROFILE: Profile = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Работа',
  portalUrl: 'https://vpn.example.com',
  username: 'ivan',
  authMode: 'auto',
  savePassword: false,
};

export interface GpMockOptions {
  profiles?: Profile[];
  settings?: Partial<Settings>;
  info?: Partial<SystemInfo>;
  state?: VpnState;
  logs?: string[];
  /** Prompts already pending when the UI mounts (`vpn.getPendingPrompts`). */
  pendingPrompts?: AuthPrompt[];
}

function channel<T>() {
  const set = new Set<(v: T) => void>();
  return {
    on: (cb: (v: T) => void) => {
      set.add(cb);
      return () => void set.delete(cb);
    },
    emit: (v: T) => act(() => set.forEach((cb) => cb(v))),
    size: () => set.size,
  };
}

type MockedGp = { [K in keyof GpApi]: Mocked<GpApi[K]> };

export interface GpMock {
  gp: MockedGp;
  emitState(s: VpnState): void;
  emitPrompt(p: AuthPrompt): void;
  emitLine(line: string): void;
  emitTheme(dark: boolean): void;
}

/** A controllable `window.gp` built from vi.fn()s; installs itself on `window`. */
export function installGpMock(opts: GpMockOptions = {}): GpMock {
  const profiles = opts.profiles ?? [PROFILE];
  let settings: Settings = { ...DEFAULT_SETTINGS, ...opts.settings };
  const info: SystemInfo = {
    platform: 'linux',
    openconnectFound: true,
    openconnectVersion: 'v9.12',
    appVersion: '1.0.0',
    shouldUseDarkColors: false,
    ...opts.info,
  };
  const state = channel<VpnState>();
  const prompt = channel<AuthPrompt>();
  const line = channel<string>();
  const theme = channel<boolean>();

  const gp = {
    profiles: {
      list: vi.fn(async () => structuredClone(profiles)),
      save: vi.fn(async (p: Parameters<GpApi['profiles']['save']>[0]) => ({ ...p, id: p.id ?? 'new-id' }) as Profile),
      remove: vi.fn(async () => undefined),
    },
    vpn: {
      connect: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
      getState: vi.fn(async () => opts.state ?? { status: 'disconnected' as const }),
      answerPrompt: vi.fn(async () => undefined),
      getPendingPrompts: vi.fn(async () => opts.pendingPrompts ?? []),
      onState: vi.fn(state.on),
      onPrompt: vi.fn(prompt.on),
    },
    logs: {
      get: vi.fn(async () => opts.logs ?? []),
      onLine: vi.fn(line.on),
      openFolder: vi.fn(async () => undefined),
    },
    settings: {
      get: vi.fn(async () => settings),
      set: vi.fn(async (patch: Partial<Settings>) => {
        settings = { ...settings, ...patch };
        return settings;
      }),
    },
    system: {
      info: vi.fn(async () => info),
      onThemeChange: vi.fn(theme.on),
      openExternal: vi.fn(async () => undefined),
    },
  } satisfies GpApi as MockedGp;

  window.gp = gp;
  return { gp, emitState: state.emit, emitPrompt: prompt.emit, emitLine: line.emit, emitTheme: theme.emit };
}
