import { describe, expect, it, vi } from 'vitest';
import type { EventCallback, UnlistenFn } from '@tauri-apps/api/event';
import { parseIpcError } from '@shared/validation';
import { createTauriGp, TAURI_EVENTS, type TauriDeps } from './tauri';

function setup(result: unknown = undefined) {
  const invoke = vi.fn(async (_cmd: string, _args?: unknown) => result);
  const handlers = new Map<string, EventCallback<unknown>>();
  const unlisten = vi.fn<UnlistenFn>();
  let resolveListen: (fn: UnlistenFn) => void = () => undefined;
  const listen = vi.fn(
    (event: string, handler: EventCallback<unknown>) =>
      new Promise<UnlistenFn>((resolve) => {
        handlers.set(event, handler);
        resolveListen = resolve;
      }),
  );
  const gp = createTauriGp({ invoke, listen } as unknown as TauriDeps);
  const emit = (event: string, payload: unknown): void =>
    handlers.get(event)?.({ event, id: 1, payload } as Parameters<EventCallback<unknown>>[0]);
  return { gp, invoke, listen, unlisten, emit, resolveListen: () => resolveListen(unlisten) };
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe('Tauri bridge: commands', () => {
  const profile = { name: 'W', portalUrl: 'https://vpn.example.com', authMode: 'auto' as const, savePassword: false };

  it.each<[string, (gp: ReturnType<typeof setup>['gp']) => Promise<unknown>, string, unknown]>([
    ['profiles.list', (gp) => gp.profiles.list(), 'profiles_list', undefined],
    ['profiles.save', (gp) => gp.profiles.save(profile, 'pw'), 'profiles_save', { profile, password: 'pw' }],
    ['profiles.save (no password)', (gp) => gp.profiles.save(profile), 'profiles_save', { profile }],
    ['profiles.remove', (gp) => gp.profiles.remove('id-1'), 'profiles_remove', { id: 'id-1' }],
    [
      'vpn.connect',
      (gp) => gp.vpn.connect('p1', { gateway: 'gw' }),
      'vpn_connect',
      { profileId: 'p1', opts: { gateway: 'gw' } },
    ],
    ['vpn.connect (no opts)', (gp) => gp.vpn.connect('p1'), 'vpn_connect', { profileId: 'p1' }],
    ['vpn.disconnect', (gp) => gp.vpn.disconnect(), 'vpn_disconnect', undefined],
    ['vpn.getState', (gp) => gp.vpn.getState(), 'vpn_get_state', undefined],
    ['vpn.answerPrompt', (gp) => gp.vpn.answerPrompt('q1', '123'), 'vpn_answer_prompt', { id: 'q1', value: '123' }],
    [
      'vpn.answerPrompt (cancel)',
      (gp) => gp.vpn.answerPrompt('q1', null),
      'vpn_answer_prompt',
      { id: 'q1', value: null },
    ],
    ['vpn.getPendingPrompts', (gp) => gp.vpn.getPendingPrompts(), 'vpn_get_pending_prompts', undefined],
    ['logs.get', (gp) => gp.logs.get(), 'logs_get', undefined],
    ['logs.openFolder', (gp) => gp.logs.openFolder(), 'logs_open_folder', undefined],
    ['settings.get', (gp) => gp.settings.get(), 'settings_get', undefined],
    ['settings.set', (gp) => gp.settings.set({ theme: 'dark' }), 'settings_set', { patch: { theme: 'dark' } }],
    ['system.info', (gp) => gp.system.info(), 'system_info', undefined],
    [
      'system.openExternal',
      (gp) => gp.system.openExternal('https://x.test'),
      'system_open_external',
      { url: 'https://x.test' },
    ],
  ])('%s → %s', async (_name, run, cmd, args) => {
    const { gp, invoke } = setup();
    await run(gp);
    expect(invoke).toHaveBeenCalledWith(cmd, args);
  });

  it('returns the command result', async () => {
    const { gp } = setup([{ id: 'p' }]);
    await expect(gp.profiles.list()).resolves.toEqual([{ id: 'p' }]);
  });

  it('turns a string rejection into an Error whose markers parseIpcError still reads', async () => {
    const { gp, invoke } = setup();
    invoke.mockRejectedValueOnce('[field:extraArgs][code:not_allowed] Option "--script" is not allowed');
    const err = await gp.settings.set({ extraArgs: ['--script'] }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(parseIpcError(err)).toEqual({
      field: 'extraArgs',
      code: 'not_allowed',
      message: 'Option "--script" is not allowed',
    });
  });

  it('passes Error rejections through unchanged', async () => {
    const { gp, invoke } = setup();
    const boom = new Error('[code:busy] Cannot connect while connecting');
    invoke.mockRejectedValueOnce(boom);
    await expect(gp.vpn.connect('p')).rejects.toBe(boom);
  });
});

describe('Tauri bridge: events', () => {
  it.each([
    ['vpn.onState', TAURI_EVENTS.vpnState, { status: 'connected' }],
    ['vpn.onPrompt', TAURI_EVENTS.vpnPrompt, { id: 'q', kind: 'otp', message: 'Code' }],
    ['logs.onLine', TAURI_EVENTS.logLine, 'line'],
    ['system.onThemeChange', TAURI_EVENTS.themeChanged, true],
  ] as const)('%s listens to %s and forwards the payload', async (name, event, payload) => {
    const { gp, listen, emit, resolveListen } = setup();
    const cb = vi.fn();
    const subscribeFn = {
      'vpn.onState': gp.vpn.onState,
      'vpn.onPrompt': gp.vpn.onPrompt,
      'logs.onLine': gp.logs.onLine,
      'system.onThemeChange': gp.system.onThemeChange,
    }[name] as (cb: (v: unknown) => void) => () => void;
    subscribeFn(cb);
    expect(listen).toHaveBeenCalledWith(event, expect.any(Function));
    resolveListen();
    await flush();
    emit(event, payload);
    expect(cb).toHaveBeenCalledWith(payload);
  });

  it('unsubscribe after listen resolved calls the unlisten function', async () => {
    const { gp, unlisten, emit, resolveListen } = setup();
    const cb = vi.fn();
    const off = gp.vpn.onState(cb);
    resolveListen();
    await flush();
    off();
    expect(unlisten).toHaveBeenCalledTimes(1);
    emit(TAURI_EVENTS.vpnState, { status: 'connected' });
    expect(cb).not.toHaveBeenCalled();
    off(); // idempotent
    expect(unlisten).toHaveBeenCalledTimes(1);
  });

  it('unsubscribe before listen resolves unlistens once registration completes and drops events', async () => {
    const { gp, unlisten, emit, resolveListen } = setup();
    const cb = vi.fn();
    const off = gp.logs.onLine(cb);
    off();
    expect(unlisten).not.toHaveBeenCalled();
    emit(TAURI_EVENTS.logLine, 'early');
    resolveListen();
    await flush();
    expect(unlisten).toHaveBeenCalledTimes(1);
    expect(cb).not.toHaveBeenCalled();
  });

  it('logs (does not throw) when listen fails', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const gp = createTauriGp({
      invoke: vi.fn(),
      listen: vi.fn(async () => Promise.reject(new Error('no ipc'))),
    } as unknown as TauriDeps);
    const off = gp.vpn.onState(vi.fn());
    await flush();
    expect(error).toHaveBeenCalled();
    expect(() => off()).not.toThrow();
    error.mockRestore();
  });
});
