/**
 * registerIpcHandlers through a fake ipcMain: sender validation, input
 * validation with `[field:][code:]` markers, and error hiding.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { DEFAULT_SETTINGS, IPC, type Profile } from '../../shared/ipc';
import { parseIpcError } from '../../shared/validation';
import {
  APP_URL,
  eventFrom,
  fakeWebContents,
  invoke,
  ipcRegistry,
  RENDERER,
  send,
  type FakeWebContents,
} from '../__fixtures__/fake-ipc';
import { Logger } from '../logging/logger';
import type { RendererLocation } from '../security';
import type { IpcBackend } from './handlers';

vi.mock('electron', async () => (await import('../__fixtures__/fake-ipc')).fakeElectronModule());
const { registerIpcHandlers } = await import('./handlers');

const PROFILE_ID = 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
const PROFILE: Profile = {
  id: PROFILE_ID.toLowerCase(),
  name: 'Work',
  portalUrl: 'https://vpn.example.com',
  authMode: 'auto',
  savePassword: false,
};

type MockedBackend = { [K in keyof IpcBackend]: Mock<IpcBackend[K]> };

function fakeBackend(): MockedBackend {
  const fn = <K extends keyof IpcBackend>(impl: IpcBackend[K]): Mock<IpcBackend[K]> => vi.fn(impl);
  return {
    listProfiles: fn<'listProfiles'>(() => [PROFILE]),
    saveProfile: fn<'saveProfile'>((p) => ({ ...p, id: p.id ?? PROFILE.id })),
    removeProfile: fn<'removeProfile'>(() => undefined),
    connect: fn<'connect'>(async () => undefined),
    disconnect: fn<'disconnect'>(async () => undefined),
    getState: fn<'getState'>(() => ({ status: 'disconnected' })),
    answerPrompt: fn<'answerPrompt'>(async () => undefined),
    getPendingPrompts: fn<'getPendingPrompts'>(() => []),
    getLogs: fn<'getLogs'>(() => ['line']),
    openLogsFolder: fn<'openLogsFolder'>(async () => undefined),
    getSettings: fn<'getSettings'>(() => DEFAULT_SETTINGS),
    setSettings: fn<'setSettings'>((patch) => ({ ...DEFAULT_SETTINGS, ...patch })),
    systemInfo: fn<'systemInfo'>(async () => ({
      platform: 'linux',
      openconnectFound: true,
      appVersion: '0.1.0',
      shouldUseDarkColors: false,
    })),
    openExternal: fn<'openExternal'>(async () => undefined),
    minimizeWindow: fn<'minimizeWindow'>(() => undefined),
    closeWindow: fn<'closeWindow'>(() => undefined),
  };
}

let backend: MockedBackend;
let logger: Logger;
let trusted: FakeWebContents | null;

function setup(renderer: RendererLocation = RENDERER, url = APP_URL): void {
  ipcRegistry.reset();
  backend = fakeBackend();
  logger = new Logger(null);
  trusted = fakeWebContents(url);
  registerIpcHandlers({
    backend,
    logger,
    renderer,
    trustedContents: () => trusted as unknown as Electron.WebContents | null,
  });
}

/** Rejection of an invoke, parsed the way the renderer does it. */
async function rejection(p: Promise<unknown>): Promise<ReturnType<typeof parseIpcError>> {
  try {
    await p;
  } catch (err) {
    return parseIpcError(err);
  }
  throw new Error('expected the call to be rejected');
}

beforeEach(() => setup());

describe('sender validation', () => {
  it('serves the main frame of the main window showing the app page', async () => {
    await expect(invoke(eventFrom(trusted!), IPC.vpn.getState)).resolves.toEqual({ status: 'disconnected' });
    expect(backend.getState).toHaveBeenCalledOnce();
  });

  it('registers a handler for every invoke channel of the contract', () => {
    const invokeChannels = [
      ...Object.values(IPC.profiles),
      IPC.vpn.connect,
      IPC.vpn.disconnect,
      IPC.vpn.getState,
      IPC.vpn.answerPrompt,
      IPC.vpn.getPendingPrompts,
      IPC.logs.get,
      IPC.logs.openFolder,
      ...Object.values(IPC.settings),
      IPC.system.info,
      IPC.system.openExternal,
    ];
    expect([...ipcRegistry.handlers.keys()].sort()).toEqual([...invokeChannels].sort());
    expect([...ipcRegistry.listeners.keys()].sort()).toEqual([IPC.window.close, IPC.window.minimize].sort());
  });

  it.each<[string, () => ReturnType<typeof eventFrom>]>([
    ['another window', () => eventFrom(fakeWebContents())],
    ['an iframe inside the main window', () => eventFrom(trusted!, { url: APP_URL })],
    ['a missing sender frame (navigated away / destroyed)', () => eventFrom(trusted!, null)],
    [
      'the main window after it navigated to a remote page',
      () => {
        trusted!.mainFrame.url = 'https://evil.example.com/';
        return eventFrom(trusted!);
      },
    ],
    [
      'the main window showing another local file',
      () => {
        trusted!.mainFrame.url = 'file:///tmp/evil.html';
        return eventFrom(trusted!);
      },
    ],
  ])('rejects calls from %s without touching the backend', async (_name, makeEvent) => {
    const ev = makeEvent();
    await expect(invoke(ev, IPC.vpn.connect, PROFILE_ID)).rejects.toThrow('Untrusted sender');
    await expect(invoke(ev, IPC.logs.get)).rejects.toThrow('Untrusted sender');
    expect(backend.connect).not.toHaveBeenCalled();
    expect(backend.getLogs).not.toHaveBeenCalled();
    expect(logger.lines().join('\n')).toMatch(/Rejected gp:vpn:connect from untrusted sender/);
  });

  it('rejects everything while there is no main window', async () => {
    const ev = eventFrom(trusted!);
    trusted = null;
    await expect(invoke(ev, IPC.profiles.list)).rejects.toThrow('Untrusted sender');
    expect(backend.listProfiles).not.toHaveBeenCalled();
  });

  it('ignores window.minimize/close from an untrusted sender', () => {
    send(eventFrom(fakeWebContents()), IPC.window.minimize);
    send(eventFrom(trusted!, { url: APP_URL }), IPC.window.close);
    expect(backend.minimizeWindow).not.toHaveBeenCalled();
    expect(backend.closeWindow).not.toHaveBeenCalled();
    send(eventFrom(trusted!), IPC.window.minimize);
    send(eventFrom(trusted!), IPC.window.close);
    expect(backend.minimizeWindow).toHaveBeenCalledOnce();
    expect(backend.closeWindow).toHaveBeenCalledOnce();
  });

  it('in development accepts any page of the dev server origin, nothing else', async () => {
    setup({ ...RENDERER, devUrl: 'http://localhost:5173' }, 'http://localhost:5173/#/log');
    await expect(invoke(eventFrom(trusted!), IPC.logs.get)).resolves.toEqual(['line']);
    trusted!.mainFrame.url = 'http://localhost:5174/';
    await expect(invoke(eventFrom(trusted!), IPC.logs.get)).rejects.toThrow('Untrusted sender');
  });
});

describe('input validation', () => {
  const call = (channel: string, ...args: unknown[]): Promise<unknown> => invoke(eventFrom(trusted!), channel, ...args);

  it('connect: normalises the profile id and options before calling the backend', async () => {
    await call(IPC.vpn.connect, PROFILE_ID, { gateway: '  US East ', password: 'pw' });
    expect(backend.connect).toHaveBeenCalledWith(PROFILE_ID.toLowerCase(), { gateway: 'US East', password: 'pw' });
    await call(IPC.vpn.connect, PROFILE_ID);
    expect(backend.connect).toHaveBeenLastCalledWith(PROFILE_ID.toLowerCase(), {});
  });

  it.each<[string, unknown[], { field?: string; code: string }]>([
    ['non-uuid profile id', ['../../etc/passwd'], { field: 'profileId', code: 'invalid' }],
    ['profile id of the wrong type', [{ id: PROFILE_ID }], { field: 'profileId', code: 'invalid' }],
    ['unknown option', [PROFILE_ID, { gateway: 'x', script: '/tmp/x' }], { field: 'script', code: 'unknown_field' }],
    [
      'multi-line password (stdin injection)',
      [PROFILE_ID, { password: 'pw\n--script=x' }],
      { field: 'password', code: 'invalid_chars' },
    ],
    ['options that are not an object', [PROFILE_ID, 'gw'], { code: 'invalid_type' }],
  ])('connect rejects %s', async (_name, args, marker) => {
    expect(await rejection(call(IPC.vpn.connect, ...args))).toMatchObject(marker);
    expect(backend.connect).not.toHaveBeenCalled();
  });

  it.each<[string, unknown, { field?: string; code: string }]>([
    [
      'http portal',
      { name: 'W', portalUrl: 'http://vpn.example.com', authMode: 'auto', savePassword: false },
      { field: 'portalUrl', code: 'not_https' },
    ],
    [
      'portal with credentials',
      { name: 'W', portalUrl: 'https://u:p@vpn.example.com', authMode: 'auto', savePassword: false },
      { field: 'portalUrl', code: 'credentials' },
    ],
    [
      'unknown auth mode',
      { name: 'W', portalUrl: 'vpn.example.com', authMode: 'kerberos', savePassword: false },
      { field: 'authMode', code: 'invalid' },
    ],
    [
      'empty name',
      { name: '  ', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false },
      { field: 'name', code: 'required' },
    ],
    [
      'extra field',
      { name: 'W', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false, isAdmin: true },
      { field: 'isAdmin', code: 'unknown_field' },
    ],
    ['not an object', ['W'], { code: 'invalid_type' }],
  ])('profiles.save rejects %s', async (_name, input, marker) => {
    expect(await rejection(call(IPC.profiles.save, input))).toMatchObject(marker);
    expect(backend.saveProfile).not.toHaveBeenCalled();
  });

  it('profiles.save passes a normalised profile and the password', async () => {
    await call(
      IPC.profiles.save,
      {
        name: ' Work ',
        portalUrl: 'HTTPS://VPN.Example.com/global-protect/',
        authMode: 'password',
        savePassword: true,
      },
      'pw',
    );
    expect(backend.saveProfile).toHaveBeenCalledWith(
      { name: 'Work', portalUrl: 'https://vpn.example.com', authMode: 'password', savePassword: true },
      'pw',
    );
  });

  it.each<[string, unknown, { field?: string; code: string }]>([
    [
      'a non-allowlisted extra arg',
      { extraArgs: ['--script=/tmp/evil.sh'] },
      { field: 'extraArgs', code: 'not_allowed' },
    ],
    [
      'a relative openconnect path',
      { openconnectPath: 'bin/openconnect' },
      { field: 'openconnectPath', code: 'not_absolute' },
    ],
    [
      'a binary that is not openconnect',
      { openconnectPath: '/bin/sh' },
      { field: 'openconnectPath', code: 'not_openconnect' },
    ],
    ['an unknown theme', { theme: 'sepia' }, { field: 'theme', code: 'invalid' }],
    ['an unknown key', { autoReconnect: false, debug: true }, { field: 'debug', code: 'unknown_field' }],
  ])('settings.set rejects %s', async (_name, patch, marker) => {
    expect(await rejection(call(IPC.settings.set, patch))).toMatchObject(marker);
    expect(backend.setSettings).not.toHaveBeenCalled();
  });

  it('answerPrompt accepts a string or null and rejects other types', async () => {
    const id = '22222222-2222-4222-8222-222222222222';
    await call(IPC.vpn.answerPrompt, id, '123456');
    await call(IPC.vpn.answerPrompt, id, null);
    expect(backend.answerPrompt.mock.calls).toEqual([
      [id, '123456'],
      [id, null],
    ]);
    expect(await rejection(call(IPC.vpn.answerPrompt, id, 123456))).toEqual({
      field: 'answer',
      code: 'invalid_type',
      message: 'Answer must be a string or null',
    });
    expect(await rejection(call(IPC.vpn.answerPrompt, 'x', 'v'))).toMatchObject({ field: 'promptId', code: 'invalid' });
    expect(backend.answerPrompt).toHaveBeenCalledTimes(2);
  });

  it.each(['file:///etc/passwd', 'javascript:alert(1)', 'http://example.com', 'not a url'])(
    'openExternal refuses %j',
    async (url) => {
      const info = await rejection(call(IPC.system.openExternal, url));
      expect(info.field).toBe('url');
      expect(backend.openExternal).not.toHaveBeenCalled();
    },
  );

  it('validation failures are not logged as errors', async () => {
    await rejection(call(IPC.vpn.connect, 'nope'));
    expect(logger.lines().join('\n')).not.toMatch(/ERROR/);
  });
});

describe('backend errors', () => {
  const call = (channel: string, ...args: unknown[]): Promise<unknown> => invoke(eventFrom(trusted!), channel, ...args);

  it('engine errors reach the renderer with markers', async () => {
    backend.connect.mockRejectedValueOnce(new Error('Cannot connect while connecting'));
    expect(await rejection(call(IPC.vpn.connect, PROFILE_ID))).toEqual({
      code: 'busy',
      message: 'Cannot connect while connecting',
    });
    backend.answerPrompt.mockRejectedValueOnce(new Error('Unknown or expired prompt'));
    expect(await rejection(call(IPC.vpn.answerPrompt, PROFILE_ID, 'x'))).toMatchObject({
      field: 'promptId',
      code: 'prompt_expired',
    });
  });

  it('internal errors are hidden from the renderer but logged', async () => {
    backend.openLogsFolder.mockRejectedValueOnce(new Error('EACCES: permission denied, open /home/alice/.config/x'));
    expect(await rejection(call(IPC.logs.openFolder))).toEqual({
      code: 'internal',
      message: 'Internal error, see the log for details',
    });
    expect(logger.lines().join('\n')).toMatch(/ERROR \[ipc\] gp:logs:openFolder failed: EACCES/);
  });

  it('a synchronous backend throw is handled like a rejection', async () => {
    backend.listProfiles.mockImplementationOnce(() => {
      throw new TypeError('boom');
    });
    expect(await rejection(call(IPC.profiles.list))).toMatchObject({ code: 'internal' });
  });
});
