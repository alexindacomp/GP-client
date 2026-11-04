import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, type AuthPrompt, type Profile, type Settings, type VpnState } from '../../shared/ipc';
import { PreloginError, type PreloginResult } from '../auth/prelogin';
import type { SamlSuccess } from '../auth/saml-extract';
import { Logger } from '../logging/logger';
import { BaseVpnProcess, SpawnError, type ProcessSpawner, type SpawnRequest } from '../process/types';
import { VpnError } from './errors';
import { VpnEngine, type EngineDeps } from './engine';

// ------------------------------------------------------------------ fakes

class FakeProcess extends BaseVpnProcess {
  readonly pid = 4242;
  readonly written: string[] = [];
  stopCalls = 0;
  killCalls = 0;
  /** When false, stop() is ignored (simulates a hung openconnect). */
  exitOnStop = true;
  /** When false, kill() is ignored too (e.g. both pkexec dialogs dismissed). */
  exitOnKill = true;
  /** When set, kill() rejects with this error. */
  killError: Error | null = null;
  /** When set, write() throws this error. */
  writeError: Error | null = null;

  write(data: string): void {
    if (this.writeError) throw this.writeError;
    this.written.push(data);
  }
  async stop(): Promise<void> {
    this.stopCalls++;
    if (this.exitOnStop) this.exit(0);
  }
  async kill(): Promise<void> {
    this.killCalls++;
    if (this.killError) throw this.killError;
    if (this.exitOnKill) this.exit(null, 'SIGKILL');
  }
  out(text: string): void {
    this.emitOutput('stdout', text);
  }
  err(text: string): void {
    this.emitOutput('stderr', text);
  }
  exit(code: number | null, signal: string | null = null): void {
    this.emitExit({ code, signal });
  }
}

class FakeSpawner implements ProcessSpawner {
  readonly requests: SpawnRequest[] = [];
  readonly processes: FakeProcess[] = [];
  failWith: Error | null = null;

  async spawn(req: SpawnRequest): Promise<FakeProcess> {
    this.requests.push(req);
    if (this.failWith) throw this.failWith;
    const p = new FakeProcess();
    this.processes.push(p);
    return p;
  }

  get last(): FakeProcess {
    const p = this.processes.at(-1);
    if (!p) throw new Error('no process spawned');
    return p;
  }
}

const PROFILE_ID = '11111111-2222-4333-8444-555555555555';
const SAML_PRELOGIN: PreloginResult = {
  authType: 'saml',
  samlMethod: 'REDIRECT',
  samlRequest: Buffer.from('https://idp.example.com/sso').toString('base64'),
};
const PASSWORD_PRELOGIN: PreloginResult = { authType: 'password', passwordLabel: 'Password' };

interface Harness {
  engine: VpnEngine;
  spawner: FakeSpawner;
  logger: Logger;
  states: VpnState[];
  prompts: AuthPrompt[];
  profile: Profile;
  settings: Settings;
  deps: EngineDeps;
  savedPassword: string | undefined;
}

function setup(
  over: { profile?: Partial<Profile>; settings?: Partial<Settings>; deps?: Partial<EngineDeps> } = {},
): Harness {
  const spawner = new FakeSpawner();
  const logger = new Logger(null);
  const profile: Profile = {
    id: PROFILE_ID,
    name: 'Work',
    portalUrl: 'https://vpn.example.com',
    username: 'alice',
    authMode: 'password',
    savePassword: true,
    ...over.profile,
  };
  const settings: Settings = { ...DEFAULT_SETTINGS, autoReconnect: true, ...over.settings };
  const h = { savedPassword: 'Secr3tPass' as string | undefined } as Harness;
  let n = 0;
  const deps: EngineDeps = {
    platform: 'linux',
    getProfile: (id) => (id === profile.id ? profile : undefined),
    getSavedPassword: () => h.savedPassword,
    getSettings: () => settings,
    prelogin: vi.fn(async () => PASSWORD_PRELOGIN),
    samlLogin: vi.fn(async (): Promise<SamlSuccess> => ({
      status: 'success',
      username: 'alice@example.com',
      cookieName: 'prelogin-cookie',
      cookie: 'SAML-COOKIE-VALUE',
    })),
    locateOpenconnect: vi.fn(async () => '/usr/sbin/openconnect'),
    verifyElevatedFiles: vi.fn(async (files: { binary: string; hipScriptPath?: string }) => files),
    spawner,
    logger,
    newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
    now: () => 1_700_000_000_000,
    ...over.deps,
  };
  const engine = new VpnEngine(deps);
  const states: VpnState[] = [];
  const prompts: AuthPrompt[] = [];
  engine.onState((s) => states.push(s));
  engine.onPrompt((p) => prompts.push(p));
  return Object.assign(h, { engine, spawner, logger, states, prompts, profile, settings, deps });
}

const flush = async (): Promise<void> => {
  await vi.advanceTimersByTimeAsync(0);
};
const statuses = (h: Harness): string[] => h.states.map((s) => s.status);

async function connectAndEstablish(h: Harness): Promise<FakeProcess> {
  await h.engine.connect(PROFILE_ID);
  await flush();
  const p = h.spawner.last;
  p.out('GlobalProtect login returned authentication-source=local\n');
  p.out('Connected as 10.8.0.42, using SSL, with ESP in progress\n');
  await flush();
  return p;
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

// ------------------------------------------------------------------ tests

describe('VpnEngine: successful connections', () => {
  it('password profile: authenticating → connecting → connected, password goes to stdin only', async () => {
    const h = setup();
    const p = await connectAndEstablish(h);

    expect(statuses(h)).toEqual(['prelogin', 'authenticating', 'connecting', 'connected']);
    expect(h.deps.prelogin).not.toHaveBeenCalled(); // authMode 'password' skips prelogin
    expect(h.spawner.requests[0]!.binary).toBe('/usr/sbin/openconnect');
    expect(h.spawner.requests[0]!.args).toContain('--user=alice');
    expect(h.spawner.requests[0]!.args.join(' ')).not.toContain('Secr3tPass');
    expect(p.written).toEqual(['Secr3tPass\n']);

    const s = h.engine.getState();
    expect(s).toMatchObject({
      status: 'connected',
      profileId: PROFILE_ID,
      assignedIp: '10.8.0.42',
      connectedAt: 1_700_000_000_000,
      gateway: { name: 'vpn.example.com', address: 'vpn.example.com' },
    });
    expect(s.error).toBeUndefined();
  });

  it('SAML profile: runs prelogin + SAML and passes the cookie on stdin with --usergroup', async () => {
    const h = setup({ profile: { authMode: 'auto', username: undefined } });
    vi.mocked(h.deps.prelogin).mockResolvedValue(SAML_PRELOGIN);
    const p = await connectAndEstablish(h);

    expect(h.deps.samlLogin).toHaveBeenCalledOnce();
    const args = h.spawner.requests[0]!.args;
    expect(args).toContain('--usergroup=portal:prelogin-cookie');
    expect(args).toContain('--user=alice@example.com');
    expect(p.written).toEqual(['SAML-COOKIE-VALUE\n']);
    expect(h.engine.getState().status).toBe('connected');
  });

  it('records the gateway list and auto-selects the preferred gateway', async () => {
    const h = setup({ profile: { preferredGateway: 'gw-us.example.com' } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    expect(h.spawner.requests[0]!.args).toContain('--authgroup=gw-us.example.com');

    p.out('2 gateway servers available:\n  Europe (gw-eu.example.com) [1]\n  US East (gw-us.example.com) [2]\n');
    p.err('GATEWAY: [Europe|US East]:');
    await vi.advanceTimersByTimeAsync(200);
    expect(p.written.at(-1)).toBe('US East\n');
    expect(h.prompts).toHaveLength(0);

    p.out('Connected as 10.1.1.1\n');
    await flush();
    expect(h.engine.getState()).toMatchObject({
      status: 'connected',
      gateway: { name: 'US East', address: 'gw-us.example.com', priority: 2 },
      gateways: [
        { name: 'Europe', address: 'gw-eu.example.com', priority: 1 },
        { name: 'US East', address: 'gw-us.example.com', priority: 2 },
      ],
    });
  });

  it('picks the first gateway when none is requested', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('GATEWAY: [Europe|US East]:');
    await vi.advanceTimersByTimeAsync(200);
    expect(p.written.at(-1)).toBe('Europe\n');
  });
});

describe('VpnEngine: prompts', () => {
  it('asks for the password when none is saved and uses the answer', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.prompts).toEqual([{ id: expect.any(String), kind: 'password', message: 'Пароль' }]);
    expect(h.spawner.requests).toHaveLength(0);

    await h.engine.answerPrompt(h.prompts[0]!.id, 'typed-pw');
    await flush();
    expect(h.spawner.last.written).toEqual(['typed-pw\n']);
  });

  it('cancelling the password prompt ends in AUTH_CANCELLED without spawning', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.answerPrompt(h.prompts[0]!.id, null);
    await flush();
    expect(h.spawner.requests).toHaveLength(0);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'AUTH_CANCELLED' } });
  });

  it('forwards an OTP challenge from openconnect and writes the answer', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('Enter the code from your authenticator app\nChallenge:');
    await vi.advanceTimersByTimeAsync(200);
    expect(h.prompts).toHaveLength(1);
    expect(h.prompts[0]).toMatchObject({
      kind: 'otp',
      message: 'Enter the code from your authenticator app\nChallenge',
    });

    await h.engine.answerPrompt(h.prompts[0]!.id, '123456');
    await flush();
    expect(p.written).toEqual(['Secr3tPass\n', '123456\n']);
  });

  it('does not treat an incomplete fragment as a prompt before the debounce', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.out('Connected as 10.0.0.1:');
    await vi.advanceTimersByTimeAsync(50);
    p.out(' extra\n');
    await vi.advanceTimersByTimeAsync(500);
    expect(h.prompts).toHaveLength(0);
  });

  it('rejects unknown prompt ids and multi-line answers', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    await expect(h.engine.answerPrompt('nope', 'x')).rejects.toThrow(/Unknown/);
    await expect(h.engine.answerPrompt(h.prompts[0]!.id, 'a\nb')).rejects.toThrow(/single line/);
  });
});

describe('VpnEngine: errors', () => {
  it('reports OPENCONNECT_NOT_FOUND', async () => {
    const h = setup({ deps: { locateOpenconnect: async () => null } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState()).toMatchObject({
      status: 'error',
      profileId: PROFILE_ID,
      error: {
        code: 'OPENCONNECT_NOT_FOUND',
        message: 'Установите OpenConnect или укажите путь к нему в настройках.',
        detail: 'openconnect binary not found',
      },
    });
  });

  it('reports PORTAL_UNREACHABLE from prelogin', async () => {
    const h = setup({ profile: { authMode: 'auto' } });
    vi.mocked(h.deps.prelogin).mockRejectedValue(
      new PreloginError('PORTAL_UNREACHABLE', 'Cannot reach portal: timeout'),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(statuses(h)).toEqual(['prelogin', 'error']);
    expect(h.engine.getState().error?.code).toBe('PORTAL_UNREACHABLE');
  });

  it('reports AUTH_CANCELLED when the SAML window is closed', async () => {
    const h = setup({ profile: { authMode: 'saml' } });
    vi.mocked(h.deps.prelogin).mockResolvedValue(SAML_PRELOGIN);
    vi.mocked(h.deps.samlLogin).mockRejectedValue(new VpnError('AUTH_CANCELLED', 'closed'));
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error?.code).toBe('AUTH_CANCELLED');
    expect(h.spawner.requests).toHaveLength(0);
  });

  it('fails with AUTH_FAILED when a saml profile gets a password-only portal', async () => {
    const h = setup({ profile: { authMode: 'saml' } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error?.code).toBe('AUTH_FAILED');
  });

  it('stops openconnect on a re-prompt after "Login failed" and reports AUTH_FAILED', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('Login failed.\nPassword:');
    await vi.advanceTimersByTimeAsync(200);
    expect(h.prompts).toHaveLength(0);
    expect(p.stopCalls).toBe(1);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'AUTH_FAILED' } });
  });

  it('refuses an untrusted server certificate and reports TLS_ERROR', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err(
      "Certificate from VPN server \"vpn.example.com\" failed verification.\nEnter 'yes' to accept, 'no' to abort; anything else to view: ",
    );
    await vi.advanceTimersByTimeAsync(200);
    expect(p.written.at(-1)).toBe('no\n');
    p.exit(1);
    await flush();
    expect(h.engine.getState().error?.code).toBe('TLS_ERROR');
  });

  it('maps a denied privilege escalation (spawn error) to PRIVILEGES_DENIED', async () => {
    const h = setup();
    h.spawner.failWith = new SpawnError('PRIVILEGES_DENIED', 'cancelled');
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error?.code).toBe('PRIVILEGES_DENIED');
  });

  it('refuses to spawn an untrusted binary/HIP script (PRIVILEGES_DENIED)', async () => {
    const h = setup({ settings: { hipScriptPath: '/home/alice/hip.sh' }, profile: { authMode: 'auto' } });
    h.savedPassword = undefined;
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValue(
      new VpnError('PRIVILEGES_DENIED', '/home/alice/hip.sh is not owned by root'),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.deps.verifyElevatedFiles).toHaveBeenCalledWith({
      binary: '/usr/sbin/openconnect',
      hipScriptPath: '/home/alice/hip.sh',
    });
    expect(h.spawner.requests).toHaveLength(0);
    // fails fast: no SAML/prelogin/password prompt before the trust check
    expect(h.deps.prelogin).not.toHaveBeenCalled();
    expect(h.prompts).toHaveLength(0);
    expect(h.engine.getState()).toMatchObject({
      status: 'error',
      error: {
        code: 'PRIVILEGES_DENIED',
        message: expect.any(String),
        detail: expect.stringContaining('not owned by root'),
      },
    });
  });

  it('re-checks the files right before spawning (state may change during auth)', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.deps.verifyElevatedFiles).toHaveBeenCalledTimes(1);
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValueOnce(new VpnError('PRIVILEGES_DENIED', 'replaced'));
    await h.engine.answerPrompt(h.prompts[0]!.id, 'pw');
    await flush();
    expect(h.deps.verifyElevatedFiles).toHaveBeenCalledTimes(2);
    expect(h.spawner.requests).toHaveLength(0);
    expect(h.engine.getState().error?.code).toBe('PRIVILEGES_DENIED');
  });

  it('spawns the verified real paths, not the configured ones', async () => {
    const h = setup({ settings: { hipScriptPath: '/usr/local/bin/hip' } });
    vi.mocked(h.deps.verifyElevatedFiles).mockResolvedValue({
      binary: '/usr/sbin/openconnect.real',
      hipScriptPath: '/usr/libexec/hip.real',
    });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.spawner.requests[0]!.binary).toBe('/usr/sbin/openconnect.real');
    expect(h.spawner.requests[0]!.args).toContain('--csd-wrapper=/usr/libexec/hip.real');
  });

  it('re-validates extra args before spawning (tampered settings never reach openconnect)', async () => {
    const h = setup({ settings: { extraArgs: ['--script=/tmp/evil'] } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.spawner.requests).toHaveLength(0);
    expect(h.engine.getState().status).toBe('error');
  });

  it('maps pkexec exit code 126 to PRIVILEGES_DENIED', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    h.spawner.last.exit(126);
    await flush();
    expect(h.engine.getState().error?.code).toBe('PRIVILEGES_DENIED');
  });

  it('uses the most specific error seen in the output when the process exits early', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err("getaddrinfo failed for host 'vpn.example.com': Name or service not known\n");
    p.exit(1);
    await flush();
    expect(h.engine.getState()).toMatchObject({
      status: 'error',
      error: {
        code: 'PORTAL_UNREACHABLE',
        message: 'Проверьте адрес портала и подключение к сети.',
        detail: expect.stringContaining('Name or service not known'),
      },
    });
  });

  it('rejects connect for an unknown profile or while busy', async () => {
    const h = setup();
    await expect(h.engine.connect('99999999-2222-4333-8444-555555555555')).rejects.toThrow(/not found/);
    await connectAndEstablish(h);
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect while connected/);
  });

  it('allows connecting again after an error', async () => {
    const h = setup({ deps: { locateOpenconnect: vi.fn(async () => null) } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().status).toBe('error');
    vi.mocked(h.deps.locateOpenconnect).mockResolvedValue('/usr/bin/openconnect');
    await connectAndEstablish(h);
    expect(h.engine.getState().status).toBe('connected');
  });
});

describe('VpnEngine: disconnect', () => {
  it('connected → disconnecting → disconnected with a graceful stop', async () => {
    const h = setup();
    const p = await connectAndEstablish(h);
    await h.engine.disconnect();
    expect(p.stopCalls).toBe(1);
    expect(p.killCalls).toBe(0);
    expect(statuses(h).slice(-2)).toEqual(['disconnecting', 'disconnected']);
    expect(h.engine.getState()).toEqual({ status: 'disconnected', profileId: PROFILE_ID });
  });

  it('kills openconnect when it ignores the graceful stop', async () => {
    const h = setup({ deps: { stopTimeoutMs: 1000 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    const done = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(1000);
    await done;
    expect(p.killCalls).toBe(1);
    expect(h.engine.getState().status).toBe('disconnected');
  });

  it('cancels a pending prompt and does not spawn when disconnecting during authentication', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.prompts).toHaveLength(1);
    await h.engine.disconnect();
    await flush();
    expect(h.engine.getState().status).toBe('disconnected');
    expect(h.spawner.requests).toHaveLength(0);
    await expect(h.engine.answerPrompt(h.prompts[0]!.id, 'late')).rejects.toThrow(/Unknown/);
  });

  it('kills a process that finishes spawning after the user disconnected', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const spawner = new FakeSpawner();
    const slowSpawner: ProcessSpawner = {
      spawn: async (req) => {
        await gate;
        return spawner.spawn(req);
      },
    };
    const h = setup({ deps: { spawner: slowSpawner } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.disconnect();
    release();
    await flush();
    expect(spawner.last.killCalls).toBe(1);
    expect(h.engine.getState().status).toBe('disconnected');
  });

  it('disconnect when idle is a no-op', async () => {
    const h = setup();
    await h.engine.disconnect();
    expect(h.states).toEqual([]);
  });
});

describe('VpnEngine: auto-reconnect', () => {
  it('reconnects with 2/5/10/30 s backoff after the tunnel drops', async () => {
    const h = setup();
    const p1 = await connectAndEstablish(h);

    p1.err('Session terminated by server; exiting.\n');
    p1.exit(2);
    await flush();
    expect(h.engine.getState()).toMatchObject({ status: 'reconnecting', profileId: PROFILE_ID });
    expect(h.spawner.processes).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1999);
    expect(h.spawner.processes).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.spawner.processes).toHaveLength(2);
    // The reconnect attempt reuses the in-memory password and stays "reconnecting".
    expect(h.spawner.last.written).toEqual(['Secr3tPass\n']);
    expect(h.engine.getState().status).toBe('reconnecting');

    // Attempt 2 fails before connecting → next delay 5 s.
    h.spawner.last.err('Failed to connect to host vpn.example.com\n');
    h.spawner.last.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(4999);
    expect(h.spawner.processes).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.spawner.processes).toHaveLength(3);

    // Attempt 3 fails → 10 s; attempt 4 fails → 30 s; then stays at 30 s.
    for (const delay of [10_000, 30_000, 30_000]) {
      const before = h.spawner.processes.length;
      h.spawner.last.exit(1);
      await flush();
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(h.spawner.processes).toHaveLength(before);
      await vi.advanceTimersByTimeAsync(1);
      expect(h.spawner.processes).toHaveLength(before + 1);
    }

    // Success resets the backoff.
    h.spawner.last.out('Connected as 10.8.0.43\n');
    await flush();
    expect(h.engine.getState()).toMatchObject({ status: 'connected', assignedIp: '10.8.0.43' });
    h.spawner.last.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.spawner.processes).toHaveLength(7);
  });

  it('gives up after maxReconnectAttempts', async () => {
    const h = setup({ deps: { maxReconnectAttempts: 2, backoffMs: [100] } });
    const p = await connectAndEstablish(h);
    p.exit(1);
    for (let i = 0; i < 2; i++) {
      await vi.advanceTimersByTimeAsync(100);
      h.spawner.last.exit(1);
    }
    await flush();
    expect(h.spawner.processes).toHaveLength(3);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'TUNNEL_FAILED' } });
  });

  it('does not reconnect when autoReconnect is off', async () => {
    const h = setup({ settings: { autoReconnect: false } });
    const p = await connectAndEstablish(h);
    p.err('Session terminated by server; exiting.\n');
    p.exit(2);
    await flush();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'TUNNEL_FAILED' } });
  });

  it('does not reconnect a first attempt that never connected', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    h.spawner.last.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState().status).toBe('error');
  });

  it('stops retrying on a non-retryable error during reconnect', async () => {
    const h = setup();
    const p = await connectAndEstablish(h);
    p.exit(1);
    await vi.advanceTimersByTimeAsync(2000);
    h.spawner.last.err('Error executing command as another user: Not authorized\n');
    h.spawner.last.exit(127);
    await flush();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(2);
    expect(h.engine.getState().error?.code).toBe('PRIVILEGES_DENIED');
  });

  it('disconnect during the backoff wait cancels the reconnect', async () => {
    const h = setup();
    const p = await connectAndEstablish(h);
    p.exit(1);
    await flush();
    expect(h.engine.getState().status).toBe('reconnecting');
    await h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState().status).toBe('disconnected');
  });
});

describe('VpnEngine: secrets', () => {
  it('never puts the password or SAML cookie into logs or state', async () => {
    const h = setup({ profile: { authMode: 'auto' } });
    vi.mocked(h.deps.prelogin).mockResolvedValue(SAML_PRELOGIN);
    const p = await connectAndEstablish(h);
    // openconnect echoing secrets (e.g. with --dump-http-traffic)
    p.out('POST body: prelogin-cookie=SAML-COOKIE-VALUE&user=alice\n');
    p.out('debug SAML-COOKIE-VALUE\n');
    p.err('Unexpected 512 result from server SAML-COOKIE-VALUE\n');
    p.exit(1);
    await flush();
    const everything = JSON.stringify([h.logger.lines(), h.states, h.engine.getState()]);
    expect(everything).not.toContain('SAML-COOKIE-VALUE');
  });

  it('masks a password typed into a prompt', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.answerPrompt(h.prompts[0]!.id, 'Typed-Pa55');
    await flush();
    h.spawner.last.err('Login failed for Typed-Pa55\n');
    h.spawner.last.exit(1);
    await flush();
    const everything = JSON.stringify([h.logger.lines(), h.states]);
    expect(everything).not.toContain('Typed-Pa55');
    expect(h.engine.getState().error?.code).toBe('AUTH_FAILED');
  });
});

describe('VpnEngine: rework round (CR-1/2/6/7)', () => {
  it('CR-1: keeps backing off when a reconnect attempt fails before spawning (portal unreachable)', async () => {
    const h = setup({ profile: { authMode: 'auto' } });
    const p = await connectAndEstablish(h);
    expect(h.deps.prelogin).toHaveBeenCalledTimes(1);

    // network still down: the next prelogin fails
    vi.mocked(h.deps.prelogin).mockRejectedValueOnce(new PreloginError('PORTAL_UNREACHABLE', 'Cannot reach portal'));
    p.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(2000); // reconnect #1 → prelogin rejects
    expect(h.deps.prelogin).toHaveBeenCalledTimes(2);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState()).toMatchObject({ status: 'reconnecting', error: { code: 'PORTAL_UNREACHABLE' } });

    await vi.advanceTimersByTimeAsync(4999);
    expect(h.deps.prelogin).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1); // reconnect #2 after 5 s succeeds
    expect(h.deps.prelogin).toHaveBeenCalledTimes(3);
    expect(h.spawner.processes).toHaveLength(2);
  });

  it.each([
    ['AUTH_CANCELLED', new VpnError('AUTH_CANCELLED', 'closed')],
    ['PRIVILEGES_DENIED', new VpnError('PRIVILEGES_DENIED', 'untrusted')],
    ['AUTH_FAILED', new VpnError('AUTH_FAILED', 'no')],
  ] as const)('CR-1: stops reconnecting on a pre-spawn %s', async (code, err) => {
    const h = setup({ profile: { authMode: 'auto' } });
    const p = await connectAndEstablish(h);
    vi.mocked(h.deps.prelogin).mockRejectedValueOnce(err);
    p.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.deps.prelogin).toHaveBeenCalledTimes(2);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code } });
  });

  it('CR-1: a failing trust check during reconnect stops (non-retryable)', async () => {
    const h = setup();
    const p = await connectAndEstablish(h);
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValueOnce(new VpnError('PRIVILEGES_DENIED', 'not root-owned'));
    p.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState().error?.code).toBe('PRIVILEGES_DENIED');
  });

  it('CR-2: an openconnect that survives stop and kill is not reported as disconnected', async () => {
    const h = setup({ deps: { stopTimeoutMs: 1000 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    p.exitOnKill = false;

    const done = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(1000 + 3000);
    await done;
    expect(p.killCalls).toBe(1);
    const s = h.engine.getState();
    expect(s).toMatchObject({
      status: 'connected',
      assignedIp: '10.8.0.42',
      error: { code: 'PRIVILEGES_DENIED', message: expect.stringContaining('Нажмите «Отключить» ещё раз') },
    });
    expect(statuses(h)).not.toContain('disconnected');

    // the engine still owns the process: no second openconnect can be started
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect/);

    // Disconnect can be retried …
    p.exitOnStop = true;
    await h.engine.disconnect();
    expect(p.stopCalls).toBe(2);
    expect(h.engine.getState()).toEqual({ status: 'disconnected', profileId: PROFILE_ID });
  });

  it('CR-2: a late exit after a failed stop still finishes as disconnected', async () => {
    const h = setup({ deps: { stopTimeoutMs: 100 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    p.exitOnKill = false;
    const done = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(100 + 3000);
    await done;
    expect(h.engine.getState().status).toBe('connected');
    p.exit(0);
    await flush();
    expect(h.engine.getState()).toEqual({ status: 'disconnected', profileId: PROFILE_ID });
  });

  it('CR-2: error message is localized (en)', async () => {
    const h = setup({ settings: { language: 'en' }, deps: { stopTimeoutMs: 10 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    p.exitOnKill = false;
    const done = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(10 + 3000);
    await done;
    expect(h.engine.getState().error?.message).toMatch(
      /^The VPN may still be active: stopping openconnect needs administrator authorization/,
    );
  });

  it('CR-6: repeated disconnect calls share one stop (no extra admin dialogs)', async () => {
    const h = setup({ deps: { stopTimeoutMs: 1000 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    const a = h.engine.disconnect();
    const b = h.engine.disconnect();
    const c = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(1000);
    await Promise.all([a, b, c]);
    expect(p.stopCalls).toBe(1);
    expect(p.killCalls).toBe(1);
    expect(h.engine.getState().status).toBe('disconnected');
  });

  it('CR-7: a late-spawned process that cannot be killed is re-adopted and surfaced', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const inner = new FakeSpawner();
    const slow: ProcessSpawner = {
      spawn: async (req) => {
        await gate;
        const proc = await inner.spawn(req);
        proc.killError = new Error('pkexec: dismissed');
        return proc;
      },
    };
    const h = setup({ deps: { spawner: slow } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.disconnect();
    expect(h.engine.getState().status).toBe('disconnected');

    release();
    await flush();
    await vi.advanceTimersByTimeAsync(3000);
    const late = inner.last;
    expect(late.killCalls).toBe(1);
    expect(h.logger.lines().join('\n')).toMatch(/Failed to kill openconnect that started after disconnect/);
    expect(h.engine.getState()).toMatchObject({ status: 'authenticating', error: { code: 'PRIVILEGES_DENIED' } });
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect/);

    // retrying Disconnect stops it
    await h.engine.disconnect();
    expect(late.stopCalls).toBe(1);
    expect(h.engine.getState().status).toBe('disconnected');
  });

  it('CR-3: pending prompts can be fetched after the push was missed', async () => {
    const h = setup();
    h.savedPassword = undefined;
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getPendingPrompts()).toEqual(h.prompts);
    await h.engine.answerPrompt(h.prompts[0]!.id, 'pw');
    expect(h.engine.getPendingPrompts()).toEqual([]);
  });
});

describe('VpnEngine: error message/detail split (DR-3/DR-11)', () => {
  it('message is the next step only; the technical cause is in detail', async () => {
    const h = setup();
    await h.engine.connect(PROFILE_ID);
    await flush();
    h.spawner.last.err('Login failed.\n');
    h.spawner.last.exit(1);
    await flush();
    const e = h.engine.getState().error!;
    expect(e).toEqual({
      code: 'AUTH_FAILED',
      message: 'Проверьте логин, пароль или одноразовый код и попробуйте снова.',
      detail: 'Login failed.',
    });
    expect(e.message).not.toMatch(/\(/);
  });

  it('TLS message tells where to find the pin (en)', async () => {
    const h = setup({ settings: { language: 'en' } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    h.spawner.last.err("Enter 'yes' to accept, 'no' to abort; anything else to view: ");
    await vi.advanceTimersByTimeAsync(200);
    h.spawner.last.exit(1);
    await flush();
    expect(h.engine.getState().error?.message).toMatch(/--servercert=pin-sha256:<…>.*the pin value is in the log/);
  });

  it('untrusted binary shows the install hint, with the reason in detail', async () => {
    const h = setup();
    const { UntrustedPathError } = await import('../openconnect/trust');
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValue(
      new UntrustedPathError('/opt/homebrew/bin/openconnect', '/opt/homebrew/bin is not owned by root'),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error).toMatchObject({
      code: 'PRIVILEGES_DENIED',
      message: expect.stringContaining('MacPorts'),
      detail: expect.stringContaining('/opt/homebrew/bin is not owned by root'),
    });
  });

  it('omits detail when there is none and never leaks secrets into it', async () => {
    const h = setup({ settings: { autoReconnect: false } });
    const p = await connectAndEstablish(h);
    p.err('Unexpected 512 result from server Secr3tPass\n');
    p.exit(1);
    await flush();
    expect(h.engine.getState().error?.detail).not.toContain('Secr3tPass');
  });
});

describe('VpnEngine: code-review round 2 (CR-14/CR-15)', () => {
  it('CR-14: Disconnect during a forced stop ends disconnected, without auto-reconnect', async () => {
    const h = setup({ deps: { stopTimeoutMs: 10_000 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    // an internal failure while handling a prompt → forced stop with a retryable code (UNKNOWN)
    p.writeError = new Error('EPIPE');
    p.err('Username:');
    await vi.advanceTimersByTimeAsync(200);
    expect(p.stopCalls).toBe(1);

    const done = h.engine.disconnect();
    expect(h.engine.getState().status).toBe('disconnecting');
    expect(p.stopCalls).toBe(1); // joined the in-flight stop, no second stop chain
    p.exit(0);
    await done;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState()).toEqual({ status: 'disconnected', profileId: PROFILE_ID });
  });

  function gatedSpawner(onProc: (p: FakeProcess) => void = () => undefined) {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const inner = new FakeSpawner();
    const spawner: ProcessSpawner = {
      spawn: async (req) => {
        await gate;
        const proc = await inner.spawn(req);
        onProc(proc);
        return proc;
      },
    };
    return { spawner, inner, release: () => release() };
  }

  it('CR-15: connect is refused (busy) until a process started during Disconnect is disposed', async () => {
    const g = gatedSpawner((proc) => {
      proc.exitOnKill = false; // the kill takes a while
    });
    const h = setup({ deps: { spawner: g.spawner } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.disconnect();
    expect(h.engine.getState().status).toBe('disconnected');
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect while openconnect is still running/);

    g.release();
    await flush();
    const late = g.inner.last;
    expect(late.killCalls).toBe(1);
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect/); // kill still pending
    late.exit(null, 'SIGKILL');
    await flush();
    await h.engine.connect(PROFILE_ID); // now accepted
    expect(h.engine.getState().status).not.toBe('disconnected');
  });

  it('CR-15: a spawn failure after Disconnect also releases the busy marker', async () => {
    let fail!: (e: Error) => void;
    const spawner: ProcessSpawner = {
      spawn: () => new Promise((_res, rej) => (fail = rej)),
    };
    const h = setup({ deps: { spawner } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.disconnect();
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/still running/);
    fail(new SpawnError('PRIVILEGES_DENIED', 'UAC cancelled'));
    await flush();
    expect(h.engine.getState().status).toBe('disconnected');
    await h.engine.connect(PROFILE_ID);
  });

  it('CR-15: if the late kill fails the engine keeps ownership (no orphan)', async () => {
    const g = gatedSpawner((proc) => {
      proc.killError = new Error('pkexec dismissed');
    });
    const h = setup({ deps: { spawner: g.spawner } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.disconnect();
    g.release();
    await flush();
    await vi.advanceTimersByTimeAsync(3000);
    expect(h.engine.getState()).toMatchObject({ status: 'authenticating', error: { code: 'PRIVILEGES_DENIED' } });
    await expect(h.engine.connect(PROFILE_ID)).rejects.toThrow(/Cannot connect/);
    await h.engine.disconnect();
    expect(g.inner.last.stopCalls).toBe(1);
    expect(h.engine.getState().status).toBe('disconnected');
    await h.engine.connect(PROFILE_ID);
  });
});

describe('VpnEngine: masked values sent back by the renderer (CR-17)', () => {
  it('(a) a masked select option is mapped back to the raw option', async () => {
    const h = setup();
    h.savedPassword = 'Berlin';
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('Choose site: [Berlin-GW|Munich-GW]:');
    await vi.advanceTimersByTimeAsync(200);
    expect(h.prompts[0]!.options).toEqual(['***-GW', 'Munich-GW']);
    await h.engine.answerPrompt(h.prompts[0]!.id, '***-GW');
    await flush();
    expect(p.written).toEqual(['Berlin\n', 'Berlin-GW\n']);
    expect(h.engine.getState().status).not.toBe('error');
  });

  it('(a) an ambiguous masked option is rejected safely (nothing written)', async () => {
    const h = setup();
    h.savedPassword = 'Berlin';
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('Challenge:');
    await vi.advanceTimersByTimeAsync(200);
    await h.engine.answerPrompt(h.prompts[0]!.id, 'Munich'); // second registered secret
    await flush();
    p.err('Choose site: [Berlin-GW|Munich-GW]:');
    await vi.advanceTimersByTimeAsync(200);
    expect(h.prompts[1]!.options).toEqual(['***-GW', '***-GW']);
    await h.engine.answerPrompt(h.prompts[1]!.id, '***-GW');
    await flush();
    expect(p.written).toEqual(['Berlin\n', 'Munich\n']);
    expect(h.engine.getState().error?.code).toBe('AUTH_CANCELLED');
  });

  async function connectWithGateways(h: ReturnType<typeof setup>, list: string): Promise<void> {
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.out(list);
    p.out('Connected as 10.0.0.2\n');
    await flush();
    await h.engine.disconnect();
  }

  it('(b) a masked gateway from the renderer is translated back for --authgroup', async () => {
    const h = setup();
    h.savedPassword = 'Berlin';
    await connectWithGateways(
      h,
      '2 gateway servers available:\n  Berlin-GW (berlin.example.com)\n  Munich-GW (munich.example.com)\n',
    );
    // while connected the renderer saw the masked name
    expect(h.states.some((st) => st.gateways?.some((g) => g.name === '***-GW'))).toBe(true);

    await h.engine.connect(PROFILE_ID, { gateway: '***-GW' });
    await flush();
    expect(h.spawner.requests.at(-1)!.args).toContain('--authgroup=Berlin-GW');
  });

  it('(b) unmasked gateways pass through unchanged', async () => {
    const h = setup();
    h.savedPassword = 'Berlin';
    await connectWithGateways(
      h,
      '2 gateway servers available:\n  Berlin-GW (berlin.example.com)\n  Munich-GW (munich.example.com)\n',
    );
    await h.engine.connect(PROFILE_ID, { gateway: 'Munich-GW' });
    await flush();
    expect(h.spawner.requests.at(-1)!.args).toContain('--authgroup=Munich-GW');
  });

  it('(b) an ambiguous masked gateway falls back to automatic selection with a warning', async () => {
    const h = setup();
    h.savedPassword = 'Berlin';
    await h.engine.connect(PROFILE_ID);
    await flush();
    const p = h.spawner.last;
    p.err('Challenge:');
    await vi.advanceTimersByTimeAsync(200);
    await h.engine.answerPrompt(h.prompts[0]!.id, 'Munich');
    await flush();
    p.out('2 gateway servers available:\n  Berlin-GW (b.example.com)\n  Munich-GW (m.example.com)\n');
    p.out('Connected as 10.0.0.2\n');
    await flush();
    await h.engine.disconnect();

    await h.engine.connect(PROFILE_ID, { gateway: '***-GW' });
    await flush();
    expect(h.spawner.requests.at(-1)!.args.some((a) => a.startsWith('--authgroup'))).toBe(false);
    expect(h.logger.lines().join('\n')).toMatch(/Gateway "\*\*\*-GW" is ambiguous/);
  });
});

describe('VpnEngine: localization and hints (B2/A2)', () => {
  it('re-localizes an existing error on language change, keeping code/hint/detail', async () => {
    const h = setup({ deps: { locateOpenconnect: async () => '/home/alice/openconnect' } });
    const { UntrustedPathError } = await import('../openconnect/trust');
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValue(
      new UntrustedPathError('/home/alice/openconnect', '/home/alice is not owned by root'),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    const ru = h.engine.getState().error!;
    expect(ru).toMatchObject({
      code: 'PRIVILEGES_DENIED',
      hint: 'untrusted_binary',
      message: expect.stringMatching(/apt install/),
    });

    const emitted = h.states.length;
    h.settings.language = 'uk';
    h.engine.relocalize();
    const uk = h.engine.getState().error!;
    expect(h.states.length).toBe(emitted + 1);
    expect(uk).toEqual({ ...ru, message: expect.stringMatching(/^Встановіть OpenConnect із репозиторію/) });
    expect(uk.detail).toBe(ru.detail);

    h.engine.relocalize(); // same language → no extra emission
    expect(h.states.length).toBe(emitted + 1);
  });

  it('relocalize is a no-op without an error', () => {
    const h = setup();
    h.engine.relocalize();
    expect(h.states).toEqual([]);
  });

  it('uses the platform for the untrusted-binary text (win32)', async () => {
    const h = setup({ deps: { platform: 'win32' } });
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValue(
      Object.assign(new VpnError('PRIVILEGES_DENIED', 'x'), { hint: 'untrusted_binary' as const }),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error?.message).toMatch(/Program Files/);
  });

  it('settings_not_confirmed hint is carried into state', async () => {
    const h = setup();
    vi.mocked(h.deps.verifyElevatedFiles).mockRejectedValue(
      Object.assign(new VpnError('PRIVILEGES_DENIED', 'Changed openconnect settings were not confirmed'), {
        hint: 'settings_not_confirmed' as const,
      }),
    );
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error).toMatchObject({
      hint: 'settings_not_confirmed',
      message: expect.stringMatching(/подтвердите/),
    });
  });

  it('stop_failed hint is set when openconnect cannot be stopped', async () => {
    const h = setup({ deps: { stopTimeoutMs: 10 } });
    const p = await connectAndEstablish(h);
    p.exitOnStop = false;
    p.exitOnKill = false;
    const done = h.engine.disconnect();
    await vi.advanceTimersByTimeAsync(10 + 3000);
    await done;
    expect(h.engine.getState().error).toMatchObject({ code: 'PRIVILEGES_DENIED', hint: 'stop_failed' });
  });

  it('errors without a specific cause carry no hint', async () => {
    const h = setup({ deps: { locateOpenconnect: async () => null } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.engine.getState().error).not.toHaveProperty('hint');
  });
});
