/**
 * VpnEngine driven by recorded openconnect 9.x GlobalProtect output
 * (src/main/__fixtures__/openconnect/*.txt). Only the process boundary is fake:
 * output parsing, prompt detection, masking and the state machine are real.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { VpnErrorCode } from '../../shared/ipc';
import { fixture } from '../__fixtures__';
import {
  createHarness,
  flush,
  loadTranscript,
  playAll,
  playUntilPrompt,
  PROFILE_ID,
  PROMPT_SETTLE_MS,
  type Harness,
  type PlayOptions,
} from '../__fixtures__/engine-harness';
import { parsePrelogin } from '../auth/prelogin';
import { extractSamlFromHtml, type SamlSuccess } from '../auth/saml-extract';

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

const statuses = (h: Harness): string[] => h.states.map((s) => s.status);
/** Consecutive duplicates removed: the status path the user sees. */
const statusPath = (h: Harness): string[] => statuses(h).filter((s, i, a) => i === 0 || a[i - 1] !== s);

describe('password profile with OTP challenge and gateway list (openconnect 9.12 transcript)', () => {
  it.each<[string, PlayOptions]>([
    ['line by line', {}],
    // Pipe reads do not respect line boundaries; prompts may arrive in pieces within the debounce.
    ['re-chunked every 7 chars, prompts split 100 ms apart', { chunkSize: 7, splitPromptGapMs: 100 }],
    ['re-chunked every 1 char, prompts split 140 ms apart', { chunkSize: 1, splitPromptGapMs: 140 }],
  ])(
    'walks prelogin → authenticating → connecting → connected, answering gateway and OTP (%s)',
    async (_mode, play) => {
      const h = createHarness({ profile: { preferredGateway: 'gw-us.example.com' }, savedPassword: 'C0rrect-Horse' });

      await h.engine.connect(PROFILE_ID);
      await flush();
      const proc = h.spawner.last;
      // The password goes to stdin as soon as the process starts; never on the command line.
      expect(proc.written).toEqual(['C0rrect-Horse\n']);
      expect(h.spawner.requests[0]!.args.join(' ')).not.toContain('C0rrect-Horse');

      let rest = await playUntilPrompt(proc, loadTranscript('password-otp-gateways.txt'), play);
      // Preferred gateway given by address is matched to the portal's label automatically.
      expect(proc.written.at(-1)).toBe('US East\n');
      expect(h.prompts).toHaveLength(0);

      rest = await playUntilPrompt(proc, rest, play);
      expect(h.prompts).toEqual([
        {
          id: expect.any(String),
          kind: 'otp',
          message: 'Enter the 6-digit code from your authenticator app\nChallenge',
        },
      ]);
      expect(h.engine.getPendingPrompts()).toHaveLength(1);
      expect(h.engine.getState().status).toBe('authenticating');

      await h.engine.answerPrompt(h.prompts[0]!.id, '481516');
      await flush();
      expect(proc.written.at(-1)).toBe('481516\n');
      expect(h.engine.getPendingPrompts()).toEqual([]);

      await playAll(proc, rest, play);
      // Nothing else (e.g. a half-received line) was ever taken for a prompt or answered.
      expect(h.prompts).toHaveLength(1);
      expect(proc.written).toEqual(['C0rrect-Horse\n', 'US East\n', '481516\n']);

      expect(statusPath(h)).toEqual(['prelogin', 'authenticating', 'connecting', 'connected']);
      expect(h.engine.getState()).toEqual({
        status: 'connected',
        profileId: PROFILE_ID,
        assignedIp: '10.8.0.42',
        connectedAt: 1_700_000_000_000,
        gateway: { name: 'US East', address: 'gw-us.example.com', priority: 2 },
        gateways: [
          { name: 'Europe', address: 'gw-eu.example.com', priority: 1 },
          { name: 'US East', address: 'gw-us.example.com', priority: 2 },
        ],
      });
    },
  );

  it('asks for username and password when neither is stored, using the prelogin labels', async () => {
    const prelogin = parsePrelogin(fixture('prelogin-password.xml'));
    const h = createHarness({
      profile: { authMode: 'auto', username: undefined },
      deps: { prelogin: vi.fn(async () => prelogin) },
    });

    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.prompts.at(-1)).toMatchObject({ kind: 'text', message: 'Корп. логин' });
    await h.engine.answerPrompt(h.prompts.at(-1)!.id, '  bob  ');
    await flush();
    expect(h.prompts.at(-1)).toMatchObject({
      kind: 'password',
      message: 'Enter login credentials & OTP\nPassword + <token>',
    });
    await h.engine.answerPrompt(h.prompts.at(-1)!.id, 'pw-and-123456');
    await flush();

    expect(h.spawner.requests[0]!.args).toContain('--user=bob');
    expect(h.spawner.last.written).toEqual(['pw-and-123456\n']);
  });

  it('an empty username answer cancels the attempt without spawning', async () => {
    const h = createHarness({ profile: { username: undefined } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.answerPrompt(h.prompts[0]!.id, '   ');
    await flush();
    expect(h.spawner.requests).toHaveLength(0);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'AUTH_CANCELLED' } });
  });

  it('answers a later "Username:" prompt from openconnect with the known username', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    proc.err('Enter login credentials\nUsername:');
    await vi.advanceTimersByTimeAsync(PROMPT_SETTLE_MS);
    expect(proc.written.at(-1)).toBe('alice\n');
    expect(h.prompts).toHaveLength(0);
  });

  it('a password re-asked by openconnect after a failed OTP is not answered in a loop', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript('login-failed.txt'));
    await flush();

    // Only the initial password was written; the re-prompt stopped openconnect.
    expect(proc.written).toEqual(['C0rrect-Horse\n']);
    expect(proc.stopCalls).toBe(1);
    expect(h.prompts).toHaveLength(0);
    expect(h.engine.getState()).toMatchObject({
      status: 'error',
      // QA-1: the specific cause, not the generic follow-up "Login failed."
      error: { code: 'AUTH_FAILED', detail: 'Invalid username or password' },
    });
  });
});

describe('SAML profile in auto mode (prelogin + SAML fixtures + openconnect transcript)', () => {
  function samlHarness(over: Parameters<typeof createHarness>[0] = {}): Harness {
    const prelogin = parsePrelogin(fixture('prelogin-saml-redirect.xml'));
    const saml = extractSamlFromHtml(fixture('saml-success.html'));
    if (saml?.status !== 'success') throw new Error('fixture must be a successful SAML response');
    return createHarness({
      ...over,
      profile: { authMode: 'auto', username: undefined, ...over.profile },
      deps: {
        prelogin: vi.fn(async () => prelogin),
        samlLogin: vi.fn(async (): Promise<SamlSuccess> => saml),
        ...over.deps,
      },
    });
  }

  it('connects with the cookie on stdin, --usergroup and the SAML username; picks the first gateway', async () => {
    const h = samlHarness();
    await h.engine.connect(PROFILE_ID);
    await flush();

    expect(h.deps.samlLogin).toHaveBeenCalledWith(
      expect.objectContaining({ id: PROFILE_ID }),
      expect.objectContaining({ authType: 'saml', samlMethod: 'REDIRECT' }),
      expect.any(AbortSignal),
    );
    const { args } = h.spawner.requests[0]!;
    expect(args).toContain('--protocol=gp');
    expect(args).toContain('--usergroup=portal:prelogin-cookie');
    expect(args).toContain('--user=j.doe@example.com');
    expect(args).toContain('--passwd-on-stdin');
    expect(args.join(' ')).not.toContain('PRELOGIN-COOKIE-abc123XYZ');

    const proc = h.spawner.last;
    expect(proc.written).toEqual(['PRELOGIN-COOKIE-abc123XYZ\n']);
    await playAll(proc, loadTranscript('saml-gateways.txt'));

    expect(proc.written.at(-1)).toBe('Europe\n');
    expect(h.prompts).toEqual([]); // SAML needs no password prompt
    expect(statusPath(h)).toEqual(['prelogin', 'authenticating', 'connecting', 'connected']);
    expect(h.engine.getState()).toMatchObject({
      status: 'connected',
      assignedIp: '10.8.0.77',
      gateway: { name: 'Europe', address: 'gw-eu.example.com' },
    });
  });

  it('the cookie never appears in logs, states or prompts even when openconnect echoes it', async () => {
    const h = samlHarness();
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    proc.err('POST https://gw-eu.example.com/ssl-vpn/login.esp\n');
    proc.err('prelogin-cookie=PRELOGIN-COOKIE-abc123XYZ&user=j.doe%40example.com\n');
    proc.err(`Cookie: ${encodeURIComponent('PRELOGIN-COOKIE-abc123XYZ')}\n`);
    proc.err('Unexpected 512 result from server PRELOGIN-COOKIE-abc123XYZ\n');
    proc.exit(1);
    await flush();

    expect(h.engine.getState().error?.code).toBe('AUTH_FAILED');
    const everything = JSON.stringify([h.logger.lines(), h.states, h.prompts, h.engine.getState()]);
    expect(everything).not.toContain('PRELOGIN-COOKIE-abc123XYZ');
  });
});

describe('gateway selection', () => {
  async function selectFrom(h: Harness, options = 'Europe|US East'): Promise<string | undefined> {
    const proc = h.spawner.last;
    proc.err('2 gateway servers available:\n  Europe (gw-eu.example.com) [1]\n  US East (gw-us.example.com) [2]\n');
    proc.err(`Please select GlobalProtect gateway.\nGATEWAY: [${options}]:`);
    await vi.advanceTimersByTimeAsync(PROMPT_SETTLE_MS);
    return proc.written.at(-1);
  }

  it('a gateway chosen for this connection overrides the profile preference', async () => {
    const h = createHarness({ profile: { preferredGateway: 'Europe' }, savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID, { gateway: 'US East' });
    await flush();
    expect(h.spawner.requests[0]!.args).toContain('--authgroup=US East');
    expect(await selectFrom(h)).toBe('US East\n');
  });

  it('matches the preferred gateway by label case-insensitively', async () => {
    const h = createHarness({ profile: { preferredGateway: 'us east' }, savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(await selectFrom(h)).toBe('US East\n');
  });

  it('falls back to the first gateway (and logs a warning) when the preferred one is not offered', async () => {
    const h = createHarness({ profile: { preferredGateway: 'gw-asia.example.com' }, savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(await selectFrom(h)).toBe('Europe\n');
    expect(h.logger.lines().join('\n')).toMatch(/Gateway "gw-asia\.example\.com" is not offered by the portal/);
  });

  it('remembers the gateway list for the profile after disconnecting (for the manual picker)', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await selectFrom(h);
    h.spawner.last.err('Connected as 10.8.0.42, using SSL\n');
    await flush();
    await h.engine.disconnect();
    expect(h.engine.getState()).toEqual({
      status: 'disconnected',
      profileId: PROFILE_ID,
      gateways: [
        { name: 'Europe', address: 'gw-eu.example.com', priority: 1 },
        { name: 'US East', address: 'gw-us.example.com', priority: 2 },
      ],
    });
  });

  it('forwards a non-gateway choice to the user and rejects an answer that is not an option', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    proc.err('Choose your authentication method\nMETHOD: [Push|SMS]:');
    await vi.advanceTimersByTimeAsync(PROMPT_SETTLE_MS);
    expect(h.prompts).toEqual([
      {
        id: expect.any(String),
        kind: 'select',
        message: 'Choose your authentication method',
        options: ['Push', 'SMS'],
      },
    ]);

    await h.engine.answerPrompt(h.prompts[0]!.id, 'Carrier pigeon');
    await flush();
    expect(proc.written).toEqual(['C0rrect-Horse\n']); // nothing written for the bad answer
    expect(proc.stopCalls).toBe(1);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'AUTH_CANCELLED' } });
  });
});

describe('error codes from realistic openconnect output', () => {
  it.each<[string, VpnErrorCode, RegExp]>([
    // Detail of equal-priority errors is the first (root-cause) line (QA-1).
    [
      'portal-dns-failure.txt',
      'PORTAL_UNREACHABLE',
      /^getaddrinfo failed for host 'vpn\.example\.com': Name or service not known$/,
    ],
    [
      'portal-unreachable.txt',
      'PORTAL_UNREACHABLE',
      /^Failed to connect to 203\.0\.113\.10:443: Connection timed out$/,
    ],
    ['tun-not-root.txt', 'PRIVILEGES_DENIED', /Failed to bind local tun device \(TUNSETIFF\): Operation not permitted/],
    ['vpnc-script-error.txt', 'TUNNEL_FAILED', /vpnc-script' returned error 1/],
  ])('%s → %s', async (name, code, detail) => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript(name));
    proc.exit(1);
    await flush();

    const s = h.engine.getState();
    expect(s.status).toBe('error');
    expect(s.error?.code).toBe(code);
    expect(s.error?.detail).toMatch(detail);
    expect(s.error?.message).not.toBe('');
    // A first attempt that never connected is not retried.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(1);
  });

  it.each<[string, VpnErrorCode, string]>([
    [
      'portal-dns-failure.txt',
      'PORTAL_UNREACHABLE',
      "getaddrinfo failed for host 'vpn.example.com': Name or service not known",
    ],
  ])('QA-1: %s keeps the root cause as error.detail (%s)', async (name, code, detail) => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript(name));
    proc.exit(1);
    await flush();
    expect(h.engine.getState().error).toMatchObject({ code, detail });
  });

  it('QA-1: the specific auth failure wins over the later generic "Login failed."', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    proc.err('Invalid username or password\nLogin failed.\n');
    proc.exit(1);
    await flush();
    expect(h.engine.getState().error).toMatchObject({ code: 'AUTH_FAILED', detail: 'Invalid username or password' });
  });

  it('QA-1: a strictly more specific code still replaces a less specific one', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    proc.err('Failed to connect to host vpn.example.com\n');
    proc.err('Server certificate verify failed: signer not found\n');
    proc.exit(1);
    await flush();
    expect(h.engine.getState().error?.code).toBe('TLS_ERROR');
  });

  it('untrusted certificate: answers "no", reports TLS_ERROR with the pin line as detail', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript('cert-untrusted.txt'));
    expect(proc.written.at(-1)).toBe('no\n');
    expect(h.prompts).toHaveLength(0); // the user is never asked to accept an untrusted certificate

    proc.err('SSL connection failure: Error in the certificate verification.\n');
    proc.err('Failed to open HTTPS connection to vpn.example.com\nFailed to complete authentication\n');
    proc.exit(1);
    await flush();

    expect(h.engine.getState()).toMatchObject({
      status: 'error',
      error: {
        code: 'TLS_ERROR',
        detail: '--servercert pin-sha256:xp3scfzy3rOgQEXnfPiYKrUk7D66a8b8O+gEXaMPleE=',
      },
    });
  });

  it('a dropped established tunnel is TUNNEL_FAILED and goes to reconnecting with the cause', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await h.engine.connect(PROFILE_ID);
    await flush();
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript('saml-gateways.txt'));
    expect(h.engine.getState().status).toBe('connected');

    await playAll(proc, loadTranscript('session-drop.txt'));
    proc.exit(1);
    await flush();
    expect(h.engine.getState()).toMatchObject({
      status: 'reconnecting',
      profileId: PROFILE_ID,
      error: { code: 'TUNNEL_FAILED', detail: 'Unrecoverable I/O error; exiting.' },
    });
  });
});

describe('auto-reconnect', () => {
  async function establish(h: Harness): Promise<void> {
    await h.engine.connect(PROFILE_ID);
    await flush();
    h.spawner.last.err('GlobalProtect login returned authentication-source=local\nConnected as 10.8.0.42, using SSL\n');
    await flush();
    expect(h.engine.getState().status).toBe('connected');
  }

  it('waits 2, 5, 10, 30, 30 s between failing reconnect attempts (default backoff, capped at 30 s)', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse' });
    await establish(h);
    const spawnTimes: number[] = [];
    let t = 0;
    h.spawner.last.exit(1);
    await flush();
    for (let attempt = 0; attempt < 5; attempt++) {
      const before = h.spawner.processes.length;
      while (h.spawner.processes.length === before) {
        await vi.advanceTimersByTimeAsync(500);
        t += 500;
      }
      spawnTimes.push(t);
      t = 0;
      h.spawner.last.err('Failed to connect to host vpn.example.com\n');
      h.spawner.last.exit(1);
      await flush();
    }
    expect(spawnTimes).toEqual([2000, 5000, 10_000, 30_000, 30_000]);
    expect(h.engine.getState()).toMatchObject({ status: 'reconnecting', error: { code: 'PORTAL_UNREACHABLE' } });
  });

  it('reconnect attempts keep the gateway chosen for the original connection', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse', deps: { backoffMs: [100] } });
    await h.engine.connect(PROFILE_ID, { gateway: 'US East' });
    await flush();
    h.spawner.last.err('Connected as 10.8.0.42, using SSL\n');
    await flush();
    h.spawner.last.exit(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(h.spawner.processes).toHaveLength(2);
    expect(h.spawner.requests[1]!.args).toContain('--authgroup=US East');
  });

  it('a typed password is reused for reconnects without prompting again, then forgotten on disconnect', async () => {
    const h = createHarness({ deps: { backoffMs: [100] } });
    await h.engine.connect(PROFILE_ID);
    await flush();
    await h.engine.answerPrompt(h.prompts[0]!.id, 'Typed-Pa55');
    await flush();
    h.spawner.last.err('Connected as 10.8.0.42, using SSL\n');
    await flush();

    h.spawner.last.exit(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(h.prompts).toHaveLength(1);
    expect(h.spawner.last.written).toEqual(['Typed-Pa55\n']);

    await h.engine.disconnect();
    await h.engine.connect(PROFILE_ID);
    await flush();
    expect(h.prompts).toHaveLength(2); // asked again after an explicit disconnect
    expect(h.prompts[1]!.kind).toBe('password');
  });

  it('Disconnect while a reconnect attempt is running stops it and schedules nothing more', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse', deps: { backoffMs: [100] } });
    await establish(h);
    h.spawner.last.exit(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(h.spawner.processes).toHaveLength(2);
    expect(h.engine.getState().status).toBe('reconnecting');

    await h.engine.disconnect();
    expect(h.spawner.last.stopCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(2);
    expect(h.engine.getState()).toMatchObject({ status: 'disconnected' });
    expect(h.engine.getState().error).toBeUndefined();
  });

  it('a profile deleted during the backoff wait ends the reconnect as disconnected', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse', deps: { backoffMs: [100] } });
    await establish(h);
    h.spawner.last.exit(1);
    await flush();
    h.profileExists = false;
    await vi.advanceTimersByTimeAsync(100);
    expect(h.spawner.processes).toHaveLength(1);
    expect(h.engine.getState()).toEqual({ status: 'disconnected' });
  });

  it('an untrusted certificate during a reconnect is not retried', async () => {
    const h = createHarness({ savedPassword: 'C0rrect-Horse', deps: { backoffMs: [100] } });
    await establish(h);
    h.spawner.last.exit(1);
    await vi.advanceTimersByTimeAsync(100);
    const proc = h.spawner.last;
    await playAll(proc, loadTranscript('cert-untrusted.txt'));
    proc.exit(1);
    await flush();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.spawner.processes).toHaveLength(2);
    expect(h.engine.getState()).toMatchObject({ status: 'error', error: { code: 'TLS_ERROR' } });
  });
});
