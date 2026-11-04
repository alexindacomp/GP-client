/**
 * Acceptance #4: passwords / OTPs / SAML cookies never reach the log buffer, the
 * log file, VpnState (message/detail), prompts or anything else sent to the
 * renderer after submission.
 *
 * Real: VpnEngine, Logger (writing to a temp dir), masking, IPC handlers with
 * sender validation. Fake: openconnect process, prelogin/SAML, Electron ipcMain.
 * The renderer sink is wired exactly like index.ts (state, prompt and log-line
 * pushes) plus every value returned by IPC invokes.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IPC, type Settings } from '../shared/ipc';
import { fixture } from './__fixtures__';
import { createHarness, flush, loadTranscript, playAll, PROFILE_ID, type Harness } from './__fixtures__/engine-harness';
import {
  eventFrom,
  fakeWebContents,
  invoke,
  ipcRegistry,
  RENDERER,
  type FakeWebContents,
} from './__fixtures__/fake-ipc';
import { parsePrelogin } from './auth/prelogin';
import { extractSamlFromHtml, type SamlSuccess } from './auth/saml-extract';
import { Logger } from './logging/logger';

vi.mock('electron', async () => (await import('./__fixtures__/fake-ipc')).fakeElectronModule());
const { registerIpcHandlers } = await import('./ipc/handlers');

const PASSWORD = 'Hunter2-Pa$$word!';
const OTP = '918273';
const COOKIE = 'PRELOGIN-COOKIE-abc123XYZ'; // from saml-success.html

interface World {
  h: Harness;
  logger: Logger;
  logFile: string;
  /** Everything pushed to or returned to the renderer. */
  toRenderer: unknown[];
  call(channel: string, ...args: unknown[]): Promise<unknown>;
}

let tmp: string;
/** Every logger opened by a test; closed afterwards so no file stream outlives its temp dir. */
const openLoggers: Logger[] = [];

beforeEach(() => {
  vi.useFakeTimers();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-secrets-'));
});
afterEach(() => {
  for (const l of openLoggers.splice(0)) l.close();
  vi.useRealTimers();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function world(over: Parameters<typeof createHarness>[0] = {}): World {
  const logger = new Logger(path.join(tmp, 'logs'));
  openLoggers.push(logger);
  const h = createHarness({ ...over, logger });
  const toRenderer: unknown[] = [];
  h.engine.onState((s) => toRenderer.push(s));
  h.engine.onPrompt((p) => toRenderer.push(p));
  logger.onLine((l) => toRenderer.push(l));

  ipcRegistry.reset();
  const wc: FakeWebContents = fakeWebContents();
  registerIpcHandlers({
    logger,
    renderer: RENDERER,
    trustedContents: () => wc as unknown as Electron.WebContents,
    backend: {
      listProfiles: () => [h.profile],
      saveProfile: () => h.profile,
      removeProfile: () => undefined,
      connect: (id, opts) => h.engine.connect(id, opts),
      disconnect: () => h.engine.disconnect(),
      getState: () => h.engine.getState(),
      answerPrompt: (id, v) => h.engine.answerPrompt(id, v),
      getPendingPrompts: () => h.engine.getPendingPrompts(),
      getLogs: () => logger.lines(),
      openLogsFolder: async () => undefined,
      getSettings: () => h.settings,
      setSettings: (p) => ({ ...h.settings, ...p }) as Settings,
      systemInfo: async () => ({
        platform: 'linux',
        openconnectFound: true,
        appVersion: '0',
        shouldUseDarkColors: false,
      }),
      openExternal: async () => undefined,
      minimizeWindow: () => undefined,
      closeWindow: () => undefined,
    },
  });
  const call = async (channel: string, ...args: unknown[]): Promise<unknown> => {
    try {
      const r = await invoke(eventFrom(wc), channel, ...args);
      toRenderer.push(r);
      return r;
    } catch (err) {
      toRenderer.push(err instanceof Error ? err.message : err);
      throw err;
    }
  };
  return { h, logger, logFile: path.join(tmp, 'logs', 'gp-connect.log'), toRenderer, call };
}

/** Closes the logger and returns the log file content once the marker line is flushed to disk. */
async function logFileContent(w: World): Promise<string> {
  w.logger.info('test', 'END-OF-TEST-MARKER');
  w.logger.close();
  let content = '';
  await vi.waitFor(() => {
    content = fs.readFileSync(w.logFile, 'utf8');
    expect(content).toContain('END-OF-TEST-MARKER');
  });
  return content;
}

/** After the attempt: snapshot calls a reloaded renderer would make. */
async function snapshotCalls(w: World): Promise<void> {
  await w.call(IPC.vpn.getState);
  await w.call(IPC.logs.get);
  await w.call(IPC.vpn.getPendingPrompts);
}

function expectNoSecret(haystack: unknown, secrets: string[]): void {
  const text = typeof haystack === 'string' ? haystack : JSON.stringify(haystack);
  for (const s of secrets) {
    expect(text).not.toContain(s);
    expect(text).not.toContain(encodeURIComponent(s));
  }
}

describe('acceptance #4: secrets never leak', () => {
  it('password given at connect + OTP typed in the dialog, echoed by a verbose openconnect, then login fails', async () => {
    const w = world();
    await w.call(IPC.vpn.connect, PROFILE_ID, { password: PASSWORD });
    await flush();
    const proc = w.h.spawner.last;
    expect(proc.written[0]).toBe(`${PASSWORD}\n`); // the secret does reach openconnect

    // openconnect -v / --dump-http-traffic style echoes
    proc.err(`POST body: user=alice&passwd=${encodeURIComponent(PASSWORD)}&computer=host\n`);
    proc.err(`< <response><passwd>${PASSWORD}</passwd></response>\n`);
    proc.err('Enter the 6-digit code from your authenticator app\nChallenge:');
    await vi.advanceTimersByTimeAsync(200);
    const prompt = (await w.call(IPC.vpn.getPendingPrompts)) as { id: string }[];
    await w.call(IPC.vpn.answerPrompt, prompt[0]!.id, OTP);
    await flush();
    expect(proc.written.at(-1)).toBe(`${OTP}\n`);

    proc.err(`inputStr=${OTP}&passwd=${PASSWORD}\n`);
    proc.err(`Login failed for user alice with ${PASSWORD} / ${OTP}\n`);
    proc.exit(1);
    await flush();

    const state = w.h.engine.getState();
    expect(state).toMatchObject({ status: 'error', error: { code: 'AUTH_FAILED' } });
    expect(state.error?.detail).toBe('Login failed for user alice with *** / ***');

    await snapshotCalls(w);
    const file = await logFileContent(w);
    expect(file).toMatch(/\[openconnect\] Login failed for user alice with \*\*\* \/ \*\*\*/); // not vacuous
    expectNoSecret(file, [PASSWORD, OTP]);
    expectNoSecret(w.logger.lines(), [PASSWORD, OTP]);
    expectNoSecret(w.toRenderer, [PASSWORD, OTP]);
    expect(w.toRenderer.length).toBeGreaterThan(10);
  });

  it('saved password and a successful session: nothing leaks during connect, drop, reconnect and disconnect', async () => {
    const w = world({ savedPassword: PASSWORD, deps: { backoffMs: [100] } });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const first = w.h.spawner.last;
    await playAll(
      first,
      loadTranscript('password-otp-gateways.txt').filter((s) => s.kind === 'out'),
    );
    // Bare values without any key ("passwd=", "Cookie:"): only masking by value can catch these.
    first.out(`GPST negotiated ${PASSWORD} for alice\n`);
    first.err(`Unexpected reply ${encodeURIComponent(PASSWORD)} from gw-us.example.com\n`);
    expect(w.h.engine.getState().status).toBe('connected');

    first.err('Unrecoverable I/O error; exiting.\n');
    first.exit(1);
    await vi.advanceTimersByTimeAsync(100); // reconnect with the in-memory password
    const second = w.h.spawner.last;
    expect(second).not.toBe(first);
    expect(second.written).toEqual([`${PASSWORD}\n`]);
    second.out(`ESP handshake with ${PASSWORD} ok\n`);
    await w.call(IPC.vpn.disconnect);

    await snapshotCalls(w);
    const file = await logFileContent(w);
    expect(file).toContain('Connected, assigned IP 10.8.0.42');
    // Both attempts' echoes were logged, masked.
    expect(file).toContain('[openconnect] GPST negotiated *** for alice');
    expect(file).toContain('[openconnect] Unexpected reply *** from gw-us.example.com');
    expect(file).toContain('[openconnect] ESP handshake with *** ok');
    expectNoSecret(file, [PASSWORD]);
    expectNoSecret(w.logger.lines(), [PASSWORD]);
    expectNoSecret(w.toRenderer, [PASSWORD]);
  });

  it('SAML cookie (from the HTML fixture) stays out of logs, file, state and renderer', async () => {
    const saml = extractSamlFromHtml(fixture('saml-success.html')) as SamlSuccess;
    const w = world({
      profile: { authMode: 'auto', username: undefined },
      deps: {
        prelogin: vi.fn(async () => parsePrelogin(fixture('prelogin-saml-redirect.xml'))),
        samlLogin: vi.fn(async () => saml),
      },
    });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const proc = w.h.spawner.last;
    expect(proc.written).toEqual([`${COOKIE}\n`]);

    proc.err(`POST https://gw-eu.example.com/ssl-vpn/login.esp?prelogin-cookie=${COOKIE}&user=j.doe\n`);
    proc.err(`Set-Cookie: SESSID=${COOKIE}; Path=/\n`);
    proc.err(`Unexpected 512 result from server; cookie ${COOKIE} rejected\n`);
    proc.exit(1);
    await flush();
    expect(w.h.engine.getState().error?.code).toBe('AUTH_FAILED');

    await snapshotCalls(w);
    const file = await logFileContent(w);
    expect(file).toContain('Unexpected 512 result from server');
    expectNoSecret(file, [COOKIE]);
    expectNoSecret(w.toRenderer, [COOKIE]);
  });

  it('a rejected (multi-line) password is not echoed back to the renderer or logged', async () => {
    const w = world();
    const bad = `${PASSWORD}\n--script=/tmp/x`;
    await expect(w.call(IPC.vpn.connect, PROFILE_ID, { password: bad })).rejects.toThrow(/single line/);
    const file = await logFileContent(w);
    expectNoSecret(file, [PASSWORD]);
    expectNoSecret(w.toRenderer, [PASSWORD]);
    expect(w.h.spawner.requests).toHaveLength(0);
  });

  it('a password typed into a prompt is not kept in the pending prompts after it is answered', async () => {
    const w = world();
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const [p] = (await w.call(IPC.vpn.getPendingPrompts)) as { id: string }[];
    await w.call(IPC.vpn.answerPrompt, p!.id, PASSWORD);
    await flush();
    expect(await w.call(IPC.vpn.getPendingPrompts)).toEqual([]);
    // A late duplicate answer is refused (the prompt is gone) without echoing the value.
    await expect(w.call(IPC.vpn.answerPrompt, p!.id, PASSWORD)).rejects.toThrow(/expired/);
    expectNoSecret(w.toRenderer, [PASSWORD]);
  });

  it('QA-2: a secret inside a newline-less prompt label is masked in AuthPrompt.message', async () => {
    const w = world({ savedPassword: PASSWORD });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const proc = w.h.spawner.last;
    proc.err(`Second factor for ${PASSWORD}:`);
    await vi.advanceTimersByTimeAsync(200);
    expect(w.h.prompts).toHaveLength(1);
    expect(w.h.prompts[0]!.message).toBe('Second factor for ***');
    const pending = await w.call(IPC.vpn.getPendingPrompts);
    expectNoSecret([w.h.prompts, pending, w.toRenderer], [PASSWORD]);
    expectNoSecret(w.logger.lines(), [PASSWORD]);
  });

  it('QA-2: secrets in select options are masked too', async () => {
    const w = world({ savedPassword: PASSWORD });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    w.h.spawner.last.err(`Choose: [Push|${PASSWORD}]:`);
    await vi.advanceTimersByTimeAsync(200);
    expect(w.h.prompts[0]!.options).toEqual(['Push', '***']);
    expectNoSecret(w.toRenderer, [PASSWORD]);
  });

  it('QA-3: a short password (< 4 chars) never reaches the log, state or renderer', async () => {
    const w = world({ savedPassword: 'abc' });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const proc = w.h.spawner.last;
    proc.err('Login failed for abc\n');
    proc.exit(1);
    await flush();
    const state = w.h.engine.getState();
    expect(state.error?.detail).toBe('Login failed for ***');
    expect(w.logger.lines().join('\n')).not.toMatch(/\babc\b/);
    expect(JSON.stringify(w.toRenderer)).not.toMatch(/\babc\b/);
    expect(await logFileContent(w)).not.toMatch(/\babc\b/);
  });

  it('classification runs on the raw line: 1-char password "a" does not break "sudo: a password is required"', async () => {
    const w = world({ savedPassword: 'a' });
    await w.call(IPC.vpn.connect, PROFILE_ID);
    await flush();
    const proc = w.h.spawner.last;
    proc.err('sudo: a password is required\n');
    proc.exit(1);
    await flush();
    const state = w.h.engine.getState();
    // classified exactly as without the secret …
    expect(state.error?.code).toBe('PRIVILEGES_DENIED');
    // … while the secret is masked in everything that leaves the parser
    expect(state.error?.detail).toBe('sudo: *** password is required');
    const logged = w.logger.lines().find((l) => l.includes('password is required'));
    expect(logged).toMatch(/sudo: \*\*\* password is required$/);
    expect(await logFileContent(w)).toContain('sudo: *** password is required');
    expect(JSON.stringify(w.toRenderer)).not.toContain('sudo: a password');
  });
});
