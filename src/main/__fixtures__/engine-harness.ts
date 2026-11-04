/**
 * Test harness for {@link VpnEngine}: a scriptable fake openconnect process and
 * spawner, plus a helper that replays recorded openconnect transcripts.
 * Only the process boundary is faked; parser, logger and masking are real.
 */
import { vi } from 'vitest';
import { DEFAULT_SETTINGS, type AuthPrompt, type Profile, type Settings, type VpnState } from '../../shared/ipc';
import type { PreloginResult } from '../auth/prelogin';
import type { SamlSuccess } from '../auth/saml-extract';
import { Logger } from '../logging/logger';
import { BaseVpnProcess, type ProcessSpawner, type SpawnRequest } from '../process/types';
import { VpnEngine, type EngineDeps } from '../vpn/engine';
import { fixture, toCrlf } from './index';

export class FakeProcess extends BaseVpnProcess {
  readonly pid = 4242;
  /** Everything written to stdin, in order. */
  readonly written: string[] = [];
  stopCalls = 0;
  killCalls = 0;

  write(data: string): void {
    this.written.push(data);
  }
  /**
   * Like a real process, the exit is reported only after stop()/kill() has
   * resolved (a few microtasks later, no timers needed), so engine code that runs
   * between "signal sent" and "process gone" is exercised.
   */
  async stop(): Promise<void> {
    this.stopCalls++;
    this.exitSoon(0, null);
  }
  async kill(): Promise<void> {
    this.killCalls++;
    this.exitSoon(null, 'SIGKILL');
  }
  private exitSoon(code: number | null, signal: string | null): void {
    void Promise.resolve()
      .then(() => undefined)
      .then(() => undefined)
      .then(() => this.exit(code, signal));
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

export class FakeSpawner implements ProcessSpawner {
  readonly requests: SpawnRequest[] = [];
  readonly processes: FakeProcess[] = [];

  async spawn(req: SpawnRequest): Promise<FakeProcess> {
    this.requests.push(req);
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

export const PROFILE_ID = '11111111-2222-4333-8444-555555555555';

export interface Harness {
  engine: VpnEngine;
  spawner: FakeSpawner;
  logger: Logger;
  states: VpnState[];
  prompts: AuthPrompt[];
  profile: Profile;
  settings: Settings;
  deps: EngineDeps;
  /** Mutable: what `getSavedPassword` returns. */
  savedPassword: string | undefined;
  /** Mutable: `getProfile` returns undefined when false (profile deleted). */
  profileExists: boolean;
}

export interface HarnessOptions {
  profile?: Partial<Profile>;
  settings?: Partial<Settings>;
  deps?: Partial<EngineDeps>;
  logger?: Logger;
  savedPassword?: string;
}

export function createHarness(over: HarnessOptions = {}): Harness {
  const spawner = new FakeSpawner();
  const logger = over.logger ?? new Logger(null);
  const profile: Profile = {
    id: PROFILE_ID,
    name: 'Work',
    portalUrl: 'https://vpn.example.com',
    username: 'alice',
    authMode: 'password',
    savePassword: false,
    ...over.profile,
  };
  const settings: Settings = { ...DEFAULT_SETTINGS, autoReconnect: true, ...over.settings };
  const h = {
    savedPassword: 'savedPassword' in over ? over.savedPassword : undefined,
    profileExists: true,
  } as Harness;
  let n = 0;
  const deps: EngineDeps = {
    platform: 'linux',
    getProfile: (id) => (h.profileExists && id === profile.id ? profile : undefined),
    getSavedPassword: () => h.savedPassword,
    getSettings: () => settings,
    prelogin: vi.fn(async (): Promise<PreloginResult> => ({ authType: 'password' })),
    samlLogin: vi.fn(async (): Promise<SamlSuccess> => {
      throw new Error('samlLogin not configured');
    }),
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

/** Lets pending promises and zero-delay timers run (fake timers must be enabled). */
export async function flush(): Promise<void> {
  await vi.advanceTimersByTimeAsync(0);
}

/** Longer than the engine's prompt debounce (150 ms). */
export const PROMPT_SETTLE_MS = 200;

// ------------------------------------------------------------------ transcripts

/**
 * One step of a recorded openconnect session.
 * - `out`: complete lines on stdout/stderr
 * - `prompt`: a newline-less fragment; openconnect now waits for stdin
 */
export type TranscriptStep =
  | { kind: 'out'; stream: 'stdout' | 'stderr'; text: string }
  | { kind: 'prompt'; stream: 'stderr'; text: string };

/**
 * Parses a transcript fixture. Format, one entry per line:
 * - `# …` comment (ignored)
 * - `! text` → stderr line. openconnect writes errors (PRG_ERR) and auth-form
 *   messages to stderr …
 * - `? Label:` → … and interactive prompts, on stderr without a trailing newline
 * - anything else → stdout line (progress: PRG_INFO / PRG_DEBUG)
 */
export function loadTranscript(name: string, opts: { eol?: 'lf' | 'crlf' } = {}): TranscriptStep[] {
  // With eol 'crlf' every emitted line ends in CRLF and every prompt in a lone CR,
  // like output from openconnect.exe / the Windows UAC bridge.
  const text = fixture(`openconnect/${name}`);
  const source = opts.eol === 'crlf' ? toCrlf(text) : text;
  const steps: TranscriptStep[] = [];
  for (const raw of source.split('\n')) {
    if (raw.startsWith('#') || raw === '' || raw === '\r') continue;
    if (raw.startsWith('? ')) steps.push({ kind: 'prompt', stream: 'stderr', text: raw.slice(2) });
    else if (raw.startsWith('! ')) steps.push({ kind: 'out', stream: 'stderr', text: `${raw.slice(2)}\n` });
    else steps.push({ kind: 'out', stream: 'stdout', text: `${raw}\n` });
  }
  return steps;
}

export interface PlayOptions {
  /**
   * Re-chunk the output at this many characters, ignoring line boundaries
   * (consecutive steps on the same stream are merged first), like pipe reads do.
   */
  chunkSize?: number;
  /**
   * Deliver each prompt in two chunks this many ms apart. Must stay below the
   * engine's 150 ms prompt debounce: the first half must not be taken as a prompt.
   */
  splitPromptGapMs?: number;
}

function emit(proc: FakeProcess, stream: 'stdout' | 'stderr', text: string, chunkSize = text.length): void {
  for (let k = 0; k < text.length; k += Math.max(1, chunkSize)) {
    const chunk = text.slice(k, k + Math.max(1, chunkSize));
    if (stream === 'stdout') proc.out(chunk);
    else proc.err(chunk);
  }
}

/**
 * Replays transcript steps into the process until (and including) the next
 * prompt, then waits past the prompt debounce. Returns the remaining steps.
 */
export async function playUntilPrompt(
  proc: FakeProcess,
  steps: TranscriptStep[],
  opts: PlayOptions = {},
): Promise<TranscriptStep[]> {
  let pending: { stream: 'stdout' | 'stderr'; text: string } | null = null;
  const flushPending = (): void => {
    if (pending) emit(proc, pending.stream, pending.text, opts.chunkSize);
    pending = null;
  };
  let i = 0;
  for (; i < steps.length; i++) {
    const s = steps[i];
    if (!s) break;
    if (s.kind === 'prompt') {
      flushPending();
      if (opts.splitPromptGapMs !== undefined) {
        const mid = Math.ceil(s.text.length / 2);
        emit(proc, s.stream, s.text.slice(0, mid), opts.chunkSize);
        await vi.advanceTimersByTimeAsync(opts.splitPromptGapMs);
        emit(proc, s.stream, s.text.slice(mid), opts.chunkSize);
      } else {
        emit(proc, s.stream, s.text, opts.chunkSize);
      }
      i++;
      break;
    }
    if (opts.chunkSize === undefined) {
      emit(proc, s.stream, s.text);
    } else if (pending && pending.stream === s.stream) {
      pending.text += s.text;
    } else {
      flushPending();
      pending = { stream: s.stream, text: s.text };
    }
  }
  flushPending();
  await vi.advanceTimersByTimeAsync(PROMPT_SETTLE_MS);
  return steps.slice(i);
}

/** Replays all remaining steps (prompts included, each followed by the debounce). */
export async function playAll(proc: FakeProcess, steps: TranscriptStep[], opts: PlayOptions = {}): Promise<void> {
  let rest = steps;
  while (rest.length > 0) rest = await playUntilPrompt(proc, rest, opts);
}
