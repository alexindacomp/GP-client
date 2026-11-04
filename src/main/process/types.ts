import type { VpnErrorCode } from '../../shared/ipc';
import { VpnError } from '../vpn/errors';

export interface ExitInfo {
  code: number | null;
  signal: string | null;
}

/** A running (possibly elevated) openconnect process. */
export interface VpnProcess {
  readonly pid: number | undefined;
  /** Writes to the process' stdin. */
  write(data: string): void;
  onStdout(cb: (chunk: string) => void): void;
  onStderr(cb: (chunk: string) => void): void;
  onExit(cb: (info: ExitInfo) => void): void;
  /** Graceful stop: SIGINT / Ctrl+C, so openconnect runs its disconnect script. */
  stop(): Promise<void>;
  /** Forced termination. */
  kill(): Promise<void>;
}

export interface SpawnRequest {
  binary: string;
  args: string[];
}

export interface ProcessSpawner {
  /** Starts the process; rejects with {@link SpawnError} when it cannot be started. */
  spawn(req: SpawnRequest): Promise<VpnProcess>;
}

export class SpawnError extends VpnError {
  constructor(code: VpnErrorCode, message: string, options?: { cause?: unknown }) {
    super(code, message, options);
    this.name = 'SpawnError';
  }
}

type Listener<T> = (v: T) => void;

/**
 * Event plumbing shared by spawner implementations. Output emitted before a
 * listener is attached is buffered, so no early output is lost.
 */
export abstract class BaseVpnProcess implements VpnProcess {
  abstract readonly pid: number | undefined;
  abstract write(data: string): void;
  abstract stop(): Promise<void>;
  abstract kill(): Promise<void>;

  private readonly listeners = {
    stdout: [] as Listener<string>[],
    stderr: [] as Listener<string>[],
    exit: [] as Listener<ExitInfo>[],
  };
  private readonly backlog = { stdout: [] as string[], stderr: [] as string[] };
  private exitInfo: ExitInfo | null = null;

  onStdout(cb: Listener<string>): void {
    this.listeners.stdout.push(cb);
    for (const c of this.backlog.stdout.splice(0)) cb(c);
  }

  onStderr(cb: Listener<string>): void {
    this.listeners.stderr.push(cb);
    for (const c of this.backlog.stderr.splice(0)) cb(c);
  }

  onExit(cb: Listener<ExitInfo>): void {
    this.listeners.exit.push(cb);
    if (this.exitInfo) cb(this.exitInfo);
  }

  get exited(): boolean {
    return this.exitInfo !== null;
  }

  protected emitOutput(stream: 'stdout' | 'stderr', chunk: string): void {
    if (chunk === '') return;
    const ls = this.listeners[stream];
    if (ls.length === 0) this.backlog[stream].push(chunk);
    else for (const l of ls) l(chunk);
  }

  protected emitExit(info: ExitInfo): void {
    if (this.exitInfo) return;
    this.exitInfo = info;
    for (const l of this.listeners.exit) l(info);
  }
}
