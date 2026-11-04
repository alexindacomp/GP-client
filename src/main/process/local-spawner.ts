import { spawn, execFile, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { privilegedKillCommand, wrapCommand, type WrappedCommand } from './elevation';
import { BaseVpnProcess, SpawnError, type ProcessSpawner, type SpawnRequest } from './types';

type Signal = 'INT' | 'TERM' | 'KILL';

function run(cmd: WrappedCommand, timeoutMs = 60_000): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(cmd.command, cmd.args, { timeout: timeoutMs, windowsHide: true }, (err) =>
      err ? reject(err) : resolve(),
    );
  });
}

/**
 * openconnect as a direct child process with piped stdio: unprivileged/root,
 * or `pkexec` (Linux).
 */
class LocalVpnProcess extends BaseVpnProcess {
  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly elevation: 'none' | 'pkexec',
  ) {
    super();
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c: string) => this.emitOutput('stdout', c));
    child.stderr.on('data', (c: string) => this.emitOutput('stderr', c));
    child.stdin.on('error', () => {
      // EPIPE after the process exited; the exit handler reports it.
    });
    child.on('close', (code, signal) => this.emitExit({ code, signal }));
  }

  get pid(): number | undefined {
    return this.child.pid;
  }

  write(data: string): void {
    if (!this.exited && this.child.stdin.writable) this.child.stdin.write(data);
  }

  stop(): Promise<void> {
    return this.signal('INT');
  }

  kill(): Promise<void> {
    return this.signal('KILL');
  }

  private async signal(sig: Signal): Promise<void> {
    const pid = this.child.pid;
    if (this.exited || pid === undefined) return;
    try {
      process.kill(pid, `SIG${sig}`);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ESRCH') return;
      if (code !== 'EPERM' || this.elevation === 'none') throw err;
    }
    // The process runs as root (pkexec execs in place), so our uid may not signal it.
    await run(privilegedKillCommand(pid, sig));
  }
}

export class LocalSpawner implements ProcessSpawner {
  constructor(private readonly elevation: 'none' | 'pkexec') {}

  spawn(req: SpawnRequest): Promise<LocalVpnProcess> {
    const cmd = wrapCommand(this.elevation, req.binary, req.args);
    return new Promise((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(cmd.command, cmd.args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch (err) {
        reject(new SpawnError('UNKNOWN', `Failed to start ${cmd.command}`, { cause: err }));
        return;
      }
      const onError = (err: NodeJS.ErrnoException): void => {
        const missing = err.code === 'ENOENT';
        const code =
          missing && this.elevation === 'none' ? 'OPENCONNECT_NOT_FOUND' : missing ? 'PRIVILEGES_DENIED' : 'UNKNOWN';
        reject(new SpawnError(code, `Failed to start ${cmd.command}: ${err.message}`, { cause: err }));
      };
      child.once('error', onError);
      child.once('spawn', () => {
        child.off('error', onError);
        child.on('error', () => {
          // Signal delivery errors etc.; exit is reported via 'close'.
        });
        resolve(new LocalVpnProcess(child, this.elevation));
      });
    });
  }
}
