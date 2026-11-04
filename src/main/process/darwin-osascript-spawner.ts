import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import { constants as fsConstants, openSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { appleScriptString, shQuote } from './elevation';
import { BaseVpnProcess, SpawnError, type ProcessSpawner, type SpawnRequest } from './types';

/**
 * Root-side wrapper. Root creates its own private directory (root-owned 0711, so
 * the user cannot plant symlinks in it), creates FIFOs for stdin/output/control
 * owned by the user, starts openconnect with stdio on those FIFOs, records pid
 * and exit status, and listens on the control FIFO for INT/TERM/KILL so that the
 * unprivileged app can stop the root process without another password prompt.
 * Prints the directory path and returns immediately.
 */
const WRAPPER_SCRIPT = [
  'UIDN="$1"; OC="$2"; shift 2',
  'umask 077',
  'D=$(/usr/bin/mktemp -d /private/tmp/gp-connect.XXXXXXXX) || exit 1',
  '/usr/bin/mkfifo -m 600 "$D/in" "$D/out" "$D/ctl" || exit 1',
  '/usr/sbin/chown "$UIDN" "$D/in" "$D/out" "$D/ctl" || exit 1',
  '/bin/chmod 711 "$D" || exit 1',
  '(',
  '  exec 3<>"$D/ctl" </dev/null >/dev/null 2>&1',
  '  "$OC" "$@" <"$D/in" >"$D/out" 2>&1 &',
  '  pid=$!',
  '  echo "$pid" >"$D/pid"; /bin/chmod 644 "$D/pid"',
  '  ( while read -r cmd <&3; do case "$cmd" in INT|TERM|KILL) kill -s "$cmd" "$pid" 2>/dev/null ;; esac; done ) &',
  '  watcher=$!',
  '  wait "$pid"; echo "$?" >"$D/status"; /bin/chmod 644 "$D/status"',
  '  kill "$watcher" 2>/dev/null',
  '  sleep 15; /bin/rm -rf "$D"',
  ') &',
  'echo "$D"',
].join('\n');

const DIR_RE = /^\/private\/tmp\/gp-connect\.[A-Za-z0-9]{8}$/;
const POLL_MS = 500;

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function openFifoSocket(file: string): net.Socket {
  // O_RDWR on a FIFO never blocks and never sees EOF, so nothing hangs if the
  // elevated side dies. A raw fd (not a FileHandle) is used because the socket
  // takes ownership of it. O_NOFOLLOW: never follow a symlink.
  const fd = openSync(file, fsConstants.O_RDWR | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW);
  return new net.Socket({ fd, readable: true, writable: true });
}

/** Builds the AppleScript that runs the wrapper with administrator privileges. */
export function buildOsascript(uid: number, req: SpawnRequest): string {
  const shellCmd = [
    '/bin/sh',
    '-c',
    shQuote(WRAPPER_SCRIPT),
    'gp-connect',
    ...[String(uid), req.binary, ...req.args].map(shQuote),
  ].join(' ');
  return (
    `do shell script ${appleScriptString(shellCmd)} ` +
    `with prompt ${appleScriptString(`GP Connect needs administrator rights to run ${req.binary} and create the VPN tunnel.`)} ` +
    'with administrator privileges'
  );
}

class OsascriptVpnProcess extends BaseVpnProcess {
  private poller: NodeJS.Timeout | null = null;

  constructor(
    readonly pid: number,
    private readonly dir: string,
    private readonly input: net.Socket,
    private readonly output: net.Socket,
  ) {
    super();
    output.setEncoding('utf8');
    output.on('data', (c: string) => this.emitOutput('stderr', c));
    output.on('error', () => undefined);
    input.on('error', () => undefined);
    this.poller = setInterval(() => void this.checkAlive(), POLL_MS);
  }

  write(data: string): void {
    if (!this.exited) this.input.write(data);
  }

  stop(): Promise<void> {
    return this.control('INT');
  }

  kill(): Promise<void> {
    return this.control('KILL');
  }

  private async control(cmd: 'INT' | 'KILL'): Promise<void> {
    if (this.exited) return;
    const fh = await fs.open(
      path.join(this.dir, 'ctl'),
      fsConstants.O_WRONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW,
    );
    try {
      await fh.write(`${cmd}\n`);
    } finally {
      await fh.close();
    }
  }

  private async checkAlive(): Promise<void> {
    try {
      process.kill(this.pid, 0);
      return; // alive and ours (unlikely for a root process)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM') return; // alive, owned by root
    }
    if (this.poller) clearInterval(this.poller);
    this.poller = null;
    let code: number | null = null;
    for (let i = 0; i < 4 && code === null; i++) {
      const raw = (await fs.readFile(path.join(this.dir, 'status'), 'utf8').catch(() => '')).trim();
      if (/^\d+$/.test(raw)) code = Number(raw);
      else await delay(250);
    }
    await delay(200); // let the last output arrive
    this.input.destroy();
    this.output.destroy();
    // The root-owned directory is removed by the wrapper itself.
    this.emitExit({ code, signal: null });
  }
}

/** macOS: elevation through the system administrator dialog. */
export class DarwinOsascriptSpawner implements ProcessSpawner {
  async spawn(req: SpawnRequest): Promise<OsascriptVpnProcess> {
    const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
    if (uid < 0) throw new SpawnError('UNKNOWN', 'Cannot determine the current user id');

    const dir = await new Promise<string>((resolve, reject) =>
      execFile(
        '/usr/bin/osascript',
        ['-e', buildOsascript(uid, req)],
        { timeout: 5 * 60_000 },
        (err, stdout, stderr) => {
          if (!err) return resolve(String(stdout).trim());
          const text = String(stderr);
          reject(
            new SpawnError(
              /-128|cancel/i.test(text) ? 'PRIVILEGES_DENIED' : 'UNKNOWN',
              `Administrator authorization failed: ${text.trim() || err.message}`,
            ),
          );
        },
      ),
    );
    if (!DIR_RE.test(dir)) throw new SpawnError('UNKNOWN', 'Elevated helper returned an unexpected result');

    const st = await fs.lstat(dir);
    if (!st.isDirectory() || st.uid !== 0 || (st.mode & 0o022) !== 0) {
      throw new SpawnError('UNKNOWN', 'Elevated helper directory has unexpected ownership');
    }

    let input: net.Socket | undefined;
    let output: net.Socket | undefined;
    try {
      input = openFifoSocket(path.join(dir, 'in'));
      output = openFifoSocket(path.join(dir, 'out'));
      let pid: number | undefined;
      for (let i = 0; i < 40 && pid === undefined; i++) {
        const raw = await fs.readFile(path.join(dir, 'pid'), 'utf8').catch(() => '');
        if (/^\d+\s*$/.test(raw)) pid = Number(raw.trim());
        else await delay(250);
      }
      if (pid === undefined) throw new SpawnError('UNKNOWN', 'Elevated openconnect did not start');
      return new OsascriptVpnProcess(pid, dir, input, output);
    } catch (err) {
      input?.destroy();
      output?.destroy();
      if (err instanceof SpawnError) throw err;
      throw new SpawnError('UNKNOWN', `Failed to attach to elevated openconnect: ${(err as Error).message}`, {
        cause: err,
      });
    }
  }
}
