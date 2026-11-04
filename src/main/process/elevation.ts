/** Pure decisions about how openconnect gets the privileges it needs to create a tun device. */

export type ElevationMethod = 'none' | 'pkexec' | 'osascript' | 'uac';

export interface ElevationContext {
  platform: NodeJS.Platform;
  /** Running as root (uid 0) on Unix. */
  isRoot: boolean;
}

/**
 * macOS always uses the system admin dialog: a passwordless `sudo` rule would let
 * any process of the user run openconnect (and its --script) as root.
 */
export function chooseElevation(ctx: ElevationContext): ElevationMethod {
  if (ctx.platform === 'win32') return 'uac';
  if (ctx.isRoot) return 'none';
  if (ctx.platform === 'darwin') return 'osascript';
  return 'pkexec';
}

export interface WrappedCommand {
  command: string;
  args: string[];
}

/** Command line for the methods that keep stdio attached (none / pkexec). */
export function wrapCommand(method: 'none' | 'pkexec', binary: string, args: string[]): WrappedCommand {
  if (method === 'none') return { command: binary, args };
  // No textual agent: we have no TTY, the desktop polkit agent shows the dialog.
  return { command: 'pkexec', args: ['--disable-internal-agent', binary, ...args] };
}

/** Command that sends `signal` to a root-owned `pid` through pkexec. */
export function privilegedKillCommand(pid: number, signal: 'INT' | 'TERM' | 'KILL'): WrappedCommand {
  if (!Number.isInteger(pid) || pid <= 1) throw new RangeError(`Invalid pid ${pid}`);
  return { command: 'pkexec', args: ['--disable-internal-agent', '/bin/kill', '-s', signal, String(pid)] };
}

/** POSIX shell single-quoting. */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Quoting for a Windows command line as parsed by the MSVC runtime (CommandLineToArgvW rules). */
export function quoteWindowsArg(arg: string): string {
  if (arg !== '' && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes++;
    } else if (ch === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
    } else {
      out += '\\'.repeat(backslashes) + ch;
      backslashes = 0;
    }
  }
  out += '\\'.repeat(backslashes * 2) + '"';
  return out;
}

/** Escapes a string for use inside an AppleScript double-quoted string literal. */
export function appleScriptString(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}
