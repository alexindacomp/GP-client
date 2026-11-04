/**
 * Checks that a file which will be executed with administrator/root rights
 * (the openconnect binary, the HIP `--csd-wrapper` script) cannot be replaced by
 * an unprivileged process. Otherwise any program running as the user could plant
 * a binary and get it elevated by the next VPN connection.
 *
 * Unix: the real path (symlinks resolved) and every parent directory must be
 * owned by root and not writable by group/others.
 * Windows: the real path must be inside a Program Files directory registered in
 * HKLM (never taken from environment variables; %SystemRoot% is NOT accepted,
 * it contains user-writable folders such as C:\Windows\Temp), and the owner and
 * ACL of the file and every parent up to that root must grant write access only
 * to SYSTEM, Administrators or TrustedInstaller (see windows-acl.ts).
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { VpnError } from '../vpn/errors';
import { aclProblem, pathsUpTo, powershellProbe, type WindowsSecurityProbe } from './windows-acl';

export interface TrustStat {
  uid: number;
  mode: number;
  isFile(): boolean;
  isDirectory(): boolean;
}

export interface TrustFs {
  realpath(p: string): Promise<string>;
  stat(p: string): Promise<TrustStat>;
}

export interface TrustOptions {
  platform: NodeJS.Platform;
  fs?: TrustFs;
  /** Windows: registry/ACL probe (injected in tests). */
  windowsProbe?: WindowsSecurityProbe;
}

export class UntrustedPathError extends VpnError {
  constructor(
    readonly filePath: string,
    reason: string,
  ) {
    super(
      'PRIVILEGES_DENIED',
      `Refusing to run "${filePath}" with administrator rights: ${reason}. ` +
        (filePath.includes('/opt/homebrew') || filePath.startsWith('/usr/local/')
          ? 'Homebrew installs are user-writable; install OpenConnect with MacPorts (sudo port install openconnect)'
          : 'install it to a location only administrators can modify'),
    );
    this.name = 'UntrustedPathError';
    this.hint =
      filePath.includes('/opt/homebrew') || filePath.startsWith('/usr/local/')
        ? 'untrusted_homebrew'
        : 'untrusted_binary';
  }
}

const nodeFs: TrustFs = {
  realpath: (p) => fs.realpath(p),
  stat: (p) => fs.stat(p),
};

const GROUP_OR_WORLD_WRITABLE = 0o022;

async function verifyUnix(file: string, tfs: TrustFs): Promise<string> {
  let real: string;
  try {
    real = await tfs.realpath(file);
  } catch {
    throw new UntrustedPathError(file, 'file does not exist');
  }
  const st = await tfs.stat(real);
  if (!st.isFile()) throw new UntrustedPathError(file, 'not a regular file');
  const check = (p: string, s: TrustStat): void => {
    if (s.uid !== 0) throw new UntrustedPathError(file, `${p} is not owned by root`);
    if ((s.mode & GROUP_OR_WORLD_WRITABLE) !== 0) {
      throw new UntrustedPathError(file, `${p} is writable by group or others`);
    }
  };
  check(real, st);
  let dir = path.posix.dirname(real);
  for (;;) {
    const ds = await tfs.stat(dir);
    if (!ds.isDirectory()) throw new UntrustedPathError(file, `${dir} is not a directory`);
    check(dir, ds);
    const parent = path.posix.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return real;
}

function normalizeRoot(r: string): string {
  return path.win32.normalize(r).replace(/[\\/]+$/, '');
}

/**
 * Windows: the real path must be inside a Program Files directory registered in
 * HKLM (never taken from the environment; %SystemRoot% is not accepted because
 * it contains user-writable folders such as C:\Windows\Temp), and neither the
 * file nor any parent up to that root may be owned or writable by a non-admin
 * principal.
 */
async function verifyWindows(file: string, tfs: TrustFs, probe: WindowsSecurityProbe): Promise<string> {
  if (!path.win32.isAbsolute(file) || file.startsWith('\\\\') || file.startsWith('//')) {
    throw new UntrustedPathError(file, 'path must be a local absolute path');
  }
  let real: string;
  try {
    real = path.win32.normalize(await tfs.realpath(file));
  } catch {
    throw new UntrustedPathError(file, 'file does not exist');
  }
  if (real.startsWith('\\\\')) throw new UntrustedPathError(file, 'network paths are not allowed');
  const st = await tfs.stat(real);
  if (!st.isFile()) throw new UntrustedPathError(file, 'not a regular file');

  // First call: registered Program Files roots (+ ACL of the file itself).
  const first = await probe([real]);
  const lower = real.toLowerCase();
  const root = first.programFiles
    .filter((r) => path.win32.isAbsolute(r))
    .map(normalizeRoot)
    .find((r) => lower.startsWith(`${r.toLowerCase()}\\`));
  if (!root) {
    throw new UntrustedPathError(file, 'it must be installed under "Program Files" (admin-only folder)');
  }
  const chain = pathsUpTo(real, root);
  const { items } = await probe(chain);
  if (items.length !== chain.length) throw new UntrustedPathError(file, 'could not read permissions');
  for (const item of items) {
    const problem = aclProblem(item);
    if (problem) throw new UntrustedPathError(file, problem);
  }
  return real;
}

/**
 * Resolves `file` to its real path and verifies it is admin-controlled.
 * Throws {@link UntrustedPathError} (code PRIVILEGES_DENIED) otherwise.
 */
export function verifyTrustedFile(file: string, opts: TrustOptions): Promise<string> {
  const tfs = opts.fs ?? nodeFs;
  const run = async (): Promise<string> => {
    if (opts.platform === 'win32') return verifyWindows(file, tfs, opts.windowsProbe ?? powershellProbe);
    if (!path.posix.isAbsolute(file)) throw new UntrustedPathError(file, 'path must be absolute');
    return verifyUnix(file, tfs);
  };
  return run().catch((err: unknown) => {
    if (err instanceof UntrustedPathError) throw err;
    throw new UntrustedPathError(file, err instanceof Error ? err.message : String(err));
  });
}

/** `true` when {@link verifyTrustedFile} would accept the file. */
export async function isTrustedFile(file: string, opts: TrustOptions): Promise<boolean> {
  try {
    await verifyTrustedFile(file, opts);
    return true;
  } catch {
    return false;
  }
}

/**
 * Memoised {@link isTrustedFile} for discovery/UI (`system.info()` is called
 * often and on Windows each check starts PowerShell). Keyed by path + mtime with
 * a short TTL. Never use it for the check right before elevation.
 */
export function createTrustCache(
  opts: TrustOptions,
  ttlMs = 30_000,
  now: () => number = Date.now,
  mtimeOf: (p: string) => Promise<number> = async (p) => (await fs.stat(p)).mtimeMs,
): (file: string) => Promise<boolean> {
  const cache = new Map<string, { ok: boolean; at: number }>();
  return async (file) => {
    let mtime: number;
    try {
      mtime = await mtimeOf(file);
    } catch {
      return false;
    }
    const key = `${file}\0${mtime}`;
    const hit = cache.get(key);
    if (hit && now() - hit.at < ttlMs) return hit.ok;
    const ok = await isTrustedFile(file, opts);
    cache.set(key, { ok, at: now() });
    if (cache.size > 64) cache.delete(cache.keys().next().value!);
    return ok;
  };
}
