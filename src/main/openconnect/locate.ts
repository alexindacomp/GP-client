import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

export type OpenconnectSource = 'settings' | 'bundled' | 'path' | 'well-known';

export interface LocatedBinary {
  path: string;
  source: OpenconnectSource;
}

export interface LocateOptions {
  platform: NodeJS.Platform;
  /** User-configured path from settings (highest priority). */
  configuredPath?: string;
  /** Directory with bundled binaries: `<resources>/bin` — `<platform>/openconnect[.exe]` is looked up inside. */
  bundledBinDir?: string;
  /** Value of the PATH environment variable. */
  envPath?: string;
  /** Overridable for tests. */
  isExecutable?: (p: string) => Promise<boolean>;
  /**
   * Whether a candidate may be run with administrator rights (see trust.ts).
   * Trusted candidates win over untrusted ones regardless of order, so a binary
   * planted in a user-writable PATH directory cannot shadow the system one.
   */
  isTrusted?: (p: string) => Promise<boolean>;
}

export function executableName(platform: NodeJS.Platform): string {
  return platform === 'win32' ? 'openconnect.exe' : 'openconnect';
}

/**
 * Directories where package managers install openconnect but that are often
 * missing from PATH of GUI apps (Finder/Dock launches get a minimal PATH; Ubuntu
 * installs to /usr/sbin, which is not in a regular user's PATH).
 */
export function wellKnownDirs(platform: NodeJS.Platform): string[] {
  switch (platform) {
    case 'win32':
      return [
        'C:\\Program Files\\OpenConnect',
        'C:\\Program Files\\OpenConnect-GUI',
        'C:\\Program Files (x86)\\OpenConnect',
        'C:\\Program Files (x86)\\OpenConnect-GUI',
      ];
    case 'darwin':
      return ['/opt/homebrew/bin', '/usr/local/bin', '/opt/local/bin', '/opt/local/sbin'];
    default:
      return ['/usr/sbin', '/usr/bin', '/usr/local/sbin', '/usr/local/bin', '/sbin', '/bin'];
  }
}

export async function defaultIsExecutable(p: string): Promise<boolean> {
  try {
    const st = await fs.stat(p);
    if (!st.isFile()) return false;
    if (process.platform !== 'win32') await fs.access(p, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Ordered candidate list: settings → bundled → PATH → well-known install dirs. */
export function candidatePaths(opts: LocateOptions): LocatedBinary[] {
  const exe = executableName(opts.platform);
  const p = opts.platform === 'win32' ? path.win32 : path.posix;
  const out: LocatedBinary[] = [];
  const seen = new Set<string>();
  const add = (candidate: string, source: OpenconnectSource): void => {
    const key = opts.platform === 'win32' ? candidate.toLowerCase() : candidate;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ path: candidate, source });
  };

  if (opts.configuredPath && p.isAbsolute(opts.configuredPath)) add(opts.configuredPath, 'settings');
  if (opts.bundledBinDir) add(p.join(opts.bundledBinDir, opts.platform, exe), 'bundled');
  const sep = opts.platform === 'win32' ? ';' : ':';
  for (const dir of (opts.envPath ?? '').split(sep)) {
    const d = dir.trim().replace(/^"(.*)"$/, '$1');
    if (d && p.isAbsolute(d)) add(p.join(d, exe), 'path');
  }
  for (const dir of wellKnownDirs(opts.platform)) add(p.join(dir, exe), 'well-known');
  return out;
}

export interface LocateResult extends LocatedBinary {
  /** False when the binary is not admin-controlled; connecting will be refused. */
  trusted: boolean;
}

/**
 * First executable candidate that passes the trust check; if none does, the
 * first executable one (reported as untrusted so the UI can explain why
 * connecting is refused).
 */
export async function locateOpenconnect(opts: LocateOptions): Promise<LocateResult | null> {
  const isExecutable = opts.isExecutable ?? defaultIsExecutable;
  const isTrusted = opts.isTrusted ?? (async () => true);
  let firstUntrusted: LocatedBinary | null = null;
  for (const candidate of candidatePaths(opts)) {
    if (!(await isExecutable(candidate.path))) continue;
    if (await isTrusted(candidate.path)) return { ...candidate, trusted: true };
    firstUntrusted ??= candidate;
  }
  return firstUntrusted ? { ...firstUntrusted, trusted: false } : null;
}
