/**
 * Log lines describing the openconnect discovery result, emitted only when the
 * result changes (discovery runs on startup, on every system.info() and before
 * every connect — the same facts must not flood the log).
 */
import type { SystemInfo } from '../../shared/ipc';
import type { LocateResult } from './locate';
import { majorVersion } from './version';

export interface DiscoveryLine {
  level: 'info' | 'warn';
  msg: string;
}

export function discoveryLines(found: LocateResult | null, version: string | undefined): DiscoveryLine[] {
  if (!found) return [{ level: 'warn', msg: 'openconnect not found' }];
  const lines: DiscoveryLine[] = [];
  if (!found.trusted) {
    lines.push({
      level: 'warn',
      msg: `${found.path} is not admin-owned (user-writable); it will not be run with administrator rights`,
    });
  }
  lines.push({ level: 'info', msg: `Using ${found.path} (${found.source}), version ${version ?? 'unknown'}` });
  const major = majorVersion(version);
  if (major !== undefined && major < 9) {
    lines.push({
      level: 'warn',
      msg: `openconnect ${version} is older than 9; GlobalProtect support may be incomplete`,
    });
  }
  return lines;
}

/** Returns a reporter that forwards lines only when they differ from the previous report. */
export function createDiscoveryReporter(
  log: (line: DiscoveryLine) => void,
): (found: LocateResult | null, version: string | undefined) => void {
  let last: string | null = null;
  return (found, version) => {
    const lines = discoveryLines(found, version);
    const key = JSON.stringify(lines);
    if (key === last) return;
    last = key;
    for (const l of lines) log(l);
  };
}

/** Cached outcome of openconnect discovery (path null = not found). */
export interface DiscoveryResult {
  path: string | null;
  version?: string;
  trusted?: boolean;
}

/** The openconnect part of `SystemInfo`. */
export function openconnectSystemInfo(
  r: DiscoveryResult,
): Pick<SystemInfo, 'openconnectFound' | 'openconnectVersion' | 'openconnectPath' | 'openconnectTrusted'> {
  if (r.path === null) return { openconnectFound: false };
  const out: ReturnType<typeof openconnectSystemInfo> = {
    openconnectFound: true,
    openconnectPath: r.path,
    openconnectTrusted: r.trusted === true,
  };
  if (r.version !== undefined) out.openconnectVersion = r.version;
  return out;
}
