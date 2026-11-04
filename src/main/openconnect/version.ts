import { execFile } from 'node:child_process';

/** Extracts the version from `openconnect --version` output, e.g. "9.12" or "9.01-3". */
export function parseOpenconnectVersion(output: string): string | undefined {
  const m = /OpenConnect version v?([0-9]+\.[0-9]+[^\s]*)/i.exec(output);
  return m?.[1];
}

/** Major version or `undefined` when unknown. */
export function majorVersion(version: string | undefined): number | undefined {
  const m = version ? /^(\d+)\./.exec(version) : null;
  return m ? Number(m[1]) : undefined;
}

export function readOpenconnectVersion(binary: string, timeoutMs = 5000): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile(
      binary,
      ['--version'],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 256 * 1024 },
      (_err, stdout, stderr) => {
        // openconnect --version exits 0 on success; on failure we still try to parse.
        resolve(parseOpenconnectVersion(`${String(stdout)}\n${String(stderr)}`));
      },
    );
  });
}
