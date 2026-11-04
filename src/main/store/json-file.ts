import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Reads JSON; returns `undefined` when the file does not exist. Throws on corrupt JSON. */
export function readJsonFile(file: string): unknown {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
  return JSON.parse(raw) as unknown;
}

/** Atomic, durable write: exclusive random temp file (0600) + fsync + rename. */
export function writeJsonFile(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${randomBytes(8).toString('hex')}.tmp`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, JSON.stringify(data, null, 2) + '\n', null, 'utf8');
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/** Moves an unreadable file aside so the app can start with defaults. */
export function quarantineFile(file: string): string | undefined {
  const target = `${file}.corrupt-${Date.now()}`;
  try {
    fs.renameSync(file, target);
    return target;
  } catch {
    return undefined;
  }
}
