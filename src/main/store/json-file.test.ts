import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readJsonFile, writeJsonFile } from './json-file';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-json-test-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('writeJsonFile', () => {
  it('writes atomically and leaves no temp files', () => {
    const file = path.join(dir, 'sub', 'settings.json');
    writeJsonFile(file, { a: 1 });
    writeJsonFile(file, { a: 2 });
    expect(readJsonFile(file)).toEqual({ a: 2 });
    expect(fs.readdirSync(path.dirname(file))).toEqual(['settings.json']);
  });

  // POSIX permission bits do not exist on Windows (ACLs; Node reports 0o666/0o777).
  it.skipIf(process.platform === 'win32')('creates the file 0600 and its directory 0700 (POSIX only)', () => {
    const file = path.join(dir, 'sub', 'settings.json');
    writeJsonFile(file, { a: 1 });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
  });

  it('returns undefined for a missing file', () => {
    expect(readJsonFile(path.join(dir, 'missing.json'))).toBeUndefined();
  });
});
