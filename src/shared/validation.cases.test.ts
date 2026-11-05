/**
 * Runs the shared validation vectors (fixtures/validation-cases.json) against
 * src/shared/validation.ts. The same file is checked by the Rust port
 * (crates/gp-core, `cargo test`), so both implementations must agree.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  checkExtraArg,
  checkExtraArgs,
  CONTROL_CHARS_RE,
  formatIpcError,
  isAbsolutePath,
  isOpenconnectBinaryPath,
  normalizePortalUrl,
  parseIpcError,
  type IpcErrorInfo,
} from './validation';

type Text = string | { repeat: string; times: number; prefix?: string; suffix?: string };
type ArgsInput = unknown;

interface Cases {
  portalUrl: ({ input: Text; ok: true; url: string } | { input: Text; ok: false; code: string })[];
  extraArg: { arg: Text; ok: boolean; code?: string }[];
  extraArgs: { args: ArgsInput; ok: boolean; result?: ArgsInput; code?: string; arg?: string }[];
  absolutePath: { path: string; absolute: boolean }[];
  openconnectBinaryPath: { path: string; ok: boolean }[];
  controlChars: { text: string; match: boolean }[];
  ipcError: {
    format: (IpcErrorInfo & { text: string })[];
    parse: { text: string; expected: IpcErrorInfo }[];
  };
}

const cases = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'validation-cases.json'), 'utf8'),
) as Cases;

function text(t: Text): string {
  return typeof t === 'string' ? t : `${t.prefix ?? ''}${t.repeat.repeat(t.times)}${t.suffix ?? ''}`;
}

function args(a: ArgsInput): unknown {
  if (a !== null && typeof a === 'object' && !Array.isArray(a) && 'repeatItem' in a) {
    const r = a as { repeatItem: string; times: number };
    return new Array<string>(r.times).fill(r.repeatItem);
  }
  return a;
}

describe('fixtures/validation-cases.json', () => {
  it.each(cases.portalUrl.map((c) => [JSON.stringify(c.input).slice(0, 80), c] as const))(
    'normalizePortalUrl(%s)',
    (_name, c) => {
      const expected = c.ok ? { ok: true, url: c.url } : { ok: false, code: c.code };
      expect(normalizePortalUrl(text(c.input))).toEqual(expected);
    },
  );

  it.each(cases.extraArg.map((c) => [JSON.stringify(c.arg).slice(0, 80), c] as const))(
    'checkExtraArg(%s)',
    (_name, c) => {
      const arg = text(c.arg);
      expect(checkExtraArg(arg)).toEqual(c.ok ? { ok: true } : { ok: false, code: c.code, arg });
    },
  );

  it.each(cases.extraArgs.map((c) => [JSON.stringify(c.args).slice(0, 80), c] as const))(
    'checkExtraArgs(%s)',
    (_name, c) => {
      const expected = c.ok ? { ok: true, args: args(c.result) } : { ok: false, code: c.code, arg: c.arg };
      expect(checkExtraArgs(args(c.args))).toEqual(expected);
    },
  );

  it.each(cases.absolutePath.map((c) => [c.path, c.absolute] as const))('isAbsolutePath(%j) = %s', (p, abs) => {
    expect(isAbsolutePath(p)).toBe(abs);
  });

  it.each(cases.openconnectBinaryPath.map((c) => [c.path, c.ok] as const))(
    'isOpenconnectBinaryPath(%j) = %s',
    (p, ok) => {
      expect(isOpenconnectBinaryPath(p)).toBe(ok);
    },
  );

  it.each(cases.controlChars.map((c) => [c.text, c.match] as const))('CONTROL_CHARS_RE(%j) = %s', (t, match) => {
    expect(CONTROL_CHARS_RE.test(t)).toBe(match);
  });

  it.each(cases.ipcError.format.map((c) => [c.text, c] as const))('formatIpcError → %j', (_t, c) => {
    const { text: expected, ...info } = c;
    expect(formatIpcError(info)).toBe(expected);
  });

  it.each(cases.ipcError.parse.map((c) => [c.text, c.expected] as const))('parseIpcError(%j)', (t, expected) => {
    expect(parseIpcError(t)).toEqual(expected);
  });

  it('has a runner for every vector group (cargo rejects unknown groups the same way)', () => {
    expect(Object.keys(cases).sort()).toEqual(
      [
        '$comment',
        'absolutePath',
        'controlChars',
        'extraArg',
        'extraArgs',
        'ipcError',
        'openconnectBinaryPath',
        'portalUrl',
      ].sort(),
    );
    expect(Object.keys(cases.ipcError).sort()).toEqual(['format', 'parse']);
  });

  it('is not vacuous', () => {
    expect(cases.portalUrl.length).toBeGreaterThan(40);
    expect(cases.extraArg.length).toBeGreaterThan(50);
  });
});
