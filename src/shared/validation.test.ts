import { describe, expect, it } from 'vitest';
import {
  ALLOWED_EXTRA_OPTIONS,
  checkExtraArg,
  checkExtraArgs,
  CONTROL_CHARS_RE,
  formatIpcError,
  isAbsolutePath,
  isOpenconnectBinaryPath,
  MAX_EXTRA_ARGS,
  normalizePortalUrl,
  parseIpcError,
} from './validation';

describe('normalizePortalUrl (shared)', () => {
  it.each([
    ['vpn.example.com', 'https://vpn.example.com'],
    [' https://VPN.example.com:8443/x ', 'https://vpn.example.com:8443'],
  ])('%s → ok', (input, url) => {
    expect(normalizePortalUrl(input)).toEqual({ ok: true, url });
  });

  it.each([
    ['', 'empty'],
    ['   ', 'empty'],
    ['a'.repeat(2049), 'too_long'],
    ['vpn example.com', 'invalid'],
    ['http://vpn.example.com', 'not_https'],
    ['ftp://x', 'not_https'],
    ['https://u:p@vpn.example.com', 'credentials'],
    ['https://', 'invalid'],
  ])('%j → %s', (input, code) => {
    expect(normalizePortalUrl(input)).toEqual({ ok: false, code });
  });
});

describe('checkExtraArgs (shared)', () => {
  const PIN = `pin-sha256:${'A'.repeat(43)}=`;

  it('accepts allowlisted args and trims them', () => {
    expect(checkExtraArgs([' -v ', `--servercert=${PIN}`, '--mtu=1400'])).toEqual({
      ok: true,
      args: ['-v', `--servercert=${PIN}`, '--mtu=1400'],
    });
  });

  it.each([
    ['--script=/tmp/x', 'not_allowed'],
    ['--passwd', 'not_allowed'],
    ['--no-dtls=1', 'not_name_value'],
    ['--mtu', 'not_name_value'],
    ['--mtu=99999', 'bad_value'],
    ['--servercert=sha1:00', 'bad_value'],
    ['', 'bad_value'],
    ['-v\u0007', 'bad_value'],
    [`--dtls-ciphers=${'A'.repeat(600)}`, 'too_long'],
  ])('%j → %s', (arg, code) => {
    const r = checkExtraArgs([arg]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe(code);
  });

  it('reports too_many and non-array input', () => {
    expect(checkExtraArgs(new Array(MAX_EXTRA_ARGS + 1).fill('-v'))).toMatchObject({ ok: false, code: 'too_many' });
    expect(checkExtraArgs('-v')).toMatchObject({ ok: false, code: 'bad_value' });
    expect(checkExtraArgs([1])).toMatchObject({ ok: false, code: 'bad_value' });
  });

  it('reports the offending argument', () => {
    expect(checkExtraArgs(['-v', '--proxy=x'])).toEqual({ ok: false, code: 'not_allowed', arg: '--proxy=x' });
    expect(checkExtraArg('--timestamp')).toEqual({ ok: true });
  });

  it('exposes the allowlist names', () => {
    expect(ALLOWED_EXTRA_OPTIONS).toContain('--no-dtls');
    expect(ALLOWED_EXTRA_OPTIONS).not.toContain('--script');
  });
});

describe('path helpers (shared)', () => {
  it.each([
    ['/usr/sbin/openconnect', true],
    ['C:\\Program Files\\OC\\openconnect.exe', true],
    ['c:/x', true],
    ['\\\\server\\share\\x', true],
    ['openconnect', false],
    ['C:relative', false],
    ['./x', false],
  ])('isAbsolutePath(%j) = %s', (p, ok) => {
    expect(isAbsolutePath(p)).toBe(ok);
  });

  it.each([
    ['/usr/sbin/openconnect', true],
    ['C:\\Program Files\\OC\\OpenConnect.EXE', true],
    ['/usr/bin/python3', false],
    ['/usr/bin/openconnect-wrapper', false],
    ['C:\\Windows\\System32\\cmd.exe', false],
  ])('isOpenconnectBinaryPath(%j) = %s', (p, ok) => {
    expect(isOpenconnectBinaryPath(p)).toBe(ok);
  });

  it('CONTROL_CHARS_RE matches control characters only', () => {
    expect(CONTROL_CHARS_RE.test('a\nb')).toBe(true);
    expect(CONTROL_CHARS_RE.test('Привет, world!')).toBe(false);
  });
});

describe('IPC error markers', () => {
  it('formats and parses field/code markers', () => {
    const msg = formatIpcError({ field: 'extraArgs', code: 'not_allowed', message: 'Option "--x" is not allowed.' });
    expect(msg).toBe('[field:extraArgs][code:not_allowed] Option "--x" is not allowed.');
    expect(parseIpcError(msg)).toEqual({
      field: 'extraArgs',
      code: 'not_allowed',
      message: 'Option "--x" is not allowed.',
    });
  });

  it('parses the form Electron delivers to the renderer', () => {
    const err = new Error(
      "Error invoking remote method 'gp:settings:set': Error: [code:not_confirmed] The change was not confirmed",
    );
    expect(parseIpcError(err)).toEqual({ code: 'not_confirmed', message: 'The change was not confirmed' });
  });

  it('passes through plain messages', () => {
    expect(parseIpcError('boom')).toEqual({ message: 'boom' });
    expect(formatIpcError({ message: 'boom' })).toBe('boom');
  });
});
