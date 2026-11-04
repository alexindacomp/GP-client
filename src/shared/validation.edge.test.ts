/**
 * Edge cases of the shared portal-URL rule (used by the profile form for instant
 * feedback and by main as the authoritative check before anything is stored).
 */
import { describe, expect, it } from 'vitest';
import { checkExtraArg, isAbsolutePath, normalizePortalUrl, parseIpcError } from './validation';

describe('normalizePortalUrl: accepted inputs are reduced to https://host[:port]', () => {
  it.each([
    // IDN → punycode, so the host openconnect and prelogin see is unambiguous
    ['пример.рф', 'https://xn--e1afmkfd.xn--p1ai'],
    ['https://Пример.РФ/путь', 'https://xn--e1afmkfd.xn--p1ai'],
    ['xn--e1afmkfd.xn--p1ai', 'https://xn--e1afmkfd.xn--p1ai'],
    // IPv4 / IPv6 literals
    ['10.0.0.1', 'https://10.0.0.1'],
    ['[2001:db8::1]', 'https://[2001:db8::1]'],
    ['https://[2001:DB8::1]:8443/global-protect', 'https://[2001:db8::1]:8443'],
    // ports: default 443 dropped, custom kept
    ['https://vpn.example.com:443', 'https://vpn.example.com'],
    ['vpn.example.com:8443', 'https://vpn.example.com:8443'],
    // scheme/host case, trailing slash, path, query and fragment are stripped
    ['HTTPS://VPN.EXAMPLE.COM/', 'https://vpn.example.com'],
    ['Https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp#x', 'https://vpn.example.com'],
    ['vpn.example.com/', 'https://vpn.example.com'],
    ['\tvpn.example.com\n', 'https://vpn.example.com'],
    // URL-parser quirks resolve to the host the browser would contact
    ['https://vpn.example.com\\@evil.example.com', 'https://vpn.example.com'],
    ['https://vpn%2Eexample.com', 'https://vpn.example.com'],
    ['https://evil.example.com#@vpn.example.com', 'https://evil.example.com'],
  ])('%j → %s', (input, url) => {
    expect(normalizePortalUrl(input)).toEqual({ ok: true, url });
  });

  it.each([
    ['2001:db8::1', 'invalid'], // bare IPv6 needs brackets
    ['https://vpn.example.com:65536', 'invalid'],
    ['https://vpn.example.com:8443:1', 'invalid'],
    ['javascript:alert(1)', 'invalid'],
    ['https:vpn.example.com', 'invalid'],
    ['https://exa mple.com', 'invalid'],
    ['https://ex%00ample.com', 'invalid'],
    ['vpn.example.com\u0000', 'invalid'],
    ['HTTP://vpn.example.com', 'not_https'],
    ['wss://vpn.example.com', 'not_https'],
    ['file:///etc/passwd', 'not_https'],
    ['https://alice@vpn.example.com', 'credentials'],
    ['https://:pw@vpn.example.com', 'credentials'],
  ])('%j → %s', (input, code) => {
    expect(normalizePortalUrl(input)).toEqual({ ok: false, code });
  });

  it('is idempotent: a normalised URL normalises to itself', () => {
    for (const input of ['пример.рф', '[2001:db8::1]:8443', 'VPN.example.com:443/x']) {
      const first = normalizePortalUrl(input);
      if (!first.ok) throw new Error(`expected ${input} to be accepted`);
      expect(normalizePortalUrl(first.url)).toEqual(first);
    }
  });

  it('rejects non-string input instead of throwing (untrusted IPC payloads)', () => {
    expect(normalizePortalUrl(undefined as unknown as string)).toEqual({ ok: false, code: 'empty' });
    expect(normalizePortalUrl({ toString: () => 'vpn.example.com' } as unknown as string)).toEqual({
      ok: false,
      code: 'empty',
    });
  });

  it.each(['vpn.example.com:0', 'https://vpn.example.com:0/', 'https://vpn.example.com:00'])(
    'QA-4: rejects port 0 (%s)',
    (input) => {
      expect(normalizePortalUrl(input)).toEqual({ ok: false, code: 'invalid' });
    },
  );

  it('QA-4: other explicit ports are still accepted', () => {
    expect(normalizePortalUrl('vpn.example.com:1')).toEqual({ ok: true, url: 'https://vpn.example.com:1' });
    expect(normalizePortalUrl('vpn.example.com:443')).toEqual({ ok: true, url: 'https://vpn.example.com' });
  });
});

describe('other shared rules: edges', () => {
  it.each([
    ['--servercert=pin-sha256:xp3scfzy3rOgQEXnfPiYKrUk7D66a8b8O+gEXaMPleE=', true],
    ['--servercert=sha1:0123456789abcdef', false], // only pin-sha256 pins
    ['--mtu=575', false],
    ['--mtu=9000', true],
    ['--mtu=0x500', false],
    ['--verbose=1', false], // flag options take no value
    ['--verb', false], // no getopt prefix matching
    ['-vv', false], // no bundled short options
    ['--script=/tmp/x', false],
  ])('checkExtraArg(%j).ok === %s', (arg, ok) => {
    expect(checkExtraArg(arg).ok).toBe(ok);
  });

  it.each([
    ['C:\\Program Files\\OpenConnect\\openconnect.exe', true],
    ['c:/tools/openconnect.exe', true],
    ['\\\\server\\share\\openconnect.exe', true],
    ['/usr/sbin/openconnect', true],
    ['C:openconnect.exe', false], // drive-relative
    ['~/bin/openconnect', false],
    ['.\\openconnect.exe', false],
  ])('isAbsolutePath(%j) === %s', (p, abs) => {
    expect(isAbsolutePath(p)).toBe(abs);
  });

  it('parseIpcError keeps markers when Electron prefixes a custom error class name', () => {
    expect(
      parseIpcError(
        new Error("Error invoking remote method 'gp:settings:set': ValidationError: [field:theme][code:invalid] Bad"),
      ),
    ).toEqual({ field: 'theme', code: 'invalid', message: 'Bad' });
    expect(parseIpcError(42)).toEqual({ message: '42' });
  });
});
