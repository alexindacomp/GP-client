import { describe, expect, it, vi } from 'vitest';
import { fixture } from '../__fixtures__';
import {
  buildPreloginUrl,
  fetchPrelogin,
  MAX_PRELOGIN_BODY_BYTES,
  normalizePortalUrl,
  parsePrelogin,
  PreloginError,
  type FetchFn,
} from './prelogin';

describe('parsePrelogin', () => {
  it('detects SAML REDIRECT and keeps the base64 request', () => {
    const r = parsePrelogin(fixture('prelogin-saml-redirect.xml'));
    expect(r.authType).toBe('saml');
    expect(r.samlMethod).toBe('REDIRECT');
    expect(Buffer.from(r.samlRequest!, 'base64').toString()).toMatch(/^https:\/\/idp\.example\.com\/app\/sso\/saml\?/);
    expect(r.authMessage).toBe('Enter login credentials');
    expect(r.usernameLabel).toBe('Username');
    expect(r.passwordLabel).toBe('Password');
    expect(r.region).toBe('DE');
  });

  it('detects SAML POST and strips whitespace inside the request', () => {
    const r = parsePrelogin(fixture('prelogin-saml-post.xml'));
    expect(r.authType).toBe('saml');
    expect(r.samlMethod).toBe('POST');
    expect(r.samlRequest).not.toMatch(/\s/);
    expect(Buffer.from(r.samlRequest!, 'base64').toString()).toContain('<form method="POST"');
  });

  it('falls back to password auth and decodes entities, CDATA and unicode labels', () => {
    const r = parsePrelogin(fixture('prelogin-password.xml'));
    expect(r.authType).toBe('password');
    expect(r.samlRequest).toBeUndefined();
    expect(r.authMessage).toBe('Enter login credentials & OTP');
    expect(r.usernameLabel).toBe('Корп. логин');
    expect(r.passwordLabel).toBe('Password + <token>');
  });

  it('accepts the short <auth-message> tag name', () => {
    const r = parsePrelogin(
      '<prelogin-response><status>Success</status><auth-message>Hi</auth-message></prelogin-response>',
    );
    expect(r.authMessage).toBe('Hi');
  });

  it('throws AUTH_FAILED with the portal message on error status', () => {
    expect(() => parsePrelogin(fixture('prelogin-error.xml'))).toThrowError(/Valid client certificate is required/);
    try {
      parsePrelogin(fixture('prelogin-error.xml'));
    } catch (e) {
      expect(e).toBeInstanceOf(PreloginError);
      expect((e as PreloginError).code).toBe('AUTH_FAILED');
    }
  });

  it('rejects non-GlobalProtect responses', () => {
    expect(() => parsePrelogin('<html>Login</html>')).toThrowError(PreloginError);
  });

  it('rejects an unknown SAML method', () => {
    const xml =
      '<prelogin-response><status>Success</status><saml-auth-method>ARTIFACT</saml-auth-method><saml-request>aGk=</saml-request></prelogin-response>';
    expect(() => parsePrelogin(xml)).toThrowError(/Unsupported SAML auth method/);
  });
});

describe('normalizePortalUrl', () => {
  it.each([
    ['vpn.example.com', 'https://vpn.example.com'],
    ['https://vpn.example.com/', 'https://vpn.example.com'],
    ['  https://VPN.example.com:8443/global-protect  ', 'https://vpn.example.com:8443'],
  ])('%s → %s', (input, expected) => {
    expect(normalizePortalUrl(input)).toBe(expected);
  });

  it.each(['http://vpn.example.com', 'ftp://x', 'https://user:pw@vpn.example.com', '', 'vpn example.com'])(
    'rejects %j',
    (input) => {
      expect(() => normalizePortalUrl(input)).toThrow();
    },
  );
});

describe('buildPreloginUrl', () => {
  it.each([
    ['win32', 'Windows'],
    ['darwin', 'Mac'],
    ['linux', 'Linux'],
  ] as const)('uses clientos for %s', (platform, os) => {
    expect(buildPreloginUrl('vpn.example.com', platform)).toBe(
      `https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=${os}`,
    );
  });
});

describe('fetchPrelogin', () => {
  it('POSTs to the prelogin endpoint and parses the body', async () => {
    const fetch = vi.fn<FetchFn>(async () => new Response(fixture('prelogin-saml-redirect.xml'), { status: 200 }));
    const r = await fetchPrelogin('https://vpn.example.com', { fetch, platform: 'linux' });
    expect(r.authType).toBe('saml');
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe('https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux');
    expect(init?.method).toBe('POST');
  });

  it('maps HTTP errors to PORTAL_UNREACHABLE', async () => {
    const fetch: FetchFn = async () => new Response('nope', { status: 404 });
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toMatchObject({
      code: 'PORTAL_UNREACHABLE',
    });
  });

  it('maps connection failures to PORTAL_UNREACHABLE', async () => {
    const fetch: FetchFn = async () => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      });
    };
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toMatchObject({
      code: 'PORTAL_UNREACHABLE',
    });
  });

  it('maps certificate failures to TLS_ERROR', async () => {
    const fetch: FetchFn = async () => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('certificate has expired'), { code: 'CERT_HAS_EXPIRED' }),
      });
    };
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toMatchObject({
      code: 'TLS_ERROR',
    });
  });

  it('does not wrap a caller abort', async () => {
    const ctrl = new AbortController();
    const fetch: FetchFn = async () => {
      ctrl.abort();
      throw new DOMException('aborted', 'AbortError');
    };
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux', signal: ctrl.signal })).rejects.toThrow(
      'aborted',
    );
  });
});

describe('fetchPrelogin redirects and size limits', () => {
  const ok = (): Response => new Response(fixture('prelogin-password.xml'), { status: 200 });
  const redirect = (location: string, status = 302): Response => new Response(null, { status, headers: { location } });

  it('never lets fetch follow redirects by itself', async () => {
    const fetch = vi.fn<FetchFn>(async () => ok());
    await fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' });
    expect(fetch.mock.calls[0]![1]?.redirect).toBe('manual');
  });

  it('follows a same-host https redirect', async () => {
    const fetch = vi
      .fn<FetchFn>()
      .mockResolvedValueOnce(redirect('/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux&x=1', 307))
      .mockResolvedValueOnce(ok());
    const r = await fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' });
    expect(r.authType).toBe('password');
    expect(fetch.mock.calls[1]![0]).toBe(
      'https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux&x=1',
    );
  });

  it.each([
    'https://evil.example.net/global-protect/prelogin.esp',
    'http://vpn.example.com/global-protect/prelogin.esp',
    'https://vpn.example.com:8443/global-protect/prelogin.esp',
  ])('rejects a redirect to %s', async (location) => {
    const fetch = vi.fn<FetchFn>().mockResolvedValueOnce(redirect(location)).mockResolvedValue(ok());
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toMatchObject({
      code: 'PORTAL_UNREACHABLE',
      message: expect.stringContaining('only redirects within https://vpn.example.com'),
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('stops after 3 redirects', async () => {
    const fetch = vi.fn<FetchFn>(async () => redirect('/loop'));
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toThrow(/Too many redirects/);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('rejects a redirect without Location', async () => {
    const fetch: FetchFn = async () => new Response(null, { status: 302 });
    await expect(fetchPrelogin('vpn.example.com', { fetch, platform: 'linux' })).rejects.toThrow(/without Location/);
  });

  it('rejects bodies larger than 1 MiB (declared or streamed)', async () => {
    const big = 'x'.repeat(MAX_PRELOGIN_BODY_BYTES + 1);
    const declared: FetchFn = async () =>
      new Response('small', { status: 200, headers: { 'content-length': String(MAX_PRELOGIN_BODY_BYTES + 1) } });
    await expect(fetchPrelogin('vpn.example.com', { fetch: declared, platform: 'linux' })).rejects.toThrow(/too large/);
    const streamed: FetchFn = async () => new Response(big, { status: 200 });
    await expect(fetchPrelogin('vpn.example.com', { fetch: streamed, platform: 'linux' })).rejects.toThrow(/too large/);
  });
});
