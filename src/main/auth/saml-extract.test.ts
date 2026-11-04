import { describe, expect, it } from 'vitest';
import { fixture } from '../__fixtures__';
import { parsePrelogin } from './prelogin';
import {
  buildSamlLoadTarget,
  extractSamlFromHeaders,
  extractSamlFromHtml,
  isTrustedSamlSource,
  isValidSamlCookie,
  isValidSamlUsername,
} from './saml-extract';

describe('extractSamlFromHtml', () => {
  it('extracts username and prelogin-cookie from the HTML comment', () => {
    expect(extractSamlFromHtml(fixture('saml-success.html'))).toEqual({
      status: 'success',
      username: 'j.doe@example.com',
      cookieName: 'prelogin-cookie',
      cookie: 'PRELOGIN-COOKIE-abc123XYZ',
    });
  });

  it('falls back to portal-userauthcookie when prelogin-cookie is empty', () => {
    const html =
      '<!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>empty</prelogin-cookie>' +
      '<portal-userauthcookie>UAC-777</portal-userauthcookie><saml-username>bob</saml-username> -->';
    expect(extractSamlFromHtml(html)).toMatchObject({
      cookieName: 'portal-userauthcookie',
      cookie: 'UAC-777',
      username: 'bob',
    });
  });

  it('reports failure status with the portal message', () => {
    expect(extractSamlFromHtml(fixture('saml-failure.html'))).toEqual({
      status: 'failure',
      message: 'User is not authorized',
    });
  });

  it('reports failure when the success page lacks the cookie', () => {
    const r = extractSamlFromHtml('<!-- <saml-auth-status>1</saml-auth-status><saml-username>x</saml-username> -->');
    expect(r?.status).toBe('failure');
  });

  it('returns null for unrelated pages (IdP login form)', () => {
    expect(extractSamlFromHtml('<html><form><input name="password"></form></html>')).toBeNull();
  });
});

describe('extractSamlFromHeaders', () => {
  it('extracts values from response headers regardless of case and array form', () => {
    expect(
      extractSamlFromHeaders({
        'Saml-Auth-Status': ['1'],
        'saml-username': ['alice@example.com'],
        'Prelogin-Cookie': ['PC-1'],
        'Content-Type': ['text/html'],
      }),
    ).toEqual({ status: 'success', username: 'alice@example.com', cookieName: 'prelogin-cookie', cookie: 'PC-1' });
  });

  it('prefers prelogin-cookie over portal-userauthcookie', () => {
    const r = extractSamlFromHeaders({
      'saml-auth-status': '1',
      'saml-username': 'a',
      'prelogin-cookie': 'PC',
      'portal-userauthcookie': 'UAC',
    });
    expect(r).toMatchObject({ cookieName: 'prelogin-cookie', cookie: 'PC' });
  });

  it('accepts a cookie without explicit status', () => {
    expect(extractSamlFromHeaders({ 'saml-username': 'a', 'portal-userauthcookie': 'UAC' })).toMatchObject({
      status: 'success',
      cookieName: 'portal-userauthcookie',
    });
  });

  it('reports failure on status -1', () => {
    expect(extractSamlFromHeaders({ 'saml-auth-status': '-1' })).toMatchObject({ status: 'failure' });
  });

  it('ignores ordinary responses', () => {
    expect(extractSamlFromHeaders({ 'content-type': ['text/html'], 'set-cookie': ['a=b'] })).toBeNull();
  });
});

describe('buildSamlLoadTarget', () => {
  it('returns the decoded https URL for REDIRECT', () => {
    const t = buildSamlLoadTarget(parsePrelogin(fixture('prelogin-saml-redirect.xml')));
    expect(t.kind).toBe('url');
    expect(t.kind === 'url' && t.url).toMatch(/^https:\/\/idp\.example\.com\/app\/sso\/saml\?SAMLRequest=/);
  });

  it('returns a data: URL with the auto-submitting form for POST', () => {
    const t = buildSamlLoadTarget(parsePrelogin(fixture('prelogin-saml-post.xml')));
    expect(t.kind).toBe('html');
    if (t.kind !== 'html') return;
    expect(t.dataUrl.startsWith('data:text/html;charset=utf-8;base64,')).toBe(true);
    const html = Buffer.from(t.dataUrl.split(',')[1]!, 'base64').toString();
    expect(html).toContain('action="https://idp.example.com/sso"');
  });

  it('rejects a non-https redirect target', () => {
    const b64 = Buffer.from('http://idp.example.com/sso').toString('base64');
    expect(() => buildSamlLoadTarget({ authType: 'saml', samlMethod: 'REDIRECT', samlRequest: b64 })).toThrow(/https/);
  });

  it('rejects a password prelogin', () => {
    expect(() => buildSamlLoadTarget({ authType: 'password' })).toThrow();
  });
});

describe('SAML value validation', () => {
  it('rejects cookies with spaces/control characters or excessive length', () => {
    expect(isValidSamlCookie('abc-DEF_123+/=')).toBe(true);
    expect(isValidSamlCookie('abc def')).toBe(false);
    expect(isValidSamlCookie('abc\nINJECTED')).toBe(false);
    expect(isValidSamlCookie('x'.repeat(4097))).toBe(false);
    expect(isValidSamlCookie('')).toBe(false);
  });

  it('rejects usernames with control characters or excessive length', () => {
    expect(isValidSamlUsername('j.doe@example.com')).toBe(true);
    expect(isValidSamlUsername('Иван Петров')).toBe(true);
    expect(isValidSamlUsername('bob\n--script=/tmp/x')).toBe(false);
    expect(isValidSamlUsername('a'.repeat(257))).toBe(false);
  });

  it('turns an invalid cookie or username in a response into a failure', () => {
    expect(
      extractSamlFromHeaders({ 'saml-auth-status': '1', 'saml-username': 'bob', 'prelogin-cookie': 'a b' }),
    ).toMatchObject({ status: 'failure', message: expect.stringContaining('invalid cookie') });
    expect(
      extractSamlFromHeaders({ 'saml-auth-status': '1', 'saml-username': 'bo\u0007b', 'prelogin-cookie': 'ok' }),
    ).toMatchObject({ status: 'failure', message: expect.stringContaining('invalid username') });
  });
});

describe('isTrustedSamlSource', () => {
  const hosts = ['vpn.example.com'];

  it('accepts a top-level https document from the portal host', () => {
    expect(isTrustedSamlSource('https://vpn.example.com/SAML20/SP/ACS', 'mainFrame', hosts)).toBe(true);
    expect(isTrustedSamlSource('https://VPN.example.com/x', 'mainFrame', hosts)).toBe(true);
  });

  it.each([
    ['https://vpn.example.com/x', 'subFrame'],
    ['https://vpn.example.com/x', 'xhr'],
    ['https://vpn.example.com/x', 'script'],
    ['http://vpn.example.com/x', 'mainFrame'],
    ['https://idp.example.com/sso', 'mainFrame'],
    ['https://vpn.example.com.evil.net/x', 'mainFrame'],
    ['https://vpn.example.com:8443/x', 'mainFrame'],
    ['data:text/html,<saml-auth-status>1</saml-auth-status>', 'mainFrame'],
    ['not a url', 'mainFrame'],
  ])('rejects %s (%s)', (url, type) => {
    expect(isTrustedSamlSource(url, type, hosts)).toBe(false);
  });

  it('honours an explicit port in the allowed host', () => {
    expect(isTrustedSamlSource('https://vpn.example.com:8443/x', 'mainFrame', ['vpn.example.com:8443'])).toBe(true);
  });
});
