/**
 * Pure (Electron-free) SAML helpers: building what the SAML window must load and
 * extracting the GlobalProtect auth result from response headers or HTML.
 */
import { getTagText } from './xml';
import type { PreloginResult } from './prelogin';

export type SamlCookieName = 'prelogin-cookie' | 'portal-userauthcookie';

export interface SamlSuccess {
  status: 'success';
  username: string;
  cookieName: SamlCookieName;
  cookie: string;
}

export interface SamlFailure {
  status: 'failure';
  message: string;
}

export type SamlOutcome = SamlSuccess | SamlFailure;

export type SamlLoadTarget = { kind: 'url'; url: string } | { kind: 'html'; dataUrl: string };

function decodeBase64(b64: string): string {
  const normalized = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error('SAML request is not valid base64');
  return Buffer.from(normalized, 'base64').toString('utf8');
}

/** What the SAML window should load for the given prelogin result. */
export function buildSamlLoadTarget(prelogin: PreloginResult): SamlLoadTarget {
  if (prelogin.authType !== 'saml' || !prelogin.samlRequest || !prelogin.samlMethod) {
    throw new Error('Prelogin result does not contain a SAML request');
  }
  const decoded = decodeBase64(prelogin.samlRequest).trim();
  if (decoded === '') throw new Error('SAML request is empty');

  if (prelogin.samlMethod === 'REDIRECT') {
    let url: URL;
    try {
      url = new URL(decoded);
    } catch {
      throw new Error('SAML redirect URL is invalid');
    }
    if (url.protocol !== 'https:') throw new Error('SAML redirect URL must use https');
    return { kind: 'url', url: url.toString() };
  }
  return {
    kind: 'html',
    dataUrl: `data:text/html;charset=utf-8;base64,${Buffer.from(decoded, 'utf8').toString('base64')}`,
  };
}

/** Header map as delivered by Electron's `webRequest` (values may be arrays, keys any case). */
export type HeaderMap = Record<string, string | string[] | undefined>;

function lowerCaseHeaders(headers: HeaderMap): Map<string, string> {
  const map = new Map<string, string>();
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    const value = Array.isArray(v) ? v[0] : v;
    if (value !== undefined) map.set(k.toLowerCase(), value.trim());
  }
  return map;
}

function usableCookie(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const t = v.trim();
  return t === '' || t.toLowerCase() === 'empty' ? undefined : t;
}

const COOKIE_RE = /^[\x21-\x7e]{1,4096}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;

export function isValidSamlCookie(v: string): boolean {
  return COOKIE_RE.test(v);
}

export function isValidSamlUsername(v: string): boolean {
  return v.length > 0 && v.length <= 256 && !CONTROL_RE.test(v);
}

/**
 * The SAML result is accepted only from a top-level https document served by
 * one of the expected hosts (the portal). Results in sub-resources or on IdP /
 * third-party pages are ignored, so a malicious page cannot inject a cookie.
 */
export function isTrustedSamlSource(url: string, resourceType: string, allowedHosts: readonly string[]): boolean {
  if (resourceType !== 'mainFrame') return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:') return false;
  const host = u.host.toLowerCase();
  return allowedHosts.some((h) => h.toLowerCase() === host);
}

interface RawFields {
  status?: string;
  username?: string;
  preloginCookie?: string;
  userAuthCookie?: string;
  message?: string;
}

function evaluate(f: RawFields): SamlOutcome | null {
  const status = f.status?.trim();
  if (status === undefined || status === '') {
    // Some portals omit the status but still deliver the cookie.
    if (!f.username || (!usableCookie(f.preloginCookie) && !usableCookie(f.userAuthCookie))) return null;
  } else if (status !== '1') {
    return { status: 'failure', message: f.message || `SAML authentication failed (status ${status})` };
  }

  const username = f.username?.trim();
  const prelogin = usableCookie(f.preloginCookie);
  const userAuth = usableCookie(f.userAuthCookie);
  if (!username || (!prelogin && !userAuth)) {
    return { status: 'failure', message: 'SAML response did not contain a username and cookie' };
  }
  // Both values are written to openconnect's stdin / argv: no control characters, bounded size.
  if (!isValidSamlUsername(username))
    return { status: 'failure', message: 'SAML response contains an invalid username' };
  if ((prelogin && !isValidSamlCookie(prelogin)) || (!prelogin && userAuth && !isValidSamlCookie(userAuth))) {
    return { status: 'failure', message: 'SAML response contains an invalid cookie' };
  }
  return prelogin
    ? { status: 'success', username, cookieName: 'prelogin-cookie', cookie: prelogin }
    : { status: 'success', username, cookieName: 'portal-userauthcookie', cookie: userAuth! };
}

/** Looks for the GlobalProtect SAML result in HTTP response headers. */
export function extractSamlFromHeaders(headers: HeaderMap): SamlOutcome | null {
  const h = lowerCaseHeaders(headers);
  if (!h.has('saml-auth-status') && !h.has('prelogin-cookie') && !h.has('portal-userauthcookie')) {
    return null;
  }
  return evaluate({
    status: h.get('saml-auth-status'),
    username: h.get('saml-username'),
    preloginCookie: h.get('prelogin-cookie'),
    userAuthCookie: h.get('portal-userauthcookie'),
    message: h.get('saml-auth-message'),
  });
}

/**
 * Looks for the result in the final HTML page, where the portal puts it into a
 * comment: `<!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>…` .
 */
export function extractSamlFromHtml(html: string): SamlOutcome | null {
  if (!/<saml-auth-status>/i.test(html)) return null;
  return evaluate({
    status: getTagText(html, 'saml-auth-status'),
    username: getTagText(html, 'saml-username'),
    preloginCookie: getTagText(html, 'prelogin-cookie'),
    userAuthCookie: getTagText(html, 'portal-userauthcookie'),
    message: getTagText(html, 'saml-auth-message'),
  });
}
