import { normalizePortalUrl as sharedNormalizePortalUrl, type PortalUrlErrorCode } from '../../shared/validation';
import { getTagText } from './xml';
import type { VpnErrorCode } from '../../shared/ipc';
import { VpnError } from '../vpn/errors';

export type SamlMethod = 'REDIRECT' | 'POST';

export interface PreloginResult {
  /** `saml` when the portal returned a SAML request, otherwise `password`. */
  authType: 'saml' | 'password';
  samlMethod?: SamlMethod;
  /** Base64 payload of `<saml-request>` (URL for REDIRECT, HTML form for POST). */
  samlRequest?: string;
  authMessage?: string;
  usernameLabel?: string;
  passwordLabel?: string;
  region?: string;
}

export class PreloginError extends VpnError {
  constructor(code: VpnErrorCode, message: string, options?: { cause?: unknown }) {
    super(code, message, options);
    this.name = 'PreloginError';
  }
}

function nonEmpty(v: string | undefined): string | undefined {
  return v === undefined || v === '' ? undefined : v;
}

/** Parses a `prelogin.esp` response body. Throws {@link PreloginError} on error responses. */
export function parsePrelogin(xml: string): PreloginResult {
  if (!/<prelogin-response[\s>]/i.test(xml)) {
    throw new PreloginError('PORTAL_UNREACHABLE', 'Unexpected prelogin response (not a GlobalProtect portal?)');
  }
  const status = getTagText(xml, 'status');
  if (status !== undefined && status.toLowerCase() !== 'success') {
    const msg = nonEmpty(getTagText(xml, 'msg')) ?? 'Portal returned an error';
    throw new PreloginError('AUTH_FAILED', `Prelogin failed: ${msg}`);
  }

  const samlRequest = nonEmpty(getTagText(xml, 'saml-request')?.replace(/\s+/g, ''));
  const rawMethod = nonEmpty(getTagText(xml, 'saml-auth-method'))?.toUpperCase();
  const samlMethod: SamlMethod | undefined = rawMethod === 'REDIRECT' || rawMethod === 'POST' ? rawMethod : undefined;

  const result: PreloginResult = {
    authType: samlRequest ? 'saml' : 'password',
    authMessage: nonEmpty(getTagText(xml, 'authentication-message')) ?? nonEmpty(getTagText(xml, 'auth-message')),
    usernameLabel: nonEmpty(getTagText(xml, 'username-label')),
    passwordLabel: nonEmpty(getTagText(xml, 'password-label')),
    region: nonEmpty(getTagText(xml, 'region')),
  };
  if (samlRequest) {
    if (!samlMethod) {
      throw new PreloginError('AUTH_FAILED', `Unsupported SAML auth method: ${rawMethod ?? '(none)'}`);
    }
    result.samlMethod = samlMethod;
    result.samlRequest = samlRequest;
  }
  return result;
}

export type PreloginClientOs = 'Windows' | 'Linux' | 'Mac';

export function clientOsFor(platform: NodeJS.Platform): PreloginClientOs {
  if (platform === 'win32') return 'Windows';
  if (platform === 'darwin') return 'Mac';
  return 'Linux';
}

export const PORTAL_URL_MESSAGES: Record<PortalUrlErrorCode, string> = {
  empty: 'Invalid portal URL',
  too_long: 'Invalid portal URL',
  invalid: 'Invalid portal URL',
  not_https: 'Only https:// portals are supported',
  credentials: 'Portal URL must not contain credentials',
};

/** Error thrown by {@link normalizePortalUrl}; carries the shared error code. */
export class PortalUrlError extends Error {
  constructor(readonly code: PortalUrlErrorCode) {
    super(PORTAL_URL_MESSAGES[code]);
    this.name = 'PortalUrlError';
  }
}

/**
 * Normalises user input into an https portal base URL (`https://host[:port]`).
 * Throws {@link PortalUrlError}. Rules live in src/shared/validation.ts.
 */
export function normalizePortalUrl(input: string): string {
  const r = sharedNormalizePortalUrl(input);
  if (!r.ok) throw new PortalUrlError(r.code);
  return r.url;
}

export function buildPreloginUrl(portalUrl: string, platform: NodeJS.Platform): string {
  const base = normalizePortalUrl(portalUrl);
  const qs = new URLSearchParams({
    tmp: 'tmp',
    clientVer: '4100',
    clientos: clientOsFor(platform),
  });
  return `${base}/global-protect/prelogin.esp?${qs.toString()}`;
}

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

const TLS_ERROR_RE =
  /cert|ssl|tls|self[- ]signed|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_CERT|handshake|hostname\/ip does not match/i;

function classifyNetworkError(err: unknown): VpnErrorCode {
  const parts: string[] = [];
  let cur: unknown = err;
  for (let i = 0; i < 5 && cur; i++) {
    if (cur instanceof Error) {
      parts.push(cur.message);
      const code = (cur as { code?: unknown }).code;
      if (typeof code === 'string') parts.push(code);
      cur = (cur as { cause?: unknown }).cause;
    } else {
      parts.push(String(cur));
      break;
    }
  }
  return TLS_ERROR_RE.test(parts.join(' ')) ? 'TLS_ERROR' : 'PORTAL_UNREACHABLE';
}

export interface PreloginRequestOptions {
  fetch: FetchFn;
  platform: NodeJS.Platform;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export const MAX_PRELOGIN_REDIRECTS = 3;
export const MAX_PRELOGIN_BODY_BYTES = 1024 * 1024;

/** Reads the body, refusing anything larger than `max` bytes. */
async function readCappedText(res: Response, max: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) {
    throw new PreloginError('PORTAL_UNREACHABLE', 'Prelogin response is too large');
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new PreloginError('PORTAL_UNREACHABLE', 'Prelogin response is too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * POSTs to the portal's prelogin endpoint and parses the answer. Redirects are
 * followed manually: at most {@link MAX_PRELOGIN_REDIRECTS}, https only and on
 * the portal's own host.
 */
export async function fetchPrelogin(portalUrl: string, opts: PreloginRequestOptions): Promise<PreloginResult> {
  let url = buildPreloginUrl(portalUrl, opts.platform);
  const portalHost = new URL(url).host;
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? 15_000);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;

  for (let hop = 0; ; hop++) {
    let res: Response;
    try {
      res = await opts.fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'PAN GlobalProtect',
        },
        body: 'cas-support=yes',
        redirect: 'manual',
        signal,
      });
    } catch (err) {
      if (opts.signal?.aborted) throw err;
      const code = classifyNetworkError(err);
      const reason = timeout.aborted ? 'timeout' : err instanceof Error ? err.message : String(err);
      throw new PreloginError(code, `Cannot reach portal: ${reason}`, { cause: err });
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      await res.body?.cancel().catch(() => undefined);
      if (!location)
        throw new PreloginError('PORTAL_UNREACHABLE', `Portal answered HTTP ${res.status} without Location`);
      if (hop >= MAX_PRELOGIN_REDIRECTS)
        throw new PreloginError('PORTAL_UNREACHABLE', 'Too many redirects from portal');
      let next: URL;
      try {
        next = new URL(location, url);
      } catch {
        throw new PreloginError('PORTAL_UNREACHABLE', 'Portal redirected to an invalid URL');
      }
      if (next.protocol !== 'https:' || next.host !== portalHost) {
        throw new PreloginError(
          'PORTAL_UNREACHABLE',
          `Portal redirected to ${next.protocol}//${next.host}; only redirects within https://${portalHost} are followed`,
        );
      }
      url = next.toString();
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new PreloginError('PORTAL_UNREACHABLE', `Portal answered HTTP ${res.status}`);
    }
    return parsePrelogin(await readCappedText(res, MAX_PRELOGIN_BODY_BYTES));
  }
}
