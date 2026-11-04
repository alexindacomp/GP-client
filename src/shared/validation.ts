/**
 * Pure validation rules shared by the main process (authoritative) and the
 * renderer (instant form feedback). No Node or DOM APIs beyond `URL`.
 */

// eslint-disable-next-line no-control-regex
export const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/;

// ------------------------------------------------------------------ portal URL

export type PortalUrlErrorCode = 'empty' | 'too_long' | 'invalid' | 'not_https' | 'credentials';
export type PortalUrlResult = { ok: true; url: string } | { ok: false; code: PortalUrlErrorCode };

/**
 * Normalises user input into an https portal base URL (`https://host[:port]`).
 * A bare host is accepted; any other scheme, credentials or garbage is not.
 */
export function normalizePortalUrl(input: string): PortalUrlResult {
  const trimmed = typeof input === 'string' ? input.trim() : '';
  if (trimmed === '') return { ok: false, code: 'empty' };
  if (trimmed.length > 2048) return { ok: false, code: 'too_long' };
  if (/\s/.test(trimmed) || CONTROL_CHARS_RE.test(trimmed)) return { ok: false, code: 'invalid' };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, code: 'invalid' };
  }
  if (url.protocol !== 'https:') return { ok: false, code: 'not_https' };
  if (url.username || url.password) return { ok: false, code: 'credentials' };
  if (!url.hostname || url.port === '0') return { ok: false, code: 'invalid' };
  return { ok: true, url: `https://${url.host}` };
}

// ------------------------------------------------------------------ extra openconnect args

export const MAX_EXTRA_ARGS = 32;
export const MAX_EXTRA_ARG_LENGTH = 512;

const UINT_RE = /^\d{1,6}$/;
const CIPHERS_RE = /^[A-Za-z0-9:+!._-]{1,256}$/;
const inRange = (v: string, min: number, max: number): boolean =>
  UINT_RE.test(v) && Number(v) >= min && Number(v) <= max;

/**
 * Allowlist of extra openconnect options. openconnect runs as root, so only
 * options that cannot load files, run commands, redirect traffic or weaken TLS
 * trust are accepted. `null` = flag without value; a function = `--name=value`
 * with that value check. Names must match exactly (no getopt prefixes/bundles).
 */
const EXTRA_OPTIONS: ReadonlyMap<string, ((value: string) => boolean) | null> = new Map<
  string,
  ((value: string) => boolean) | null
>([
  ['-v', null],
  ['--verbose', null],
  ['-q', null],
  ['--quiet', null],
  ['--timestamp', null],
  ['--no-dtls', null],
  ['--disable-ipv6', null],
  ['--servercert', (v) => /^pin-sha256:[A-Za-z0-9+/]{43}=$/.test(v)],
  ['--mtu', (v) => inRange(v, 576, 9000)],
  ['--base-mtu', (v) => inRange(v, 576, 9000)],
  ['--reconnect-timeout', (v) => inRange(v, 0, 86_400)],
  ['--force-dpd', (v) => inRange(v, 1, 3600)],
  ['--dtls-ciphers', (v) => CIPHERS_RE.test(v)],
  ['--dtls12-ciphers', (v) => CIPHERS_RE.test(v)],
]);

export const ALLOWED_EXTRA_OPTIONS: readonly string[] = [...EXTRA_OPTIONS.keys()];

/** Whether the allowlisted option takes a `=value`. */
export function extraOptionTakesValue(name: string): boolean {
  return (EXTRA_OPTIONS.get(name) ?? null) !== null;
}

export type ExtraArgErrorCode = 'not_allowed' | 'bad_value' | 'too_many' | 'too_long' | 'not_name_value';
export type ExtraArgsResult = { ok: true; args: string[] } | { ok: false; code: ExtraArgErrorCode; arg: string };

/** Checks one (already trimmed) argument. */
export function checkExtraArg(arg: string): { ok: true } | { ok: false; code: ExtraArgErrorCode; arg: string } {
  if (arg === '' || CONTROL_CHARS_RE.test(arg)) return { ok: false, code: 'bad_value', arg };
  if (arg.length > MAX_EXTRA_ARG_LENGTH) return { ok: false, code: 'too_long', arg };
  const eq = arg.indexOf('=');
  const name = eq === -1 ? arg : arg.slice(0, eq);
  const value = eq === -1 ? undefined : arg.slice(eq + 1);
  if (!EXTRA_OPTIONS.has(name)) return { ok: false, code: 'not_allowed', arg };
  const check = EXTRA_OPTIONS.get(name) ?? null;
  if (check === null) return value === undefined ? { ok: true } : { ok: false, code: 'not_name_value', arg };
  if (value === undefined) return { ok: false, code: 'not_name_value', arg };
  return check(value) ? { ok: true } : { ok: false, code: 'bad_value', arg };
}

/** Validates the whole list; returns trimmed arguments on success. */
export function checkExtraArgs(args: unknown): ExtraArgsResult {
  if (!Array.isArray(args)) return { ok: false, code: 'bad_value', arg: String(args) };
  if (args.length > MAX_EXTRA_ARGS) return { ok: false, code: 'too_many', arg: '' };
  const out: string[] = [];
  for (const a of args as unknown[]) {
    if (typeof a !== 'string') return { ok: false, code: 'bad_value', arg: String(a) };
    const arg = a.trim();
    const r = checkExtraArg(arg);
    if (!r.ok) return r;
    out.push(arg);
  }
  return { ok: true, args: out };
}

// ------------------------------------------------------------------ paths

/** Absolute path on Windows (`C:\…`, `C:/…`, UNC) or POSIX (`/…`). */
export function isAbsolutePath(p: string): boolean {
  return p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('\\\\');
}

/** The configured binary must be openconnect itself (`openconnect` / `openconnect.exe`). */
export function isOpenconnectBinaryPath(p: string): boolean {
  const base = p.split(/[\\/]/).pop() ?? '';
  return /^openconnect(\.exe)?$/i.test(base);
}

// ------------------------------------------------------------------ IPC error markers

/**
 * Errors rejected by `window.gp` calls carry machine-readable markers in front of
 * the English message: `[field:<name>][code:<code>] message`. Electron wraps
 * them as "Error invoking remote method '<channel>': Error: …".
 */
export interface IpcErrorInfo {
  field?: string;
  code?: string;
  message: string;
}

export function formatIpcError(info: IpcErrorInfo): string {
  const field = info.field ? `[field:${info.field}]` : '';
  const code = info.code ? `[code:${info.code}]` : '';
  return field || code ? `${field}${code} ${info.message}` : info.message;
}

export function parseIpcError(input: unknown): IpcErrorInfo {
  const raw = input instanceof Error ? input.message : typeof input === 'string' ? input : String(input);
  const text = raw.replace(/^Error invoking remote method '[^']*': (?:\w*Error: )?/, '');
  const field = /\[field:([A-Za-z0-9_.-]+)\]/.exec(text)?.[1];
  const code = /\[code:([A-Za-z0-9_.-]+)\]/.exec(text)?.[1];
  const message = text.replace(/^(?:\[(?:field|code):[A-Za-z0-9_.-]+\])+\s*/, '');
  const info: IpcErrorInfo = { message };
  if (field) info.field = field;
  if (code) info.code = code;
  return info;
}
