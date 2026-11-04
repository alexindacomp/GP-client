/**
 * Validation of untrusted input (IPC payloads and files on disk).
 * Every function throws {@link ValidationError}. Its message starts with
 * machine-readable markers `[field:<name>][code:<code>] ` followed by English
 * text (see `parseIpcError` in src/shared/validation.ts). The pure rules are
 * shared with the renderer.
 */
import type { AuthMode, ConnectOptions, Language, ProfileInput, Settings, Theme } from '../../shared/ipc';
import { CONTROL_CHARS_RE, formatIpcError, isAbsolutePath, isOpenconnectBinaryPath } from '../../shared/validation';
import { normalizePortalUrl, PortalUrlError } from '../auth/prelogin';
import { InvalidArgumentError, validateExtraArgs } from '../openconnect/args';

export interface ValidationErrorInfo {
  field?: string;
  code?: string;
}

export class ValidationError extends Error {
  readonly field?: string;
  readonly code?: string;

  constructor(message: string, info: ValidationErrorInfo = {}) {
    super(formatIpcError({ ...info, message }));
    this.name = 'ValidationError';
    this.field = info.field;
    this.code = info.code;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const AUTH_MODES: readonly AuthMode[] = ['auto', 'password', 'saml'];
const THEMES: readonly Theme[] = ['system', 'light', 'dark'];
const LANGUAGES: readonly Language[] = ['ru', 'en', 'uk'];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function rejectUnknownKeys(obj: Record<string, unknown>, allowed: readonly string[], what: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k))
      throw new ValidationError(`Unknown ${what} field "${k}"`, { field: k, code: 'unknown_field' });
  }
}

export function validateId(v: unknown, what = 'id', field = 'id'): string {
  if (typeof v !== 'string' || !UUID_RE.test(v))
    throw new ValidationError(`Invalid ${what}`, { field, code: 'invalid' });
  return v.toLowerCase();
}

function text(v: unknown, field: string, max: number): string {
  if (typeof v !== 'string') throw new ValidationError(`${field} must be a string`, { field, code: 'invalid_type' });
  const t = v.trim();
  if (t === '') throw new ValidationError(`${field} must not be empty`, { field, code: 'required' });
  if (t.length > max) throw new ValidationError(`${field} is too long (max ${max})`, { field, code: 'too_long' });
  if (CONTROL_CHARS_RE.test(t)) {
    throw new ValidationError(`${field} contains invalid characters`, { field, code: 'invalid_chars' });
  }
  return t;
}

function optionalText(v: unknown, field: string, max: number): string | undefined {
  if (v === undefined || v === null || (typeof v === 'string' && v.trim() === '')) return undefined;
  return text(v, field, max);
}

function absolutePath(v: unknown, field: string): string | undefined {
  const p = optionalText(v, field, 1024);
  if (p === undefined) return undefined;
  if (!isAbsolutePath(p))
    throw new ValidationError(`${field} must be an absolute path`, { field, code: 'not_absolute' });
  return p;
}

function bool(v: unknown, field: string): boolean {
  if (typeof v !== 'boolean') throw new ValidationError(`${field} must be a boolean`, { field, code: 'invalid_type' });
  return v;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], field: string): T {
  if (typeof v !== 'string' || !allowed.includes(v as T)) {
    throw new ValidationError(`${field} must be one of: ${allowed.join(', ')}`, { field, code: 'invalid' });
  }
  return v as T;
}

const PROFILE_KEYS = ['id', 'name', 'portalUrl', 'username', 'authMode', 'preferredGateway', 'savePassword'] as const;

export function validateProfileInput(raw: unknown): ProfileInput {
  if (!isPlainObject(raw)) throw new ValidationError('Profile must be an object', { code: 'invalid_type' });
  rejectUnknownKeys(raw, PROFILE_KEYS, 'profile');
  let portalUrl: string;
  try {
    portalUrl = normalizePortalUrl(text(raw.portalUrl, 'portalUrl', 2048));
  } catch (err) {
    if (err instanceof ValidationError) throw err;
    if (err instanceof PortalUrlError) throw new ValidationError(err.message, { field: 'portalUrl', code: err.code });
    throw new ValidationError('Invalid portal URL', { field: 'portalUrl', code: 'invalid' });
  }
  const out: ProfileInput = {
    name: text(raw.name, 'name', 100),
    portalUrl,
    authMode: oneOf(raw.authMode, AUTH_MODES, 'authMode'),
    savePassword: bool(raw.savePassword, 'savePassword'),
  };
  if (raw.id !== undefined) out.id = validateId(raw.id, 'profile id');
  const username = optionalText(raw.username, 'username', 256);
  if (username !== undefined) out.username = username;
  const gw = optionalText(raw.preferredGateway, 'preferredGateway', 255);
  if (gw !== undefined) out.preferredGateway = gw;
  return out;
}

export function validatePassword(v: unknown): string | undefined {
  const field = 'password';
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string') throw new ValidationError('Password must be a string', { field, code: 'invalid_type' });
  if (v.length === 0) return undefined;
  if (v.length > 1024) throw new ValidationError('Password is too long', { field, code: 'too_long' });
  if (/[\r\n\0]/.test(v)) throw new ValidationError('Password must be a single line', { field, code: 'invalid_chars' });
  return v;
}

export function validateConnectOptions(v: unknown): ConnectOptions {
  if (v === undefined || v === null) return {};
  if (!isPlainObject(v)) throw new ValidationError('Connect options must be an object', { code: 'invalid_type' });
  rejectUnknownKeys(v, ['gateway', 'password'], 'connect option');
  const out: ConnectOptions = {};
  const gw = optionalText(v.gateway, 'gateway', 255);
  if (gw !== undefined) out.gateway = gw;
  const pw = validatePassword(v.password);
  if (pw !== undefined) out.password = pw;
  return out;
}

const SETTINGS_KEYS = [
  'theme',
  'launchAtLogin',
  'connectOnStartup',
  'autoReconnect',
  'openconnectPath',
  'extraArgs',
  'hipScriptPath',
  'language',
  'lastProfileId',
] as const;

/**
 * Validates a settings patch. Optional string settings may be cleared by passing
 * `null`/`''`; the result then contains the key with value `undefined`.
 */
export function validateSettingsPatch(raw: unknown): Partial<Settings> {
  if (!isPlainObject(raw)) throw new ValidationError('Settings patch must be an object', { code: 'invalid_type' });
  rejectUnknownKeys(raw, SETTINGS_KEYS, 'settings');
  const out: Partial<Settings> = {};
  const has = (k: string): boolean => Object.prototype.hasOwnProperty.call(raw, k);
  if (has('theme')) out.theme = oneOf(raw.theme, THEMES, 'theme');
  if (has('language')) out.language = oneOf(raw.language, LANGUAGES, 'language');
  if (has('launchAtLogin')) out.launchAtLogin = bool(raw.launchAtLogin, 'launchAtLogin');
  if (has('connectOnStartup')) out.connectOnStartup = bool(raw.connectOnStartup, 'connectOnStartup');
  if (has('autoReconnect')) out.autoReconnect = bool(raw.autoReconnect, 'autoReconnect');
  if (has('openconnectPath')) {
    const p = absolutePath(raw.openconnectPath, 'openconnectPath');
    // Only the openconnect binary itself may be configured (not an arbitrary program).
    if (p !== undefined && !isOpenconnectBinaryPath(p)) {
      throw new ValidationError(
        'openconnectPath must point to the openconnect binary (openconnect / openconnect.exe)',
        {
          field: 'openconnectPath',
          code: 'not_openconnect',
        },
      );
    }
    out.openconnectPath = p;
  }
  if (has('hipScriptPath')) out.hipScriptPath = absolutePath(raw.hipScriptPath, 'hipScriptPath');
  if (has('lastProfileId')) {
    out.lastProfileId =
      raw.lastProfileId === null || raw.lastProfileId === undefined
        ? undefined
        : validateId(raw.lastProfileId, 'id', 'lastProfileId');
  }
  if (has('extraArgs')) {
    try {
      out.extraArgs = validateExtraArgs(raw.extraArgs);
    } catch (err) {
      const code = err instanceof InvalidArgumentError ? err.code : 'bad_value';
      throw new ValidationError(err instanceof Error ? err.message : 'Invalid extraArgs', { field: 'extraArgs', code });
    }
  }
  return out;
}

/** Only https URLs may be opened externally. */
export function validateExternalUrl(v: unknown): string {
  const field = 'url';
  if (typeof v !== 'string' || v.length > 2048) throw new ValidationError('Invalid URL', { field, code: 'invalid' });
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    throw new ValidationError('Invalid URL', { field, code: 'invalid' });
  }
  if (url.protocol !== 'https:')
    throw new ValidationError('Only https:// links can be opened', { field, code: 'not_https' });
  return url.toString();
}

/** Rejection used when the user declines the confirmation dialog. */
export function notConfirmedError(): ValidationError {
  return new ValidationError('The change was not confirmed', { code: 'not_confirmed' });
}
