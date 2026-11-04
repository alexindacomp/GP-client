import {
  ALLOWED_EXTRA_OPTIONS,
  checkExtraArgs,
  extraOptionTakesValue,
  MAX_EXTRA_ARG_LENGTH,
  MAX_EXTRA_ARGS,
  type ExtraArgErrorCode,
} from '../../shared/validation';
import type { SamlCookieName } from '../auth/saml-extract';

export type OpenconnectAuth = { kind: 'password' } | { kind: 'saml'; cookieName: SamlCookieName };

export interface OpenconnectArgsInput {
  /** Normalised https portal URL. */
  portalUrl: string;
  platform: NodeJS.Platform;
  username?: string;
  auth: OpenconnectAuth;
  /** Gateway name/address to select on the portal (`--authgroup`). */
  gateway?: string;
  hipScriptPath?: string;
  extraArgs?: readonly string[];
}

export class InvalidArgumentError extends Error {
  constructor(
    message: string,
    readonly code: ExtraArgErrorCode | 'bad_value' = 'bad_value',
  ) {
    super(message);
    this.name = 'InvalidArgumentError';
  }
}

/** Names of the options accepted in extra arguments (for messages/docs). */
export function allowedExtraOptions(): string[] {
  return [...ALLOWED_EXTRA_OPTIONS];
}

function optionName(arg: string): string {
  const eq = arg.indexOf('=');
  return eq === -1 ? arg : arg.slice(0, eq);
}

/**
 * Validates user-supplied extra arguments against the shared allowlist
 * (src/shared/validation.ts). Applied on IPC input, on settings loaded from disk
 * and again right before every spawn. Throws {@link InvalidArgumentError}.
 */
export function validateExtraArgs(args: unknown): string[] {
  const r = checkExtraArgs(args);
  if (r.ok) return r.args;
  const name = optionName(r.arg);
  switch (r.code) {
    case 'too_many':
      throw new InvalidArgumentError(`At most ${MAX_EXTRA_ARGS} extra arguments allowed`, r.code);
    case 'too_long':
      throw new InvalidArgumentError(`Extra argument is too long (max ${MAX_EXTRA_ARG_LENGTH})`, r.code);
    case 'not_allowed':
      throw new InvalidArgumentError(
        `Option "${name}" is not allowed. Allowed: ${allowedExtraOptions().join(', ')}`,
        r.code,
      );
    case 'not_name_value':
      throw new InvalidArgumentError(
        extraOptionTakesValue(name)
          ? `Option ${name} needs a value (use ${name}=<value>)`
          : `Option ${name} does not take a value`,
        r.code,
      );
    default:
      throw new InvalidArgumentError(
        Array.isArray(args) && name ? `Invalid value for ${name}` : 'extraArgs must be an array of option strings',
        'bad_value',
      );
  }
}

/** `--os` value matching the `clientos` sent in prelogin (SAML cookies are bound to it). */
export function openconnectOs(platform: NodeJS.Platform): string {
  if (platform === 'win32') return 'win';
  if (platform === 'darwin') return 'mac-intel';
  return 'linux-64';
}

function assertSafeValue(name: string, value: string): void {
  // eslint-disable-next-line no-control-regex
  if (value === '' || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new InvalidArgumentError(`Invalid value for ${name}`);
  }
}

/**
 * Builds the openconnect argv (without the binary). Secrets (password / SAML
 * cookie) are never part of argv — they are written to stdin
 * (`--passwd-on-stdin`).
 */
export function buildOpenconnectArgs(input: OpenconnectArgsInput): string[] {
  const url = new URL(input.portalUrl);
  if (url.protocol !== 'https:') throw new InvalidArgumentError('Only https portals are supported');

  const args = ['--protocol=gp', `--os=${openconnectOs(input.platform)}`, '--passwd-on-stdin'];

  if (input.username !== undefined) {
    assertSafeValue('username', input.username);
    args.push(`--user=${input.username}`);
  }
  if (input.auth.kind === 'saml') {
    args.push(`--usergroup=portal:${input.auth.cookieName}`);
  }
  if (input.gateway !== undefined) {
    assertSafeValue('gateway', input.gateway);
    args.push(`--authgroup=${input.gateway}`);
  }
  if (input.hipScriptPath !== undefined) {
    assertSafeValue('hipScriptPath', input.hipScriptPath);
    args.push(`--csd-wrapper=${input.hipScriptPath}`);
  }
  args.push(...validateExtraArgs(input.extraArgs ?? []));
  // `--` guarantees the server is never parsed as an option.
  args.push('--', `https://${url.host}`);
  return args;
}
