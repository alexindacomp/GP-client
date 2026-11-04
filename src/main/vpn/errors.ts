import type { VpnErrorCode } from '../../shared/ipc';
import type { ErrorHint } from './messages';

const CODES: ReadonlySet<string> = new Set<VpnErrorCode>([
  'OPENCONNECT_NOT_FOUND',
  'AUTH_FAILED',
  'AUTH_CANCELLED',
  'PORTAL_UNREACHABLE',
  'TLS_ERROR',
  'PRIVILEGES_DENIED',
  'TUNNEL_FAILED',
  'UNKNOWN',
]);

/** Error carrying a {@link VpnErrorCode}; anything thrown into the engine may use it. */
export class VpnError extends Error {
  /** Cause-specific next-step text to show instead of the per-code one (see messages.ts). */
  hint?: ErrorHint;

  constructor(
    readonly code: VpnErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'VpnError';
  }
}

export function isVpnErrorCode(v: unknown): v is VpnErrorCode {
  return typeof v === 'string' && CODES.has(v);
}

/** Error code of any thrown value that has a valid `code` property, else `UNKNOWN`. */
export function errorCodeOf(err: unknown): VpnErrorCode {
  const code = (err as { code?: unknown } | null)?.code;
  return isVpnErrorCode(code) ? code : 'UNKNOWN';
}
