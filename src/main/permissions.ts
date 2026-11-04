/**
 * Permission policy for the app's default session (pure; no Electron imports).
 * Everything is denied except sanitized clipboard writes (log "Copy") from the
 * app's own page in the main window.
 */
export interface PermissionContext {
  permission: string;
  /** Identity of the requesting webContents; compared by reference. */
  requester: unknown;
  /** The main window's webContents (the only trusted one). */
  trusted: unknown;
  /** Full URL of the requesting frame, if known. */
  requestingUrl: string | undefined;
  isAppUrl(url: string): boolean;
}

export const ALLOWED_PERMISSIONS: ReadonlySet<string> = new Set(['clipboard-sanitized-write']);

export function isPermissionAllowed(ctx: PermissionContext): boolean {
  if (!ALLOWED_PERMISSIONS.has(ctx.permission)) return false;
  if (ctx.requester === null || ctx.requester === undefined || ctx.requester !== ctx.trusted) return false;
  return ctx.requestingUrl !== undefined && ctx.isAppUrl(ctx.requestingUrl);
}
