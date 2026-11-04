import { app, session, type IpcMainEvent, type IpcMainInvokeEvent, type WebContents } from 'electron';
import { pathToFileURL } from 'node:url';
import { isPermissionAllowed } from './permissions';

const PROD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

// Vite's dev server needs inline scripts (React refresh preamble) and websockets (HMR).
const DEV_CSP = PROD_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'").replace(
  "connect-src 'self'",
  "connect-src 'self' ws: http://localhost:*",
);

export interface RendererLocation {
  /** Dev server URL (electron-vite sets ELECTRON_RENDERER_URL) or undefined in production. */
  devUrl?: string;
  /** Absolute path of the built index.html. */
  indexHtml: string;
}

/** Session-wide hardening of the app's default session. */
export function hardenDefaultSession(loc: RendererLocation, trustedContents: () => WebContents | null): void {
  const ses = session.defaultSession;
  const csp = loc.devUrl ? DEV_CSP : PROD_CSP;
  ses.webRequest.onHeadersReceived((details, callback) => {
    const headers = { ...details.responseHeaders };
    headers['Content-Security-Policy'] = [csp];
    callback({ responseHeaders: headers });
  });
  // Deny everything except clipboard writes from our own page (log "Copy").
  const allowed = (permission: string, wc: WebContents | null, url: string | undefined): boolean =>
    isPermissionAllowed({
      permission,
      requester: wc,
      trusted: trustedContents(),
      requestingUrl: url ?? (wc && !wc.isDestroyed() ? wc.getURL() : undefined),
      isAppUrl: (u) => isAppUrl(u, loc),
    });
  ses.setPermissionRequestHandler((wc, permission, cb, details) => cb(allowed(permission, wc, details.requestingUrl)));
  ses.setPermissionCheckHandler((wc, permission, _origin, details) => allowed(permission, wc, details.requestingUrl));
}

/** Prevents webviews anywhere in the app. */
export function blockWebviews(): void {
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-attach-webview', (event) => event.preventDefault());
  });
}

function stripHash(u: string): string {
  const url = new URL(u);
  url.hash = '';
  url.search = '';
  return url.toString();
}

export function isAppUrl(url: string, loc: RendererLocation): boolean {
  try {
    if (loc.devUrl) return new URL(url).origin === new URL(loc.devUrl).origin;
    return stripHash(url) === pathToFileURL(loc.indexHtml).toString();
  } catch {
    return false;
  }
}

/**
 * IPC calls are accepted only from the main frame of our own window showing
 * our own page.
 */
export function isTrustedSender(
  event: IpcMainInvokeEvent | IpcMainEvent,
  expected: WebContents | null,
  loc: RendererLocation,
): boolean {
  if (!expected || event.sender !== expected) return false;
  const frame = event.senderFrame;
  if (!frame || frame !== event.sender.mainFrame) return false;
  return isAppUrl(frame.url, loc);
}
