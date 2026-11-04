import { BrowserWindow, session, shell, type OnHeadersReceivedListenerDetails } from 'electron';
import type { PreloginResult } from './prelogin';
import {
  buildSamlLoadTarget,
  extractSamlFromHeaders,
  extractSamlFromHtml,
  isTrustedSamlSource,
  type SamlOutcome,
  type SamlSuccess,
} from './saml-extract';
import type { Logger } from '../logging/logger';
import { VpnError } from '../vpn/errors';

export class SamlCancelledError extends VpnError {
  constructor() {
    super('AUTH_CANCELLED', 'SAML authentication was cancelled');
    this.name = 'SamlCancelledError';
  }
}

export class SamlFailedError extends VpnError {
  constructor(message: string) {
    super('AUTH_FAILED', message);
    this.name = 'SamlFailedError';
  }
}

export interface SamlWindowOptions {
  profileId: string;
  prelogin: PreloginResult;
  parent?: BrowserWindow | null;
  signal?: AbortSignal;
  logger: Logger;
  title?: string;
  /** Hosts allowed to deliver the SAML result (the portal host, `host[:port]`). */
  allowedHosts: readonly string[];
}

const PROFILE_ID_RE = /^[A-Za-z0-9-]{1,64}$/;

/**
 * Opens an isolated browser window for the IdP login and resolves with the
 * GlobalProtect cookie. Rejects with {@link SamlCancelledError} when the user
 * closes the window or the signal aborts.
 */
export function runSamlLogin(opts: SamlWindowOptions): Promise<SamlSuccess> {
  if (!PROFILE_ID_RE.test(opts.profileId)) {
    return Promise.reject(new Error('Invalid profile id for SAML partition'));
  }
  const target = buildSamlLoadTarget(opts.prelogin);
  const ses = session.fromPartition(`persist:saml-${opts.profileId}`);
  const log = opts.logger;

  const baseTitle = opts.title ?? 'GP Connect — SSO';
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ses.setPermissionCheckHandler(() => false);

  return new Promise<SamlSuccess>((resolve, reject) => {
    let settled = false;
    const win = new BrowserWindow({
      width: 520,
      height: 700,
      title: baseTitle,
      parent: opts.parent ?? undefined,
      modal: false,
      autoHideMenuBar: true,
      show: true,
      webPreferences: {
        session: ses,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        spellcheck: false,
      },
    });

    const finish = (outcome: SamlOutcome | Error): void => {
      if (settled) return;
      settled = true;
      ses.webRequest.onHeadersReceived(null);
      opts.signal?.removeEventListener('abort', onAbort);
      if (!win.isDestroyed()) win.destroy();
      if (outcome instanceof Error) {
        reject(outcome);
      } else if (outcome.status === 'success') {
        // Never log the cookie itself.
        log.secrets.add(outcome.cookie);
        log.info('saml', `SAML login succeeded for ${outcome.username} (${outcome.cookieName})`);
        resolve(outcome);
      } else {
        log.warn('saml', outcome.message);
        reject(new SamlFailedError(outcome.message));
      }
    };

    const onAbort = (): void => finish(new SamlCancelledError());
    if (opts.signal?.aborted) {
      onAbort();
      return;
    }
    opts.signal?.addEventListener('abort', onAbort, { once: true });

    // Only the portal's own top-level https response may carry the result.
    ses.webRequest.onHeadersReceived((details: OnHeadersReceivedListenerDetails, callback) => {
      callback({});
      if (!isTrustedSamlSource(details.url, details.resourceType, opts.allowedHosts)) return;
      const outcome = extractSamlFromHeaders(details.responseHeaders ?? {});
      if (outcome) finish(outcome);
    });

    win.webContents.on('did-finish-load', () => {
      if (settled) return;
      const url = win.webContents.getURL();
      if (!isTrustedSamlSource(url, 'mainFrame', opts.allowedHosts)) return;
      win.webContents
        .executeJavaScript('document.documentElement ? document.documentElement.outerHTML : ""', false)
        .then((html: unknown) => {
          // The page may have navigated while the script ran.
          if (typeof html !== 'string' || win.isDestroyed()) return;
          if (!isTrustedSamlSource(win.webContents.getURL(), 'mainFrame', opts.allowedHosts)) return;
          const outcome = extractSamlFromHtml(html);
          if (outcome) finish(outcome);
        })
        .catch(() => {
          // Page navigated away mid-evaluation; the next load will be checked.
        });
    });

    // Plain-http navigation is never allowed in the login window.
    const guard = (event: Electron.Event, url: string): void => {
      if (!url.startsWith('https://')) {
        event.preventDefault();
        log.warn('saml', `Blocked non-https navigation to ${url.split(/[?#]/)[0]}`);
      }
    };
    win.webContents.on('will-navigate', guard);
    win.webContents.on('will-redirect', guard);
    // Sub-frames too (iframes of the IdP page).
    win.webContents.on('will-frame-navigate', (details) => {
      if (!details.url.startsWith('https://') && details.url !== 'about:blank' && details.url !== 'about:srcdoc') {
        details.preventDefault();
        log.warn('saml', `Blocked non-https frame navigation to ${details.url.split(/[?#]/)[0]}`);
      }
    });

    // Show which site the user is typing credentials into.
    const showOrigin = (): void => {
      if (win.isDestroyed()) return;
      try {
        win.setTitle(`${baseTitle} — ${new URL(win.webContents.getURL()).host}`);
      } catch {
        win.setTitle(baseTitle);
      }
    };
    win.webContents.on('did-navigate', showOrigin);
    win.webContents.on('did-navigate-in-page', showOrigin);
    win.on('page-title-updated', (e) => e.preventDefault());

    win.webContents.on('did-fail-load', (_e, code, description, url, isMainFrame) => {
      if (isMainFrame && code !== -3 /* ERR_ABORTED: normal on redirects */) {
        let origin = url;
        try {
          origin = new URL(url).origin;
        } catch {
          // keep raw
        }
        log.warn('saml', `Failed to load ${origin}: ${description} (${code})`);
      }
    });

    // Popups (e.g. "help" links) go to the system browser; the login stays here.
    win.webContents.setWindowOpenHandler(({ url }) => {
      if (url.startsWith('https://')) void shell.openExternal(url);
      return { action: 'deny' };
    });

    win.on('closed', () => finish(new SamlCancelledError()));

    const load = target.kind === 'url' ? win.loadURL(target.url) : win.loadURL(target.dataUrl);
    load.catch((err: unknown) => {
      // ERR_ABORTED happens when the page immediately redirects; ignore it.
      const msg = err instanceof Error ? err.message : String(err);
      if (!/ERR_ABORTED/.test(msg)) log.warn('saml', `SAML page load error: ${msg}`);
    });
  });
}

/** Removes cookies/storage of a profile's SAML partition (on profile removal). */
export async function clearSamlPartition(profileId: string): Promise<void> {
  if (!PROFILE_ID_RE.test(profileId)) return;
  const ses = session.fromPartition(`persist:saml-${profileId}`);
  await ses.clearStorageData();
  await ses.clearCache();
}
