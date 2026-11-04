# GP Connect — cross-platform GlobalProtect VPN client

## Goal
A friendlier replacement for the stock Palo Alto GlobalProtect client on Windows 11 (light/dark
theme), Ubuntu (latest LTS, GNOME) and macOS. Connect in one or two clicks, with clear statuses
and errors.

## Stack
- Electron (main + preload + renderer), strict TypeScript, Vite (`electron-vite`), React 18.
- VPN engine: the external **OpenConnect ≥ 9** binary with `--protocol=gp`. The client does not
  implement the tunnel; it manages the openconnect process.
- Distributables: `electron-builder` (Windows: NSIS installer + portable; Linux: AppImage + deb;
  macOS: dmg).
- Releases: tag `vX.Y.Z` → `.github/workflows/release.yml` builds all platforms and attaches them
  to the GitHub Release; `.github/workflows/ci.yml` runs on push/PR.
- Tests: Vitest (unit tests for main logic, React components via @testing-library/react).

## Layout
```
src/shared/      — IPC contract and shared types (single source of truth)
src/main/        — main process: VPN engine, auth, settings, tray, IPC handlers
src/preload/     — contextBridge: window.gp (typed API)
src/renderer/    — React UI
```

## Functionality (main / "backend")
1. **Portal profiles**: list of {id, name, portalUrl, username?, preferredGateway?, authMode: 'auto'|'password'|'saml'}.
   Stored in `app.getPath('userData')/profiles.json`. Passwords only via `safeStorage`
   (OS encryption), optional "remember password".
2. **Prelogin**: `POST https://<portal>/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=<Windows|Linux|Mac>`
   — parse the XML: `saml-auth-method`, `saml-request` (base64), `auth-message`, `username-label`, `password-label`.
   If `saml-request` is present → SAML, otherwise password.
3. **SAML**: a separate `BrowserWindow` (isolated partition `persist:saml-<profileId>`) loads the
   SAML request (REDIRECT → URL, POST → HTML form). The response is captured from the headers
   `saml-username`, `prelogin-cookie` / `portal-userauthcookie` (via `webRequest.onHeadersReceived`)
   or from the same values in an HTML comment `<!-- <saml-auth-status>1</saml-auth-status>... -->`.
   The result is passed to openconnect: `--usergroup=portal:prelogin-cookie` (or `portal-userauthcookie`),
   `--user=<saml-username>`, cookie on stdin (`--passwd-on-stdin`).
4. **Password authentication**: openconnect with `--user`, password on stdin. openconnect MFA/OTP
   challenges are forwarded to the UI as an `authPrompt` event; the answer is written to stdin.
5. **Gateways**: after authentication, the gateway list (parsed from openconnect output) is
   offered for manual or automatic selection (preferredGateway / first). The chosen gateway is
   passed as `--authgroup`.
6. **Process management** (`VpnEngine`, state machine):
   `disconnected → prelogin → authenticating → connecting → connected → disconnecting → disconnected`,
   plus `error` (with a code and a human-readable message) and `reconnecting`.
   - Elevation: Linux — `pkexec` (polkit policy file in `build/linux/`); macOS — helper started via
     `osascript ... with administrator privileges` (no sudoers/`NOPASSWD` rule: it would let any
     user process run openconnect as root); Windows — the app itself runs `asInvoker`, openconnect
     is started through an elevated helper (UAC); the Wintun driver comes with OpenConnect-GUI.
   - Before every elevated launch the binary and HIP script must pass a trust check (root-owned /
     admin-only location, see README); otherwise `PRIVILEGES_DENIED`.
   - Binary lookup: configured path → bundled `resources/bin/<platform>/openconnect` → PATH →
     standard install directories.
   - Disconnect: graceful SIGINT (Ctrl+C on Windows), forced kill after a 10 s timeout.
   - stdout/stderr parsing: "Connected as <ip>", "ESP session established", authentication and
     DNS errors. Log kept in a ring buffer (≤ 2000 lines) plus a file in userData/logs.
   - Stats: connection time, assigned IP, gateway; rx/tx are not shown.
   - Auto-reconnect on connection loss (configurable), backoff 2/5/10/30 s.
7. **Tray / menu bar**: status icon (disconnected/connecting/connected), menu:
   Connect/Disconnect, profile selection, Show window, Quit. Closing the window hides it to the tray.
   Template icons for the macOS menu bar.
8. **Settings**: theme (`system`|`light`|`dark`) via `nativeTheme.themeSource`, launch at login,
   connect on startup, auto-reconnect, openconnect path, extra arguments (allowlisted),
   HIP script (path to `hipreport.sh`, `--csd-wrapper`), language (ru/en/uk). Changing the
   openconnect path, HIP script or extra arguments requires confirmation in a system dialog.
9. **Security**: `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`,
   strict CSP, validation of all IPC input, https portals only, no secrets in logs
   (mask cookies/passwords), single app instance (`requestSingleInstanceLock`).

## IPC contract (`src/shared/ipc.ts`, exposed as `window.gp`)
```ts
type AuthMode = 'auto' | 'password' | 'saml';
interface Profile { id: string; name: string; portalUrl: string; username?: string;
  authMode: AuthMode; preferredGateway?: string; savePassword: boolean; }
type VpnStatus = 'disconnected'|'prelogin'|'authenticating'|'connecting'|'connected'
  |'disconnecting'|'reconnecting'|'error';
interface Gateway { name: string; address: string; priority?: number; }
interface VpnState { status: VpnStatus; profileId?: string; gateway?: Gateway;
  assignedIp?: string; connectedAt?: number;
  error?: { code: VpnErrorCode; message: string; detail?: string;
    hint?: 'untrusted_binary' | 'untrusted_homebrew' | 'stop_failed' | 'settings_not_confirmed' };
  gateways?: Gateway[]; }
type VpnErrorCode = 'OPENCONNECT_NOT_FOUND'|'AUTH_FAILED'|'AUTH_CANCELLED'|'PORTAL_UNREACHABLE'
  |'TLS_ERROR'|'PRIVILEGES_DENIED'|'TUNNEL_FAILED'|'UNKNOWN';
interface AuthPrompt { id: string; kind: 'password'|'otp'|'text'|'select';
  message: string; options?: string[]; }
type Language = 'ru' | 'en' | 'uk';
interface Settings { theme: 'system'|'light'|'dark'; launchAtLogin: boolean;
  connectOnStartup: boolean; autoReconnect: boolean; openconnectPath?: string;
  extraArgs: string[]; hipScriptPath?: string; language: Language;
  lastProfileId?: string; }
interface SystemInfo { platform: 'win32'|'darwin'|'linux'; openconnectVersion?: string;
  openconnectFound: boolean; appVersion: string; shouldUseDarkColors: boolean; }

window.gp = {
  profiles: { list(): Promise<Profile[]>; save(p: Omit<Profile,'id'> & {id?: string}, password?: string): Promise<Profile>;
              remove(id: string): Promise<void>; },
  vpn: { connect(profileId: string, opts?: { gateway?: string; password?: string }): Promise<void>;
         disconnect(): Promise<void>; getState(): Promise<VpnState>;
         answerPrompt(id: string, value: string | null): Promise<void>;   // null = cancel
         getPendingPrompts(): Promise<AuthPrompt[]>;   // prompts pushed before subscribing; dedupe by id
         onState(cb: (s: VpnState) => void): () => void;
         onPrompt(cb: (p: AuthPrompt) => void): () => void; },
  logs: { get(): Promise<string[]>; onLine(cb: (line: string) => void): () => void;
          openFolder(): Promise<void>; },
  settings: { get(): Promise<Settings>; set(patch: Partial<Settings>): Promise<Settings>; },
  system: { info(): Promise<SystemInfo>; onThemeChange(cb: (dark: boolean) => void): () => void;
            openExternal(url: string): Promise<void>; },
  window: { minimize(): void; close(): void; }   // for the custom title bar
};
```
`VpnState.error`:
- `message` — localized next step for the user, without a technical suffix.
- `detail` — raw technical cause (e.g. "Login failed", "getaddrinfo ENOTFOUND"), secrets masked,
  untranslated, ≤ ~300 chars; absent when unknown.
- `hint` — machine-readable cue that lets the UI offer a specific action: `untrusted_binary`
  (openconnect/HIP script failed the trust check), `untrusted_homebrew` (same, Homebrew path —
  suggest MacPorts), `stop_failed` (openconnect could not be stopped), `settings_not_confirmed`
  (the user declined the confirmation dialog for changed sensitive settings).

IPC channels are named `gp:<area>:<action>` and listed as constants in `src/shared/ipc.ts`.

## UI (renderer / "frontend")
- Window 380×600 (min. 360×520), custom title bar: Windows — `titleBarOverlay` in theme colors,
  macOS — `hiddenInset` with traffic lights, Linux — native frame.
- **Main screen**: large Connect/Disconnect toggle with animated state, profile dropdown, gateway
  selection (auto/list), status card (IP, gateway, connection duration), clear errors with an
  action ("Set openconnect path", "Retry").
- **Authentication dialog**: username/password, OTP, choice from a list; "remember password".
- **Profiles**: list, add/edit/delete, portal URL validation.
- **Settings**: theme, launch at login, auto-reconnect, openconnect path, extra arguments, language.
- **Log**: live log with auto-scroll, copy, "open log folder".
- **Onboarding**: no profiles → "Add a portal" screen; openconnect not found → install
  instructions for the current OS (Windows: OpenConnect-GUI installer, `winget search openconnect`
  as an alternative; macOS: MacPorts; Ubuntu: apt).
- **Themes**: design tokens as CSS custom properties; light and dark themes in the Windows 11
  Fluent style (Segoe UI Variable on Windows, system-ui on macOS/Ubuntu), accent color, 8px radii,
  `system` mode follows `nativeTheme`. Windows 11 — `backgroundMaterial: 'mica'` (with a
  transparent body background), macOS — `vibrancy: 'under-window'`.
- Accessibility: keyboard navigation, visible focus ring, aria attributes, WCAG AA contrast in
  both themes, `prefers-reduced-motion`.
- Localization: ru (default), en, uk — a plain dictionary, no heavy libraries.

## Acceptance criteria
1. `npm install && npm run typecheck && npm run lint && npm test && npm run build` pass.
2. `npm run dev` starts the app; without openconnect it shows the install screen and does not crash.
3. The prelogin parser, SAML cookie capture, openconnect output parser and the state machine are
   covered by fixture-based unit tests (no real portal needed).
4. Passwords/cookies never reach the log, nor the renderer after submission.
5. The theme switches system/light/dark instantly, without restart; both themes meet AA contrast.
6. `npm run dist:win|dist:mac|dist:linux` are configured in electron-builder.
7. The README (English) covers installing openconnect on each OS, privileges, building, releasing
   and known limitations.
