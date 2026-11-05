# GP Connect — cross-platform GlobalProtect VPN client

## Goal
A friendlier replacement for the stock Palo Alto GlobalProtect client on Windows 10/11 (light/dark
theme), Ubuntu/Debian (GNOME) and macOS. Connect in one or two clicks, with clear statuses
and errors.

## Stack
- **Tauri 2**: Rust backend + the OS WebView (WebView2 / WKWebView / WebKitGTK 4.1). Rust workspace:
  `crates/gp-core` (pure logic), `crates/gp-elevate` (elevation), `crates/gp-helper` (Windows
  elevated helper `gp-connect-helper.exe`), `src-tauri` (app shell). Async runtime: tokio.
- UI: React 18, strict TypeScript, Vite; `window.gp` is implemented on top of `@tauri-apps/api`
  (`src/renderer/src/bridge/tauri.ts`).
- VPN engine: the external **OpenConnect ≥ 9** binary with `--protocol=gp`. The client does not
  implement the tunnel; it manages the openconnect process. On Windows OpenConnect v9.21 + Wintun
  is bundled into the installer.
- Distributables: the Tauri bundler (Windows: NSIS installer, per-machine, no portable build;
  Linux: AppImage + deb; macOS: dmg for arm64 and x64).
- Releases: tag `v<version>` (must equal the package.json version) → `.github/workflows/release.yml`
  builds all platforms and attaches them to the GitHub Release under stable names;
  `.github/workflows/ci.yml` runs on push/PR on Linux, Windows and macOS.
- Tests: `cargo test --workspace` (backend logic, fixture-based) and Vitest (src/shared, React
  components via @testing-library/react); shared fixtures in `fixtures/`.

## Layout
```
src/shared/          — IPC contract and shared types (single source of truth for the UI)
src/renderer/        — React UI (bridge/tauri.ts implements window.gp)
crates/gp-core/      — VPN engine, prelogin, SAML parsing, openconnect, stores, validation, logging
crates/gp-elevate/   — pkexec / osascript / Windows helper client, helper protocol, Windows ACL probe
crates/gp-helper/    — gp-connect-helper.exe (Windows, runs elevated)
src-tauri/           — Tauri commands and events, windows, SAML window, tray, keystore, migration
```
Architecture details: [ARCHITECTURE-TAURI.md](ARCHITECTURE-TAURI.md).

## Functionality ("backend", Rust)
1. **Portal profiles**: list of {id, name, portalUrl, username?, preferredGateway?, authMode: 'auto'|'password'|'saml'}.
   Stored in `<app data dir>/profiles.json` (identifier `com.gpconnect.client`). Passwords only in
   the OS keystore (`keyring`: Credential Manager / Keychain / Secret Service), optional
   "remember password"; without a keystore the password is not stored.
2. **Prelogin**: `POST https://<portal>/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=<Windows|Linux|Mac>`
   — parse the XML: `saml-auth-method`, `saml-request` (base64), `auth-message`, `username-label`, `password-label`.
   If `saml-request` is present → SAML, otherwise password.
3. **SAML**: a separate webview window (persistent data store isolated per profile:
   `<app local data>/saml/<profileId>` on Windows/Linux, a WKWebsiteDataStore per profile on
   macOS 14+; cleared on profile removal; no IPC) loads the SAML request (REDIRECT → URL, POST →
   HTML form). The response is read from the HTML comment
   `<!-- <saml-auth-status>1</saml-auth-status>... -->` after each top-level page load (all OSes) and,
   on Windows, also from the headers `saml-auth-status`, `saml-username`, `prelogin-cookie` /
   `portal-userauthcookie` (WebView2 `WebResourceResponseReceived`). Only top-level https
   documents from the portal host are trusted.
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
   - Elevation: Linux — `pkexec` (polkit policy `build/linux/com.gpconnect.openconnect.policy`,
     `auth_admin`); macOS — root wrapper started via `osascript ... with administrator privileges`
     (no sudoers/`NOPASSWD` rule: it would let any user process run openconnect as root);
     Windows — the app runs unelevated, openconnect is started by `gp-connect-helper.exe` launched
     with UAC, which re-validates the request as administrator (trust check, argv allowlist) and
     relays I/O over an authenticated named pipe; Wintun comes with the bundled OpenConnect.
   - Before every elevated launch the binary and HIP script must pass a trust check (root-owned /
     admin-only location, see README); otherwise `PRIVILEGES_DENIED`.
   - Binary lookup: configured path → bundled `<resources>/bin/<platform>/openconnect[.exe]`
     (Windows: `C:\Program Files\GP Connect\bin\win32\`) → PATH → standard install directories;
     trusted candidates win over untrusted ones.
   - Disconnect: graceful SIGINT (Ctrl+C on Windows), forced kill after a 10 s timeout.
   - stdout/stderr parsing: "Connected as <ip>", "ESP session established", authentication and
     DNS errors. Log kept in a ring buffer (≤ 2000 lines) plus `gp-connect.log` in the app log dir
     (rotated at 5 MB).
   - Stats: connection time, assigned IP, gateway; rx/tx are not shown.
   - Auto-reconnect on connection loss (configurable), backoff 2/5/10/30 s.
7. **Tray / menu bar**: status icon (disconnected/connecting/connected), menu:
   Connect/Disconnect, profile selection, Show window, Quit. Closing the window hides it to the tray.
   Template icons for the macOS menu bar.
8. **Settings**: theme (`system`|`light`|`dark`) via the window theme, launch at login,
   connect on startup, auto-reconnect, openconnect path, extra arguments (allowlisted),
   HIP script (path to `hipreport.sh`, `--csd-wrapper`), language (ru/en/uk). Changing the
   openconnect path, HIP script or extra arguments requires confirmation in a native dialog;
   values changed on disk are re-confirmed before the next elevated launch (per-field HMAC whose
   key is in the OS keystore).
9. **Security**: Tauri capabilities allow only the GpApi commands and event listening, only for
   the main window with local content (the SAML window gets no IPC); `withGlobalTauri: false`;
   strict CSP; navigation of the main window locked to the app origin; validation of all command
   input; https portals only; no secrets in logs (mask cookies/passwords); single app instance
   (`tauri-plugin-single-instance`).
10. **Migration**: on first start, `settings.json` and `profiles.json` of the Electron version are
   copied once; saved passwords are re-entered; sensitive settings are re-confirmed once.

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
  openconnectFound: boolean; openconnectPath?: string; openconnectTrusted?: boolean;
  appVersion: string; shouldUseDarkColors: boolean; }

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
  window: { minimize(): void; close(): void; }   // close = hide to tray
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

IPC channels are named `gp:<area>:<action>` and listed as constants in `src/shared/ipc.ts`. In the
Tauri app each method is a command named `<area>_<action>` in snake_case (e.g. `vpn_connect
{profileId, opts?}`), events keep the `gp:<area>:<action>` names (`gp:vpn:state`, `gp:vpn:prompt`,
`gp:logs:line`, `gp:system:themeChanged`); errors are strings in the
`[field:<f>][code:<c>] <message>` format read by `parseIpcError` (`src/shared/validation.ts`).

## UI (renderer / "frontend")
- Window 380×600 (min. 360×520): Windows — native title bar, macOS — overlay title bar
  (`titleBarStyle: Overlay`, hidden title, traffic lights, draggable header drawn by the UI),
  Linux — native frame.
- **Main screen**: large Connect/Disconnect toggle with animated state, profile dropdown, gateway
  selection (auto/list), status card (IP, gateway, connection duration), clear errors with an
  action ("Set openconnect path", "Retry").
- **Authentication dialog**: username/password, OTP, choice from a list; "remember password".
- **Profiles**: list, add/edit/delete, portal URL validation.
- **Settings**: theme, launch at login, auto-reconnect, openconnect path, extra arguments, language.
- **Log**: live log with auto-scroll, copy, "open log folder".
- **Onboarding**: no profiles → "Add a portal" screen; openconnect not found → install
  instructions for the current OS (Windows: OpenConnect is bundled — reinstall/repair GP Connect or
  set the path; macOS: MacPorts; Ubuntu: apt).
- **Themes**: design tokens as CSS custom properties; light and dark themes in the Windows 11
  Fluent style (Segoe UI Variable on Windows, system-ui on macOS/Ubuntu), accent color, 8px radii,
  `system` mode follows the OS theme. Windows 11 — Mica (`window-vibrancy`, solid fallback) behind a
  transparent webview, macOS — vibrancy, Linux — opaque window.
- Accessibility: keyboard navigation, visible focus ring, aria attributes, WCAG AA contrast in
  both themes, `prefers-reduced-motion`.
- Localization: ru (default), en, uk — a plain dictionary, no heavy libraries.

## Acceptance criteria
1. `npm install && npm run typecheck && npm run lint && npm test` and
   `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings &&
   cargo test --workspace` pass; `npm run build` produces the bundles for the current OS.
2. `npm run dev` starts the app; without openconnect it shows the install screen and does not crash.
3. The prelogin parser, SAML cookie capture, openconnect output parser and the state machine are
   covered by fixture-based unit tests (no real portal needed), shared by cargo tests and Vitest.
4. Passwords/cookies never reach the log, nor the renderer after submission.
5. The theme switches system/light/dark instantly, without restart; both themes meet AA contrast.
6. `npm run dist:win|dist:mac|dist:linux` build the NSIS installer (with the helper and bundled
   OpenConnect), the dmg and the deb + AppImage via the Tauri bundler.
7. The README (English) covers installing openconnect on each OS, privileges, building, releasing
   and known limitations.
