# GP Connect on Tauri 2 — architecture

Status: **implemented**. The Electron implementation has been removed; GP Connect is a Tauri 2 app
on **Windows 10/11 (x64), macOS (arm64 + x64) and Linux (Ubuntu/Debian x64)** with the same
features, UI and security model as before and a much smaller footprint (Windows installer about
5.7 MB including OpenConnect, versus 121 MB for Electron). Functional requirements and the UI
contract are in [SPEC.md](SPEC.md); user-facing details are in the [README](../README.md).

## Repository layout

```
Cargo.toml                 Rust workspace (members below), shared lints, release profile
crates/gp-core/            Pure Rust logic. NO tauri, NO GUI deps → `cargo test` works on any OS
                           (incl. WSL without WebKitGTK). Optional `http` feature: reqwest/rustls.
crates/gp-elevate/         Privilege elevation: Linux pkexec, macOS osascript wrapper, Windows
                           client of the elevated helper, helper wire protocol, native Windows
                           ACL probe, explicit security descriptors. Depends on gp-core.
crates/gp-helper/          Windows elevated helper binary (gp-connect-helper.exe), started via
                           UAC (ShellExecuteExW "runas"). Logic is platform-independent and tested
                           everywhere; only the pipe client, console Ctrl+C and process flags are
                           Windows-specific.
src-tauri/                 Tauri 2 app crate (binary `gp-connect`): commands, events, main and SAML
                           windows, tray, keystore, Electron data migration, bundling config
                           (tauri.conf.json + tauri.windows.conf.json), capabilities/.
src/renderer/              React UI; `window.gp` is implemented by src/renderer/src/bridge/tauri.ts
                           on top of @tauri-apps/api. preview/ = browser preview with a mock GpApi.
src/shared/                TS contract (ipc.ts) + validation for the renderer.
fixtures/                  Shared test data (openconnect transcripts, prelogin XML, SAML HTML,
                           validation cases) used by BOTH cargo tests and vitest.
scripts/                   fetch-openconnect-win.mjs, prepare-helper.mjs, generate-icons.mjs.
build/linux/               polkit policy (installed by the deb).
build/win32/licenses/      licence texts shipped with the bundled OpenConnect.
```

App identifier: **`com.gpconnect.client`** (data directories, keystore service name).

## Contract between renderer and backend

The TypeScript `GpApi` interface in `src/shared/ipc.ts` is the single UI contract. Each method maps
1:1 to a Tauri command (snake_case of `area_action`) and each event keeps its `gp:<area>:<action>`
name:

| GpApi | Tauri command / event |
|---|---|
| `profiles.list/save/remove` | `profiles_list`, `profiles_save {profile, password?}`, `profiles_remove {id}` |
| `vpn.connect/disconnect/getState/answerPrompt/getPendingPrompts` | `vpn_connect {profileId, opts?}`, `vpn_disconnect`, `vpn_get_state`, `vpn_answer_prompt {id, value}`, `vpn_get_pending_prompts` |
| `vpn.onState` / `vpn.onPrompt` | events `gp:vpn:state` (VpnState), `gp:vpn:prompt` (AuthPrompt) |
| `logs.get/openFolder`, `logs.onLine` | `logs_get`, `logs_open_folder`, event `gp:logs:line` |
| `settings.get/set` | `settings_get`, `settings_set {patch}` |
| `system.info/openExternal`, `system.onThemeChange` | `system_info`, `system_open_external {url}`, event `gp:system:themeChanged` (bool dark) |
| `window.minimize/close` | `window_minimize`, `window_close` (close = hide to tray) |

* JSON field names are camelCase exactly as in `src/shared/ipc.ts` (`#[serde(rename_all = "camelCase")]`).
* Arguments arrive as raw JSON and are validated with the gp-core validators.
* Errors: commands return `Err(String)` in the marker format `[field:<f>][code:<c>] <English message>`,
  so `parseIpcError` in `src/shared/validation.ts` works unchanged; unexpected failures are logged
  and reported as `[code:internal]` without details.
* Commands are `async` (never run on the UI thread).

### Capabilities

`src-tauri/capabilities/main.json` (identifier `main-window`) grants, **for the `main` window and
local content only**: `core:event:allow-listen`/`allow-unlisten`, `core:window:allow-start-dragging`
(macOS overlay title bar) and one `allow-<command>` permission per GpApi command. Nothing else
(no fs, shell or http plugin permissions). The SAML window is not listed in any capability and gets
**no IPC**; every command additionally re-checks that the caller is the main webview.
`app.withGlobalTauri` is `false`; a strict CSP is set in `tauri.conf.json`
(`script-src 'self'`, `connect-src 'self' ipc: http://ipc.localhost`, `object-src 'none'`,
`form-action 'none'`, …).

## gp-core (pure logic)

* `prelogin` — XML parse; URL `https://<portal>/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=…`;
  injectable transport (reqwest/rustls behind the `http` feature), manual redirects (https, same
  host, ≤ 3 hops), 1 MiB body cap.
* `saml` — load target for REDIRECT/POST bindings, result extraction from headers / HTML comment,
  cookie + username validation, trusted-source check.
* `openconnect::{locate, version, args, output_parser, trust, windows_acl, discovery_log}` —
  lookup order settings → bundled `<resources>/bin/<platform>/` → PATH → well-known dirs (trusted
  candidates win); argv builder (secrets only via stdin); CRLF-safe line splitter + parser; trust
  check (Unix ownership/mode; Windows HKLM Program Files roots + owner/DACL via an injectable probe;
  Windows install-dir check of sibling `.dll`/`.exe`/`.js`).
* `validation` — profile/settings validation, extra-args allowlist, Windows HIP script extensions.
* `vpn::{engine, backoff, errors, messages}` — state machine, reconnect backoff 2/5/10/30 s,
  graceful stop with a 10 s kill timeout, pending-prompt handling, localized messages (ru/en/uk).
* `store::{json_file (atomic, 0600), settings, profiles (+ SecretStore trait), validation,
  sensitive_settings, confirmed_settings (per-field HMAC-SHA256), confirm_dialog texts}`.
* `logging` — secret masking, ring buffer of 2000 lines, `gp-connect.log` rotated at 5 MB.
* `tray_labels`.

Async runtime: tokio. The engine depends only on traits (`ProcessSpawner`/`VpnProcess`,
`SecretStore`, `PreloginClient`, `SamlAuthenticator`, `OpenconnectProvider`, `ConfirmDialog`,
`Clock`, …), so it is tested with fakes against the shared fixtures.

## Elevation (gp-elevate, gp-helper)

`choose_elevation` picks direct spawning when the app already runs as root, otherwise:

* **Linux:** `pkexec --disable-internal-agent <trusted openconnect> …` (`/usr/bin/pkexec`, falling
  back to `/bin/pkexec`). The deb installs the polkit policy `com.gpconnect.openconnect.policy`
  (`auth_admin` for `/usr/sbin/openconnect` and `/usr/bin/openconnect`). Stop: `pkexec kill -s INT
  <pid>` (asks for the password again).
* **macOS:** `/usr/bin/osascript` with `do shell script … with administrator privileges` runs a root
  wrapper: root creates `/private/tmp/gp-connect.XXXXXXXX` (0711), user-owned FIFOs `in`/`out`/`ctl`
  (opened with `O_NOFOLLOW`), records pid and exit status; the control FIFO accepts INT/TERM/KILL for
  the openconnect pid only, so disconnect needs no second password. The dialog names the binary.
* **Windows:** `gp-connect-helper.exe` (Tauri sidecar, installed next to `gp-connect.exe` in
  `C:\Program Files\GP Connect\`), started with UAC (`ShellExecuteExW`, verb `runas`) as
  `gp-connect-helper.exe --config <path> --sha256 <hex>`. No PowerShell, `Add-Type` or
  `-EncodedCommand`.

### Helper protocol (crates/gp-elevate/src/helper_protocol.rs)

1. The app creates the named pipe `\\.\pipe\gp-connect-<32 hex>` (protected DACL: current user,
   SYSTEM, Administrators; remote clients rejected) and writes a `HelperConfig` JSON
   `{pipe, token (64 hex), binary, args, script?, serverPid}` (`deny_unknown_fields`) as a new file in
   a fresh `%TEMP%\gp-connect-<hex>` directory with a protected DACL. Pipe name and token never
   appear on a command line; only the file's SHA-256 does.
2. The helper hardens itself first (`SetDefaultDllDirectories(System32 | application dir)`,
   `SetDllDirectoryW("")`, image-load mitigation: no remote / low-label images, prefer System32;
   `/DEPENDENTLOADFLAG:0x800` for static imports; working directory System32).
3. It reads the config as hostile input (no reparse points, size cap, hash match, schema and format
   checks), deletes it through the read handle, connects to the pipe, verifies
   `GetNamedPipeServerProcessId == serverPid`, and sends `H` + token. The app accepts only a client
   that presents the token within 5 s (`HELLO_TIMEOUT`) and keeps waiting for the real helper
   otherwise.
4. Admin-side re-validation: binary is `openconnect.exe` and trusted, plus every `.dll`/`.exe`/`.js`
   in its folder; HIP script trusted with an allowed extension and identical to the argv value;
   argv exactly `--protocol=gp --os=win --passwd-on-stdin [--user=…] [--usergroup=portal:<cookie>]
   [--authgroup=…] [--csd-wrapper=<script>] <allowlisted extra args> -- https://<host[:port]>`.
5. openconnect starts in a hidden console with piped stdio and a minimal environment derived from
   system APIs only, `TEMP`/`TMP` = a new `C:\ProgramData\GP-Connect-<hex>` directory with a
   protected SYSTEM + Administrators DACL (removed afterwards).
6. Frames (`tag: u8`, `len: u32 LE`, payload): helper → app `H` token, `P` pid, `O` stdout, `E`
   stderr, `X` exit code (last), `F` fatal (code byte + message); app → helper `I` stdin, `S`
   graceful stop (`GenerateConsoleCtrlEvent` Ctrl+C), `K` kill. Closing the pipe from the app side
   kills openconnect, so it never outlives the app.

## Bundled OpenConnect (Windows)

`npm run fetch:openconnect:win` downloads the official OpenConnect **v9.21** MinGW64/GnuTLS build
from the OpenConnect project's GitLab CI release job (unpacked from the upstream NSIS installer with
7-Zip; every download pinned by SHA-256, hard fail on mismatch) and stages `openconnect.exe`, its
DLLs, `wintun.dll`, `vpnc-script-win.js`, `licenses/` and `THIRD-PARTY-NOTICES.txt` in
`src-tauri/resources/bin/win32/`. `tauri.windows.conf.json` maps that folder to the bundle resource
`bin/win32/`, i.e. **`C:\Program Files\GP Connect\bin\win32\`**; discovery finds it as
`<resource_dir>/bin/win32/openconnect.exe`. openconnect locates `vpnc-script-win.js` next to itself,
so **no `--script` option is needed** (and `--script` stays forbidden in extra args). The bundled
copy passes the trust check because the NSIS installer is `perMachine` (Program Files ACLs).

macOS and Linux use the system OpenConnect (MacPorts; distribution package / deb dependency). A
bundled binary on macOS would fail the trust check (an app in `/Applications` is user-owned).

## App shell (src-tauri)

* Plugins: `single-instance` (registered first; a second launch shows the running window),
  `autostart` (launch at login with `--hidden`), `dialog` (confirmation of sensitive settings with
  localized buttons, Cancel default), `opener` (https links and SAML popups go to the system browser).
* Secrets: `keyring` crate (Windows Credential Manager, macOS Keychain, Linux Secret Service),
  service `com.gpconnect.client`. An unavailable keystore is detected once; then passwords are not
  stored (the "remember password" flag keeps working without persisting) and the confirmed-settings
  HMAC key lives in memory only.
* Data: `app_data_dir` → `settings.json`, `profiles.json`, `confirmed-settings.json`;
  `app_log_dir` → `gp-connect.log`; `app_local_data_dir/saml/<profileId>` → SAML webview data.
* Main window: created from the `main` entry of tauri.conf.json, 380×600, min 360×520, initially
  hidden, close → hide to tray. Navigation locked to the app's own origin; `target=_blank` https
  links open in the system browser. Windows 11: Mica via `window-vibrancy` (solid theme colour as
  fallback) behind a transparent webview, native title bar. macOS: `titleBarStyle: Overlay` +
  hidden title + vibrancy (`macOSPrivateApi` for the transparent webview); the renderer draws a
  draggable header. Linux: native frame, opaque window; clipboard access enabled for WebKitGTK.
* Theme: `settings.theme` → `window.set_theme()`; OS theme changes emit `gp:system:themeChanged`
  and refresh the backdrop.
* Tray: `tray-icon` feature, localized menu (ru/en/uk) rebuilt on state/profile/language change,
  status icons, macOS template icons.

### SAML window — actual behaviour per OS

* A separate `WebviewWindow` per login with a persistent data store isolated per profile, cleared
  when the profile is removed:
  * Windows (WebView2) and Linux (WebKitGTK): `data_directory` = `<app local data>/saml/<profileId>`.
  * macOS 14+: `data_store_identifier` = the profile UUID. WKWebView ignores `data_directory`, and
    older macOS falls back to the default store shared with the main window.
* Navigation https only (top level and, where the platform reports them, frames; `about:` and the
  initial `data:` page of a POST binding excepted); popups go to the system browser; the title
  shows the current host.
* Result extraction:
  1. **All OSes:** after every top-level page load a script reads the document's comments and
     `outerHTML` via `eval_with_callback` (no IPC channel), and the `<saml-auth-status>` HTML comment
     is parsed.
  2. **Windows only:** the GlobalProtect response headers (`saml-auth-status`, `prelogin-cookie`,
     `portal-userauthcookie`, `saml-username`) of the top-level document via WebView2
     `WebResourceResponseReceived`. WebKitGTK and WKWebView headers are not read (wry does not
     expose the navigation response); portals put the same values into the HTML comment.
* Only top-level https documents from the portal host are trusted (`is_trusted_saml_source`).
  Closing the window or cancelling → `AUTH_CANCELLED`.

## Data migration from Electron

On start, if the Electron `userData` folder exists (`<config dir>/GP Connect`: `%APPDATA%\GP Connect`,
`~/Library/Application Support/GP Connect`, `~/.config/GP Connect`) and the Tauri data dir has no
`settings.json`, `settings.json` and `profiles.json` are copied (re-written atomically, 0600; existing
files are never overwritten). Electron safeStorage passwords cannot be decrypted → dropped, the user
re-enters them once (a warning with the count is logged). `confirmed-settings.json` is not copied (its
key was in safeStorage; v2 records are ignored), so non-default sensitive settings are confirmed once
more before the first elevated start.

## Packaging (tauri bundler) — stable artifact names

| OS | Artifact |
|---|---|
| Windows | `GP-Connect-Setup-x64.exe` (NSIS, `installMode: perMachine`; includes `gp-connect-helper.exe` as `externalBin` and the bundled OpenConnect + Wintun under `bin\win32\`). No portable build. |
| macOS | `GP-Connect-mac-arm64.dmg`, `GP-Connect-mac-x64.dmg` (ad-hoc signed, `signingIdentity: "-"`; `minimumSystemVersion` 10.15) |
| Linux | `GP-Connect-linux-x86_64.AppImage` (`bundleMediaFramework: false`), `gp-connect_amd64.deb` (Depends: `openconnect, libwebkit2gtk-4.1-0, policykit-1 \| pkexec`; installs the polkit policy) |

* `release.yml` (tag `v*`): checks tag == `v` + package.json version, creates the release, then per
  target runs `npm ci`, `npm test`, (Windows) `fetch:openconnect:win`, optional Windows signing
  (pfx secrets `WINDOWS_CERTIFICATE`/`WINDOWS_CERTIFICATE_PASSWORD`, or Azure Trusted Signing
  `AZURE_*` secrets via `trusted-signing-cli`), `tauri build --target … --bundles …`, renames to the
  names above and uploads them. Linux is built on Ubuntu 22.04 (oldest supported WebKitGTK 4.1).
* `ci.yml` (push/PR, Ubuntu + Windows + macOS): typecheck, lint, vitest, `build:renderer`,
  (Windows) `prepare:helper`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
  `cargo test --workspace`.
