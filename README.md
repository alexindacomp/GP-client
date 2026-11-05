# GP Connect

A cross-platform (Windows 10/11, macOS, Ubuntu/Debian) client for **Palo Alto GlobalProtect** VPN
and a friendlier replacement for the stock client. Connect in one or two clicks, with clear
statuses and error messages, light and dark themes, and a tray / menu bar icon. The UI is
available in Russian, English and Ukrainian (switch in Settings).

GP Connect does not implement the tunnel itself: it drives the external
[OpenConnect](https://www.infradead.org/openconnect/) program (version **9 or newer**,
`--protocol=gp`). On Windows OpenConnect is bundled into the installer; on macOS and Linux it is
installed from the system package manager (see [OpenConnect](#openconnect)).

The app is built with [Tauri 2](https://tauri.app/) (Rust backend, the OS's own WebView, React UI).
The Windows installer is about **5.7 MB including OpenConnect** (the previous Electron version was
121 MB).

## Download

| OS      | Package                                                                                                                                   | Notes                           |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| Windows | [`GP-Connect-Setup-x64.exe`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-Setup-x64.exe)                 | Installer, includes OpenConnect |
| macOS   | [`GP-Connect-mac-arm64.dmg`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-mac-arm64.dmg)                 | Apple Silicon                   |
| macOS   | [`GP-Connect-mac-x64.dmg`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-mac-x64.dmg)                     | Intel                           |
| Linux   | [`gp-connect_amd64.deb`](https://github.com/alexindacomp/GP-client/releases/latest/download/gp-connect_amd64.deb)                         | Ubuntu / Debian (recommended)   |
| Linux   | [`GP-Connect-linux-x86_64.AppImage`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-linux-x86_64.AppImage) | Other distributions             |

There is no portable Windows build: the elevated parts must live in an administrator-only
folder (Program Files), which only the installer provides.

### Unsigned builds

The release builds are not code-signed, so browsers and the OS warn on download / first launch:

- **Windows** (SmartScreen): click **More info → Run anyway**. The installer asks for UAC because
  it installs for all users into `C:\Program Files\GP Connect`. Keep the default install folder:
  a folder outside Program Files fails the trust check (see
  [Which files may run as administrator](#which-files-may-run-as-administrator)).
- **macOS** (Gatekeeper; the app is ad-hoc signed, not notarized):
  - macOS 14 and earlier: right-click the app in Finder → **Open** → Open.
  - macOS 15 (Sequoia) and later: try to open the app once, then go to
    **System Settings → Privacy & Security → Open Anyway**.
  - Either version: `xattr -dr com.apple.quarantine "/Applications/GP Connect.app"`.
- **Linux deb** (recommended on Ubuntu): `sudo apt install ./gp-connect_amd64.deb` — pulls in
  `openconnect`, `libwebkit2gtk-4.1-0` and pkexec, and installs the polkit policy.
- **Linux AppImage**: `chmod +x GP-Connect-linux-x86_64.AppImage`, then run it. It is built on
  Ubuntu 22.04 and carries its GTK/WebKitGTK libraries (GStreamer media libraries are not
  bundled). If it refuses to start with a FUSE error, install FUSE 2
  (`sudo apt install libfuse2t64` on 24.04, `libfuse2` on 22.04). OpenConnect and the polkit
  policy are not included — install them by hand (see [OpenConnect](#openconnect) and
  [Linux: polkit policy](#linux-polkit-policy)).

What removes the download and SmartScreen warnings is a **code-signing certificate**. The release
workflow has optional Windows signing hooks that sign the app, the helper and the installer when
repository secrets are set (every signing step is skipped otherwise):

- a pfx certificate: `WINDOWS_CERTIFICATE` (base64 of the .pfx) and `WINDOWS_CERTIFICATE_PASSWORD`;
- or Azure Trusted Signing: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`, `AZURE_CERTIFICATE_PROFILE`
  (used only when `WINDOWS_CERTIFICATE` is empty).

macOS notarization is not set up.

## Features

- Portal profiles (name, portal address, username, preferred gateway, sign-in mode `auto` / `password` / `saml`).
- Sign-in method detection via `prelogin.esp`: SAML (SSO in a separate window) or username/password.
- OpenConnect MFA/OTP prompts are shown in the app window.
- Gateway selection: automatic (preferred or first) or manual.
- Auto-reconnect after a dropped connection, with 2 / 5 / 10 / 30 s delays.
- Passwords are stored only in the OS keystore (Windows Credential Manager, macOS Keychain, Linux
  Secret Service). If no keystore is available, the password is not saved at all.
- Log with secret masking (passwords and cookies are never written to the log).
- Launch at login, connect on startup, single app instance, close-to-tray.
- UI languages: Russian (default), English, Ukrainian.

## Requirements

- **Windows 10/11** (x64) with the Microsoft Edge **WebView2** runtime — preinstalled on
  Windows 11 and on up-to-date Windows 10; if it is missing, the installer downloads it.
- **macOS 10.15** or newer (arm64 or x64). Per-profile isolation of SAML sessions needs macOS 14
  (see [Known limitations](#known-limitations)).
- **Linux** x86_64 with **WebKitGTK 4.1** (Ubuntu 22.04+, Debian 12+), polkit (`pkexec`) and
  OpenConnect. The GNOME tray icon is shown by the AppIndicator extension, enabled by default on
  Ubuntu.

## OpenConnect

GP Connect looks for `openconnect` in this order:

1. the path set in the app's Settings (it must point at a file named `openconnect` / `openconnect.exe`);
2. the binary bundled with the app: `<resources>/bin/<platform>/openconnect[.exe]` (Windows only in
   practice);
3. directories in `PATH`;
4. standard install locations (`C:\Program Files\OpenConnect[-GUI]`, `/opt/local/sbin`, `/opt/local/bin`,
   `/usr/sbin`, `/usr/bin`, etc.).

A **trusted** binary wins over an untrusted one regardless of order (see
[Which files may run as administrator](#which-files-may-run-as-administrator)). An untrusted binary
is still reported as found, but connecting with it is refused with a `PRIVILEGES_DENIED` error that
explains why.

### Windows 10/11 — bundled, nothing to install

The installer contains the official OpenConnect **v9.21** Windows build (MinGW64/GnuTLS, from the
OpenConnect project's GitLab CI release job, pinned by SHA-256) together with the **Wintun** driver
DLL and `vpnc-script-win.js`. They are installed to `C:\Program Files\GP Connect\bin\win32\` with
their licence texts (`licenses\`, `THIRD-PARTY-NOTICES.txt`). openconnect finds
`vpnc-script-win.js` next to itself, so no `--script` option is passed.

If the bundled copy is missing or damaged, run the installer again to repair it, or point Settings
at another `openconnect.exe` installed under Program Files.

### macOS — MacPorts

```bash
sudo port install openconnect
```

The binary lands in `/opt/local/sbin/openconnect` (or `/opt/local/bin/openconnect`) and is found
automatically. [Install MacPorts](https://www.macports.org/install.php) first if needed.

**Homebrew is not supported.** Homebrew's directories (`/opt/homebrew`, and `/usr/local` on Intel)
are owned by the user, not root, so any program running as you could replace `openconnect` (or a
library it loads) there and gain root on the next connection. GP Connect therefore refuses to run
such a binary with administrator rights. Any other OpenConnect build works as long as the file and
all its parent directories are owned by root and not writable by others. Copying the Homebrew
binary into a system directory is **not recommended**: it would still load libraries from
`/opt/homebrew`.

### Linux

- **deb**: OpenConnect is a package dependency (`Depends: openconnect, libwebkit2gtk-4.1-0,
policykit-1 | pkexec`) and is installed together with GP Connect.
- **AppImage**: install it yourself:

  ```bash
  sudo apt install openconnect
  ```

The binary is installed to `/usr/sbin/openconnect`.

## Administrator privileges and security model

OpenConnect needs administrator rights to create the VPN interface. The app itself runs
**without** elevation; only openconnect (and, on Windows, a small helper) is elevated.

| OS      | How openconnect is started                                                                                 | What the user sees                                 |
| ------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Windows | `gp-connect-helper.exe` started with UAC; it starts `openconnect.exe` and relays its I/O over a named pipe | UAC prompt on every connect                        |
| macOS   | `osascript … with administrator privileges` runs a root wrapper script (the dialog names the binary)       | Administrator password dialog on every connect     |
| Linux   | `/usr/bin/pkexec --disable-internal-agent openconnect …` (polkit policy, `auth_admin`)                     | polkit dialog on every connect (and on disconnect) |

The password / SAML cookie is passed to openconnect only via stdin (`--passwd-on-stdin`), never on
the command line.

Passwordless elevation (a `NOPASSWD` sudoers rule, `auth_admin_keep`/`yes` in polkit) is
**neither used nor recommended**: it would let any program running as the user start openconnect as
root with arbitrary options (e.g. `--script`), i.e. get root.

### Windows: the elevated helper

There is no PowerShell involved. The app starts `C:\Program Files\GP Connect\gp-connect-helper.exe`
with UAC (`ShellExecuteExW`, verb `runas`) as `gp-connect-helper.exe --config <path> --sha256 <hex>`:

- **Launch config.** The pipe name, a one-time 256-bit token, the openconnect path and argv, the HIP
  script and the app's process id are written to a new file in a fresh directory under the user's
  `%TEMP%` (protected DACL: the user, SYSTEM, Administrators). Only its SHA-256 is on the command
  line. The helper treats the file as hostile: no reparse points, size cap, hash must match, strict
  JSON schema; it then deletes the file through the handle it read.
- **Named pipe.** `\\.\pipe\gp-connect-<random>` is created by the app with a protected DACL (the
  user, SYSTEM, Administrators), remote clients rejected. Before sending the token the helper checks
  with `GetNamedPipeServerProcessId` that the pipe server is the app's pid from the config; the app
  accepts only a client that presents the token within 5 s.
- **Re-validation as administrator.** The helper repeats every check the app made: the binary must be
  `openconnect.exe` and pass the trust check, together with every `.dll`, `.exe` and `.js` next to
  it; the HIP script (if any) must be trusted and have an allowed extension (`.js`, `.cmd`, `.bat`,
  `.exe`); the argv must have exactly the shape the app builds, with only allowlisted extra options
  and one `https://` server.
- **Hardened process.** DLLs are loaded only from System32 and the install folder (never from the
  current directory or `PATH`; also enforced for static imports by a link flag); remote and
  low-integrity images are refused; the working directory is System32.
- **Minimal environment.** openconnect gets an environment built from system APIs only (none of the
  user-writable `HKCU\Environment` values such as `PATH`, `TEMP`, `OPENSSL_CONF`, `*_PROXY`), and a
  private temp directory `C:\ProgramData\GP-Connect-<random>` accessible only to SYSTEM and
  Administrators (removed afterwards).
- **Relay and stop.** stdin/stdout/stderr and the exit code are relayed over the pipe. Disconnecting
  sends Ctrl+C to openconnect's hidden console so `vpnc-script-win.js` can restore routes and DNS;
  if openconnect has not exited within 10 s, it is killed. If the app closes the pipe (e.g. it
  crashes), the helper kills openconnect, so it never outlives the app.

The installer installs for all users (`perMachine`), so the app, the helper and the bundled
OpenConnect are protected from tampering by Program Files ACLs.

### Which files may run as administrator

Before every elevated launch the app checks (uncached) the openconnect binary and the HIP script
(`--csd-wrapper`):

- **Linux / macOS**: the path is resolved to its real location (symlinks followed); the file and
  **all** its parent directories must be owned by root and not writable by group or others.
- **Windows**: the real path must be inside a Program Files directory registered in
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` (environment variables such as `%ProgramFiles%`
  are not used, because any user process can change them; the Windows directory is not accepted,
  since it contains user-writable folders such as `C:\Windows\Temp`). The owner and DACL of the
  file and of every parent up to Program Files are read natively (`GetNamedSecurityInfoW`, by SID,
  independent of the system language): the owner must be SYSTEM, Administrators or
  TrustedInstaller, and only they may have write rights. The same applies to every `.dll`, `.exe`
  and `.js` in openconnect's folder.
- **macOS, bundled binary**: not supported (an app dragged into `/Applications` is owned by the
  user). Use openconnect from MacPorts.

### Sensitive settings

Changing the openconnect path, the HIP script or the extra arguments in Settings requires
confirmation in a native dialog that shows the new value (Cancel is the default button). Confirmed
values are remembered as a per-field HMAC-SHA256 whose key is kept in the OS keystore; if these
settings are changed behind the app's back (e.g. by editing `settings.json`), the confirmation
dialog appears again before the next openconnect launch. Without an OS keystore, confirmation is
asked once per app run.

Extra openconnect arguments are restricted to an allowlist of safe options:
`-v`/`--verbose`, `-q`/`--quiet`, `--timestamp`, `--no-dtls`, `--disable-ipv6`,
`--servercert=pin-sha256:<base64>`, `--mtu=N`, `--base-mtu=N`, `--reconnect-timeout=N`,
`--force-dpd=N`, `--dtls-ciphers=…`, `--dtls12-ciphers=…`. Options that run commands, read files,
redirect traffic or weaken certificate checks (`--script`, `--config`, `--cafile`, `--proxy`,
`--resolve`, `--no-system-trust`, etc.) are rejected, because openconnect runs as root. The list is
validated on input, when `settings.json` is read from disk, before every launch and — on Windows —
again by the elevated helper.

### Linux: polkit policy

The `.deb` package installs `build/linux/com.gpconnect.openconnect.policy` into
`/usr/share/polkit-1/actions/com.gpconnect.openconnect.policy` (actions for `/usr/sbin/openconnect`
and `/usr/bin/openconnect`). The policy uses `auth_admin`: the administrator password is asked on
every launch. `auth_admin_keep` is deliberately not used — cached authorization would let any user
process run openconnect as root with any options for several minutes. For the AppImage, install
the policy manually (from a checkout of this repository):

```bash
sudo install -m 0644 build/linux/com.gpconnect.openconnect.policy /usr/share/polkit-1/actions/
```

Without the policy `pkexec` behaves the same (the default action also requires a password), only
the dialog text is less clear.

### Residual risks

Protection against malicious code already running as the same user is out of scope (it can read
the user's memory and files anyway), but the known gaps are:

- **Windows**: while the UAC dialog is open, a process of the same user can read the launch config
  and race the helper for the pipe; the server-pid and token checks stop it from impersonating
  either side, but it can still break the connection attempt.
- **macOS**: the wrapper's directory is root-owned (0711), but the FIFOs for openconnect's
  input/output/control must be owned by the user, so another process of the same user can open
  them, read openconnect's output, write to its input or stop the connection. The password/cookie
  travels through this channel.
- **Linux**: a process started via `pkexec` is owned by root, so disconnecting asks for the
  password again (`pkexec kill -s INT <pid>`). Removing this would require a separate system
  service, which is out of scope.

## Where data is stored

The app identifier is `com.gpconnect.client`:

| OS      | Settings and profiles                                 | Log                                         | SAML sessions                                        |
| ------- | ----------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------- |
| Windows | `%APPDATA%\com.gpconnect.client\`                     | `%LOCALAPPDATA%\com.gpconnect.client\logs\` | `%LOCALAPPDATA%\com.gpconnect.client\saml\<profile>` |
| macOS   | `~/Library/Application Support/com.gpconnect.client/` | `~/Library/Logs/com.gpconnect.client/`      | WebKit data store per profile (macOS 14+)            |
| Linux   | `~/.local/share/com.gpconnect.client/`                | `~/.local/share/com.gpconnect.client/logs/` | `~/.local/share/com.gpconnect.client/saml/<profile>` |

- `settings.json` — settings; `profiles.json` — profiles (no passwords);
  `confirmed-settings.json` — fingerprints of confirmed sensitive settings. Written atomically with
  mode 0600.
- `gp-connect.log` — log (rotated at 5 MB; the last 2000 lines are kept in memory).
- Saved passwords and the confirmation HMAC key are in the OS keystore under the service name
  `com.gpconnect.client` (Credential Manager / Keychain / Secret Service).
- A profile's SAML session data is cleared when the profile is removed.

### Migrating from the Electron version

On the first start, if the old data folder exists (`%APPDATA%\GP Connect`,
`~/Library/Application Support/GP Connect`, `~/.config/GP Connect`) and the new one has no
`settings.json`, `settings.json` and `profiles.json` are copied once (existing files are never
overwritten). Passwords saved by the Electron version cannot be decrypted and must be entered
again; non-default sensitive openconnect settings (path, HIP script, extra arguments) are
re-confirmed once before the first connection. The old folder is left untouched.

## Development

Prerequisites:

- **Node.js 22** (≥ 22.12) and npm.
- **Rust stable** with clippy and rustfmt — `rust-toolchain.toml` selects it automatically under
  rustup (minimum Rust 1.88).
- [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your OS:
  - **Windows**: Microsoft C++ Build Tools (MSVC, "Desktop development with C++") and WebView2.
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`).
  - **Linux (Ubuntu/Debian)**: as in CI:

    ```bash
    sudo apt install build-essential libwebkit2gtk-4.1-dev libgtk-3-dev \
      libayatana-appindicator3-dev librsvg2-dev libssl-dev patchelf
    ```

```bash
npm install                   # JS dependencies (incl. the Tauri CLI)
npm run dev                   # run the app (Vite dev server with HMR + tauri dev)
npm run preview:web           # UI only, in a browser, with a mock backend
npm run build                 # tauri build (all bundles for the current OS)

npm test                      # Vitest: src/shared and the React UI
npm run typecheck             # TypeScript
npm run lint                  # ESLint
cargo test --workspace        # Rust tests (gp-core, gp-elevate, gp-helper, src-tauri)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

`src-tauri` needs WebKitGTK to build on Linux; where it is not available (e.g. WSL), run
`cargo test -p gp-core -p gp-elevate -p gp-helper`. The Rust and Vitest tests share the fixtures in
`fixtures/` and need no network or real portal.

Building distributables (output in `target/release/bundle/`):

```bash
npm run dist:win              # Windows: fetches OpenConnect, builds the helper, NSIS installer
npm run dist:mac              # macOS: dmg (build on macOS)
npm run dist:linux            # Linux: deb and AppImage
```

Windows-specific steps (run automatically by `dist:win`; `dev` and `build` run `prepare:helper`):

- `npm run fetch:openconnect:win` — downloads the pinned OpenConnect v9.21 build and 7-Zip,
  verifies their SHA-256 (hard fail on mismatch), unpacks it and stages `openconnect.exe`, the DLLs,
  `wintun.dll`, `vpnc-script-win.js` and licences into `src-tauri/resources/bin/win32/`.
- `npm run prepare:helper` — builds `crates/gp-helper` and stages it as the Tauri sidecar
  `src-tauri/binaries/gp-connect-helper-x86_64-pc-windows-msvc.exe` (no-op on other OSes).

`npm run icons` regenerates the tray and app icons.

### Releasing

Bump `version` in `package.json` (and the workspace version in `Cargo.toml`), then push a tag
`v<version>`:

```bash
git tag v0.1.1
git push origin v0.1.1
```

`.github/workflows/release.yml` checks that the tag equals `v` + the `package.json` version, creates
the GitHub Release, runs the tests and builds Windows (NSIS), macOS (arm64 and x64 dmg) and Linux
(deb + AppImage, on Ubuntu 22.04), then uploads them under the stable names from the
[Download](#download) table. `.github/workflows/ci.yml` runs typecheck, lint, Vitest, `cargo fmt`,
`cargo clippy -D warnings` and `cargo test --workspace` on Linux, Windows and macOS for every push
and pull request.

### Layout

```
Cargo.toml            Rust workspace (gp-core, gp-elevate, gp-helper, src-tauri)
crates/gp-core/       pure logic, no GUI deps: prelogin, SAML result parsing, openconnect lookup /
                      trust check / argv / output parser, VPN engine (state machine, reconnect),
                      settings & profiles stores, validation, logging with masking, tray labels
crates/gp-elevate/    elevation: Linux pkexec, macOS osascript wrapper, Windows helper client,
                      helper wire protocol, native Windows ACL probe
crates/gp-helper/     gp-connect-helper.exe — the elevated Windows helper
src-tauri/            Tauri app: commands, events, main and SAML windows, tray, keystore,
                      migration, tauri*.conf.json, capabilities/
src/shared/           TypeScript IPC contract (ipc.ts) and input validation
src/renderer/         React UI; bridge/tauri.ts implements window.gp; i18n/ translations;
                      preview/ browser preview with a mock backend
fixtures/             test data shared by cargo tests and Vitest
scripts/              fetch-openconnect-win, prepare-helper, generate-icons
build/linux/          polkit policy
build/win32/licenses/ licence texts shipped with the bundled OpenConnect
resources/            app and tray icons
docs/                 SPEC.md, ARCHITECTURE-TAURI.md
.github/workflows/    ci.yml, release.yml
```

## Known limitations

- **macOS and Linux builds have not yet been tested manually** on real systems; elevated launching
  on all platforms (UAC helper, `osascript`, `pkexec`) is not covered by end-to-end tests.
- **SAML**: the result is read from the `<saml-auth-status>` HTML comment on every OS; the
  GlobalProtect response headers (`saml-auth-status`, `prelogin-cookie`, …) are captured only on
  Windows (WebView2). Portals that deliver the result only in headers therefore work only on
  Windows.
- **SAML on macOS 13 and earlier**: per-profile session isolation is unavailable; the SAML window
  uses the app's default WebKit data store.
- SAML runs in an embedded window. IdPs that require the system browser or a device certificate
  (e.g. Okta FastPass, Microsoft Entra with device compliance) may not work.
- **HIP (Host Information Profile)** is not implemented in the app itself. If the portal requires a
  HIP report, set the path to a `hipreport.sh` script (from the OpenConnect sources; on Windows,
  `hipreport.js`) in Settings — it is passed to openconnect as `--csd-wrapper`.
- Client-certificate and Kerberos authentication are not supported.
- Prelogin is performed against the portal only (`/global-protect/prelogin.esp`); connecting
  directly to a gateway without a portal is not supported.
- Traffic statistics (rx/tx) are not shown.
- If the server certificate fails verification, the connection is refused. To trust the server,
  add `--servercert=pin-sha256:…` to the extra arguments.
- The gateway list becomes known only after the first authentication against the portal.
- Linux: the administrator password is asked on connect and on disconnect.
- macOS: OpenConnect from Homebrew is not supported.
- Builds are not code-signed (see [Unsigned builds](#unsigned-builds)).

## License

[MIT](LICENSE). The bundled Windows OpenConnect and its libraries are under their own licences
(LGPL/GPL, Wintun prebuilt binaries licence); see `bin\win32\THIRD-PARTY-NOTICES.txt` in the
install folder.
