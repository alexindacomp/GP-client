# GP Connect

A cross-platform (Windows 11, macOS, Ubuntu) client for **Palo Alto GlobalProtect** VPN and a
friendlier replacement for the stock client. Connect in one or two clicks, with clear statuses
and error messages, light and dark themes, and a tray / menu bar icon. The UI is available in
Russian, English and Ukrainian (switch in Settings).

GP Connect does not implement the tunnel itself: it drives the external
[OpenConnect](https://www.infradead.org/openconnect/) program (version **9 or newer**, `--protocol=gp`).
OpenConnect must therefore be installed separately (see below) or bundled into the build.

## Download

| OS      | Package                                                                                                                                   | Notes                     |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| Windows | [`GP-Connect-Setup-x64.exe`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-Setup-x64.exe)                 | Installer (recommended)   |
| Windows | [`GP-Connect-Portable-x64.exe`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-Portable-x64.exe)           | Portable, no installation |
| macOS   | [`GP-Connect-mac-arm64.dmg`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-mac-arm64.dmg)                 | Apple Silicon             |
| macOS   | [`GP-Connect-mac-x64.dmg`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-mac-x64.dmg)                     | Intel                     |
| Linux   | [`GP-Connect-linux-x86_64.AppImage`](https://github.com/alexindacomp/GP-client/releases/latest/download/GP-Connect-linux-x86_64.AppImage) | Any distribution          |
| Linux   | [`gp-connect_amd64.deb`](https://github.com/alexindacomp/GP-client/releases/latest/download/gp-connect_amd64.deb)                         | Ubuntu / Debian           |

The builds are not code-signed, so the OS will warn on first launch:

- **Windows** (SmartScreen): click **More info → Run anyway**. The installer asks for UAC because
  it installs for all users into Program Files.
- **macOS** (Gatekeeper; the app is ad-hoc signed, not notarized):
  - macOS 14 and earlier: right-click the app in Finder → **Open** → Open.
  - macOS 15 (Sequoia) and later: try to open the app once, then go to
    **System Settings → Privacy & Security → Open Anyway**.
  - Either version: `xattr -dr com.apple.quarantine "/Applications/GP Connect.app"`.
- **Linux deb** (recommended on Ubuntu): `sudo apt install ./gp-connect_amd64.deb` — pulls in
  `openconnect`, installs the polkit policy, the `gp-connect` command and an AppArmor profile.
- **Linux AppImage**: `chmod +x GP-Connect-linux-x86_64.AppImage`. It needs FUSE 2
  (`sudo apt install libfuse2t64` on 24.04, `libfuse2` on 22.04), and the polkit policy must be
  installed by hand (see [Linux: polkit policy](#linux-polkit-policy)). On Ubuntu 24.04+ AppArmor
  may block Electron AppImages from starting — prefer the deb there.

The portable Windows build does not install into Program Files, so its bundled openconnect (if
any) will not pass the trust check (see [Which files may run as administrator](#which-files-may-run-as-administrator));
use it with OpenConnect installed under Program Files.

## Features

- Portal profiles (name, portal address, username, preferred gateway, sign-in mode `auto` / `password` / `saml`).
- Sign-in method detection via `prelogin.esp`: SAML (SSO in a separate window) or username/password.
- OpenConnect MFA/OTP prompts are shown in the app window.
- Gateway selection: automatic (preferred or first) or manual.
- Auto-reconnect after a dropped connection, with 2 / 5 / 10 / 30 s delays.
- Passwords are stored only encrypted by the OS keystore (`safeStorage`: DPAPI on Windows,
  Keychain on macOS, Secret Service / KWallet on Linux). If no OS keystore is available,
  the password is not saved at all.
- Log with secret masking (passwords and cookies are never written to the log).
- UI languages: Russian (default), English, Ukrainian.

## Installing OpenConnect

GP Connect looks for `openconnect` in this order:

1. the path set in the app's Settings;
2. a binary bundled with the build: `resources/bin/<platform>/openconnect[.exe]` (`win32`, `darwin`, `linux`);
3. directories in `PATH`;
4. standard install locations (`C:\Program Files\OpenConnect-GUI`, `/opt/local/sbin`,
   `/usr/sbin`, `/usr/bin`, etc.).

The first **trusted** binary is used (see [Which files may run as administrator](#which-files-may-run-as-administrator)).
An untrusted binary is still reported as found, but connecting with it is refused with a
`PRIVILEGES_DENIED` error that explains why.

### Windows 10/11

Recommended: the **OpenConnect-GUI** installer from
<https://gitlab.com/openconnect/openconnect-gui/-/releases>. It installs `openconnect.exe`
together with the **Wintun** driver (`wintun.dll`) and `vpnc-script-win.js` into Program Files —
all of which are needed to create the tunnel. You do not need to run the OpenConnect-GUI
interface itself.

Alternative: look for a package with `winget` (PowerShell) and install the one you pick:

```powershell
winget search openconnect
```

OpenConnect must end up under `Program Files`: binaries in the user profile
(`%LOCALAPPDATA%`, Downloads, etc.) will not be run.

### macOS

**Homebrew is not supported.** Homebrew's directories (`/opt/homebrew`, and `/usr/local/bin` on
Intel) are owned by the user, not root, so any program running as you could silently replace
`openconnect` (or a library it loads) there and gain root on the next connection. GP Connect
therefore refuses to run such a binary with administrator rights.

Use [MacPorts](https://www.macports.org/install.php) instead, which installs into the
root-owned `/opt/local`:

```bash
sudo port install openconnect
```

The binary lands in `/opt/local/sbin/openconnect` (or `/opt/local/bin/openconnect`) and is found
automatically. Any other OpenConnect build also works, as long as the file, all its parent
directories and every library it loads are owned by root and not writable by regular users.
Copying the Homebrew binary into a system directory is **not recommended**: it would still load
libraries from `/opt/homebrew`.

### Ubuntu (24.04 LTS and newer)

```bash
sudo apt update
sudo apt install openconnect
```

The binary is installed to `/usr/sbin/openconnect`. `pkexec` (polkit) is preinstalled on Ubuntu
Desktop. The GNOME tray icon is shown by the AppIndicator extension, enabled by default on Ubuntu.

## Administrator privileges

OpenConnect needs administrator rights to create the VPN interface. The app itself runs
**without** elevation; only the `openconnect` process is elevated.

| OS      | How openconnect is started                                                                                                             | What the user sees                                       |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Windows | UAC prompt, then a hidden elevated PowerShell helper starts `openconnect.exe` and relays its input/output to the app over a named pipe | UAC prompt on every connect                              |
| macOS   | System dialog `osascript … with administrator privileges` (it shows the path of the binary being run)                                  | Administrator password dialog on every connect           |
| Linux   | `pkexec openconnect …`                                                                                                                 | polkit dialog on every connect (and possibly disconnect) |

The password / SAML cookie is passed to openconnect only via stdin (`--passwd-on-stdin`), never
on the command line.

Passwordless elevation (a `NOPASSWD` sudoers rule, `auth_admin_keep`/`yes` in polkit) is
**neither used nor recommended**: it would let any program running as the user start openconnect
as root with arbitrary options (e.g. `--script`), i.e. get root.

### Which files may run as administrator

Before every elevated launch the main process checks the openconnect binary and the HIP script
(`--csd-wrapper`):

- **Linux / macOS**: the path is resolved to its real location (symlinks followed); the file and
  **all** its parent directories must be owned by root and not writable by group or others.
- **Windows**: the real path must be inside a Program Files directory registered in
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` (environment variables such as
  `%ProgramFiles%`/`%SystemRoot%` are not used, because any user process can change them; the
  Windows directory is not accepted at all, since it contains user-writable folders such as
  `C:\Windows\Temp`). In addition, the ACLs of the file and every parent up to Program Files are
  checked (by SID, independent of the system language): the owner must be SYSTEM, Administrators
  or TrustedInstaller, and only they may have write/modify rights. The check runs PowerShell from
  the hard-coded path `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; if Windows is
  not installed on `C:`, elevation is refused. The GP Connect installer installs the app for all
  users (`perMachine`), so the bundled `resources\bin\win32\openconnect.exe` is also protected
  from tampering.
- **macOS, bundled binary**: not supported. An app dragged from the dmg into `/Applications` is
  owned by the user (and `/Applications` is writable by the `admin` group), so
  `resources/bin/darwin/openconnect` will fail the check. Use openconnect from MacPorts.

The Settings path may only point at the openconnect binary itself (file name `openconnect` or
`openconnect.exe`).

Changing the openconnect path, the HIP script or the extra arguments in Settings requires
confirmation in a system dialog that shows the new value. Confirmed values are remembered (as an
HMAC whose key is protected by the OS keystore via `safeStorage`); if these settings are changed
behind the app's back (e.g. by editing `settings.json`), the confirmation dialog appears again
before the next openconnect launch. Without an OS keystore, confirmation is asked once per app run.

Extra openconnect arguments are restricted to an allowlist of safe options:
`-v`/`--verbose`, `-q`/`--quiet`, `--timestamp`, `--no-dtls`, `--disable-ipv6`,
`--servercert=pin-sha256:<base64>`, `--mtu=N`, `--base-mtu=N`, `--reconnect-timeout=N`,
`--force-dpd=N`, `--dtls-ciphers=…`, `--dtls12-ciphers=…`. Options that run commands, read
files, redirect traffic or weaken certificate checks (`--script`, `--config`, `--cafile`,
`--proxy`, `--resolve`, `--no-system-trust`, etc.) are rejected, because openconnect runs as root.
The list is validated on input, when `settings.json` is read from disk, and before every launch.

### Linux: polkit policy

The `.deb` package installs `build/linux/com.gpconnect.openconnect.policy` into
`/usr/share/polkit-1/actions/` (actions for `/usr/sbin/openconnect` and `/usr/bin/openconnect`).
The policy uses `auth_admin`: the administrator password is asked on every launch.
`auth_admin_keep` is deliberately not used — cached authorization would let any user process run
openconnect as root with any options for several minutes. For the AppImage, install the policy
manually:

```bash
sudo install -m 0644 build/linux/com.gpconnect.openconnect.policy /usr/share/polkit-1/actions/
```

Without the policy `pkexec` behaves the same (the default action also requires a password), only
the dialog text is less clear.

A process started via `pkexec` is owned by root, so disconnecting asks for the password again
(`pkexec kill -s INT <pid>`). This is a known inconvenience; removing it would require a separate
system service, which is currently out of scope.

### macOS

The helper script started through the administrator dialog creates its own root-owned directory
with FIFOs for openconnect's input/output and a control channel. The control channel lets the app
stop openconnect cleanly on disconnect without asking for the password again.

Residual risk: the FIFOs are owned by the user (otherwise the app could not use them), so another
process of the same user can open them, read openconnect's output, write to its input or stop the
connection. The password/cookie travels through this channel. Protection against malicious code
already running as the user is out of scope: such code can read the user's memory and files anyway.

### Windows

The installer installs GP Connect for all users into `Program Files`; choosing a different
install directory is disabled (`allowToChangeInstallationDirectory: false`), because the trust
check only accepts directories writable by administrators alone.

The app is built with `requestedExecutionLevel: asInvoker` and does not need "Run as
administrator". A UAC prompt appears when connecting. Parameters for the helper process (pipe
name, one-time token, command) are passed through a temporary file in the user profile; the
elevated process verifies its SHA-256 and deletes the file. A pipe client that does not send the
correct token within 5 seconds is disconnected, and the app keeps waiting for the real helper.
For `Add-Type` (needed to send Ctrl+C correctly) the elevated process uses a temporary directory
under `ProgramData` accessible only to SYSTEM and Administrators, not the user's `%TEMP%`.

Residual risk: while the UAC dialog is open, the token file is readable by processes of the same
user; such a process could connect to the pipe first, obtain the password/cookie or break the
connection. As on macOS, protection against malicious code running as the user is out of scope.
Disconnecting sends Ctrl+C to the helper's console so that `vpnc-script` can restore routes and
DNS; if openconnect has not exited within 10 seconds, it is terminated forcibly.

## Development

Requires Node.js ≥ 22.12.

```bash
npm install          # dependencies
npm run dev          # run in development mode (electron-vite, HMR for the UI)
npm run typecheck    # type checking (main/preload and renderer)
npm run lint         # ESLint
npm test             # Vitest unit tests (no network, fixture-based)
npm run build        # build into out/
npm run icons        # regenerate tray and app icons
```

Building distributables (electron-builder, output in `dist/`; targets are defined in
`electron-builder.yml`):

```bash
npm run dist:win     # Windows: NSIS installer and portable exe
npm run dist:mac     # macOS: dmg (arm64, x64) — build on macOS
npm run dist:linux   # Linux: AppImage and deb
```

To bundle openconnect, put the binary (and on Windows also `wintun.dll`, `vpnc-script-win.js`
and the required DLLs) into `resources/bin/<platform>/` before building.

### Releasing

Push a tag `vX.Y.Z`: the GitHub Actions workflow `.github/workflows/release.yml` builds all
platforms and attaches the packages to the GitHub Release. The CI workflow
`.github/workflows/ci.yml` runs on every push and pull request.

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Layout

```
src/shared/      IPC contract and shared types (src/shared/ipc.ts)
src/preload/     contextBridge: window.gp (type declaration: src/preload/gp-api.d.ts)
src/main/        main process:
  auth/          prelogin (XML + HTTP), SAML window and cookie extraction
  openconnect/   binary lookup, trust check, arguments, output parsing
  process/       launching openconnect with elevation (pkexec / osascript / UAC)
  vpn/           VpnEngine — state machine, auto-reconnect
  store/         settings and profiles, input validation
  logging/       ring-buffer log, log file, secret masking
src/renderer/    React UI (translations: src/renderer/src/i18n/)
build/linux/     polkit policy and deb package scripts
resources/       tray and app icons, bundled binaries
```

### Where data is stored

In Electron's `userData` directory (`%APPDATA%\GP Connect`, `~/Library/Application Support/GP Connect`,
`~/.config/GP Connect`):

- `settings.json` — settings;
- `profiles.json` — profiles and encrypted passwords;
- `logs/gp-connect.log` — log (rotated at 5 MB; the last 2000 lines are kept in memory);
- SAML window sessions — in separate `persist:saml-<profile id>` partitions.

## Known limitations

- **HIP (Host Information Profile)** is not implemented in the app itself. If the portal requires
  a HIP report, set the path to a `hipreport.sh` script (from the OpenConnect sources; on Windows,
  `hipreport.js`) in Settings — it is passed to openconnect as `--csd-wrapper`.
- Client-certificate and Kerberos authentication are not supported.
- SAML runs in an embedded window. IdPs that require the system browser or a device certificate
  (e.g. Okta FastPass, Microsoft Entra with device compliance) may not work.
- Prelogin is performed against the portal only (`/global-protect/prelogin.esp`); connecting
  directly to a gateway without a portal is not supported.
- Traffic statistics (rx/tx) are not shown.
- If the server certificate fails verification, the connection is refused. To trust the server,
  add `--servercert=pin-sha256:…` to the extra arguments.
- The gateway list becomes known only after the first authentication against the portal.
- Linux: the administrator password is asked on connect and on disconnect (see above).
- macOS: OpenConnect from Homebrew is not supported (see [Installing OpenConnect](#installing-openconnect)).
- Elevated launching on Windows and macOS (UAC bridge, `osascript`) is not covered by automated
  tests and needs manual verification on real systems.

## License

[MIT](LICENSE)
