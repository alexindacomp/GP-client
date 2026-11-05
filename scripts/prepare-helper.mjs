// Builds the Windows elevated helper (crates/gp-helper) and stages it as the Tauri sidecar
// src-tauri/binaries/gp-connect-helper-x86_64-pc-windows-msvc.exe (bundle.externalBin in
// src-tauri/tauri.windows.conf.json). The NSIS installer (perMachine) puts it next to the app:
// C:\Program Files\GP Connect\gp-connect-helper.exe. No-op on other platforms.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') process.exit(0);

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const triple = 'x86_64-pc-windows-msvc';
execFileSync('cargo', ['build', '--release', '-p', 'gp-helper', '--target', triple], {
  cwd: root,
  stdio: 'inherit',
});
const src = join(root, 'target', triple, 'release', 'gp-connect-helper.exe');
const destDir = join(root, 'src-tauri', 'binaries');
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, `gp-connect-helper-${triple}.exe`));
console.log(`Staged ${src} -> src-tauri/binaries/`);
