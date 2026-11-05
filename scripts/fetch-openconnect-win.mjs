// Fetches the official prebuilt Windows OpenConnect (MinGW64/GnuTLS, with GlobalProtect support)
// and stages it for the Windows installer in src-tauri/resources/bin/win32/ (gitignored;
// bundle.resources in src-tauri/tauri.windows.conf.json → C:\Program Files\GP Connect\bin\win32\).
//
// Source: the OpenConnect project's GitLab CI job "persist-windows-builds-for-tagged-releases"
// of the release tag (artifacts never expire). It contains the upstream NSIS installer, which is
// unpacked with 7-Zip (7zr.exe unpacks the full 7-Zip, whose 7z.exe can read NSIS). Every
// download is pinned by SHA-256 and verified (hard fail). openconnect.exe finds
// vpnc-script-win.js next to itself (main.c set_default_vpncscript), so no --script is needed.
//
// Usage (Windows only): npm run fetch:openconnect:win
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OPENCONNECT = {
  version: '9.21',
  // gitlab.com/openconnect/openconnect pipeline 2605045915 (tag v9.21, commit 8b702bf2).
  url: 'https://gitlab.com/openconnect/openconnect/-/jobs/14877945032/artifacts/download',
  sha256: '9e132236aa720c9f40919051bd07c5cded233f2840fdabfbb4979e05e7dc8bdf',
  installer: 'openconnect-installer-MinGW64-GnuTLS-v9.21.exe',
  installerSha256: '6ee9e8eb9bc59ef70bb0717df7f99703f8a2ccd11d8e45d58a61f9a2e6ef7d00',
};
// 7-Zip 26.05 (github.com/ip7z/7zip release assets; digests as published there).
const SEVEN_ZIP = {
  zr: {
    url: 'https://github.com/ip7z/7zip/releases/download/26.05/7zr.exe',
    sha256: '9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7',
  },
  full: {
    url: 'https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.exe',
    sha256: 'fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0',
  },
};

/** Files of the upstream installer that are bundled (everything else is ignored). */
const REQUIRED = ['openconnect.exe', 'libopenconnect-5.dll', 'wintun.dll', 'vpnc-script-win.js'];
const isBundled = (name) => name === 'openconnect.exe' || name === 'vpnc-script-win.js' || /\.dll$/i.test(name);

/** Component and licence of a bundled file, for THIRD-PARTY-NOTICES.txt. */
const COMPONENTS = [
  [/^(openconnect\.exe|libopenconnect)/i, 'OpenConnect', 'LGPL-2.1', 'https://www.infradead.org/openconnect/'],
  [
    /^vpnc-script-win\.js$/i,
    'vpnc-scripts (vpnc-script-win.js)',
    'GPL-2.0-or-later',
    'https://gitlab.com/openconnect/vpnc-scripts',
  ],
  [
    /^wintun\.dll$/i,
    'Wintun (prebuilt binary, unmodified)',
    'Wintun Prebuilt Binaries License',
    'https://www.wintun.net/',
  ],
  [/^libgnutls/i, 'GnuTLS', 'LGPL-2.1-or-later', 'https://www.gnutls.org/'],
  [
    /^libnettle|^libhogweed/i,
    'Nettle',
    'LGPL-3.0-or-later OR GPL-2.0-or-later',
    'https://www.lysator.liu.se/~nisse/nettle/',
  ],
  [/^libgmp/i, 'GNU MP', 'LGPL-3.0-or-later OR GPL-2.0-or-later', 'https://gmplib.org/'],
  [/^libtasn1/i, 'libtasn1', 'LGPL-2.1-or-later', 'https://www.gnu.org/software/libtasn1/'],
  [/^libidn2/i, 'libidn2', 'LGPL-3.0-or-later OR GPL-2.0-or-later', 'https://www.gnu.org/software/libidn/'],
  [
    /^libunistring/i,
    'libunistring',
    'LGPL-3.0-or-later OR GPL-2.0-or-later',
    'https://www.gnu.org/software/libunistring/',
  ],
  [/^libp11-kit/i, 'p11-kit', 'BSD-3-Clause', 'https://p11-glue.github.io/p11-glue/p11-kit.html'],
  [/^libffi/i, 'libffi', 'MIT', 'https://sourceware.org/libffi/'],
  [/^libxml2/i, 'libxml2', 'MIT', 'https://gitlab.gnome.org/GNOME/libxml2'],
  [/^zlib|^libz/i, 'zlib', 'Zlib', 'https://zlib.net/'],
  [/^liblz4/i, 'LZ4', 'BSD-2-Clause', 'https://lz4.org/'],
  [/^(lib)?iconv/i, 'GNU libiconv', 'LGPL-2.1-or-later', 'https://www.gnu.org/software/libiconv/'],
  [/^libintl/i, 'GNU gettext runtime (libintl)', 'LGPL-2.1-or-later', 'https://www.gnu.org/software/gettext/'],
  [/^libstoken/i, 'stoken', 'LGPL-2.1-or-later', 'https://github.com/stoken-dev/stoken'],
  [/^libpskc/i, 'libpskc', 'LGPL-2.1-or-later', 'https://www.nongnu.org/oath-toolkit/'],
  [/^libbrotli/i, 'Brotli', 'MIT', 'https://github.com/google/brotli'],
  [/^libzstd/i, 'Zstandard', 'BSD-3-Clause', 'https://facebook.github.io/zstd/'],
  [/^libgcc_s|^libstdc\+\+/i, 'GCC runtime', 'GPL-3.0-or-later WITH GCC-exception-3.1', 'https://gcc.gnu.org/'],
  [/^libwinpthread/i, 'MinGW-w64 winpthreads', 'MIT AND BSD-3-Clause', 'https://www.mingw-w64.org/'],
];

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'target', 'openconnect-win-cache');
const destDir = join(root, 'src-tauri', 'resources', 'bin', 'win32');
const licenseSrc = join(root, 'build', 'win32', 'licenses');

function fail(msg) {
  console.error(`fetch-openconnect-win: ${msg}`);
  process.exit(1);
}

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

/** Downloads `url` into the cache (unless a verified copy exists) and verifies the pin. */
async function fetchPinned(url, expected, name) {
  const file = join(cacheDir, name);
  if (existsSync(file) && sha256(file) === expected) return file;
  console.log(`Downloading ${url}`);
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) fail(`download failed: ${url} → HTTP ${res.status}`);
  writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  const actual = sha256(file);
  if (actual !== expected) {
    rmSync(file, { force: true });
    fail(`SHA-256 mismatch for ${name}: expected ${expected}, got ${actual}`);
  }
  return file;
}

const run = (exe, args, opts = {}) => execFileSync(exe, args, { stdio: ['ignore', 'pipe', 'inherit'], ...opts });

if (process.platform !== 'win32') {
  console.log('fetch-openconnect-win: Windows only (skipped).');
  process.exit(0);
}

mkdirSync(cacheDir, { recursive: true });
const zr = await fetchPinned(SEVEN_ZIP.zr.url, SEVEN_ZIP.zr.sha256, '7zr.exe');
const full = await fetchPinned(SEVEN_ZIP.full.url, SEVEN_ZIP.full.sha256, '7z-x64.exe');
const artifacts = await fetchPinned(
  OPENCONNECT.url,
  OPENCONNECT.sha256,
  `openconnect-${OPENCONNECT.version}-artifacts.zip`,
);

// Full 7-Zip (7z.exe + 7z.dll) from its self-extracting package.
const sevenDir = join(cacheDir, '7z');
rmSync(sevenDir, { recursive: true, force: true });
run(zr, ['x', '-y', `-o${sevenDir}`, full]);
const sevenZip = join(sevenDir, '7z.exe');
if (!existsSync(sevenZip)) fail('7z.exe missing after unpacking 7-Zip');

// The upstream installer from the artifacts zip (Windows' own tar.exe reads zip).
const work = join(cacheDir, 'work');
rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });
const tar = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe');
run(tar, ['-xf', artifacts, '-C', work, OPENCONNECT.installer]);
const installer = join(work, OPENCONNECT.installer);
if (sha256(installer) !== OPENCONNECT.installerSha256) fail(`SHA-256 mismatch for ${OPENCONNECT.installer}`);

// Unpack the NSIS installer: $INSTDIR files land at the top level.
const unpacked = join(work, 'installer');
run(sevenZip, ['x', '-y', `-o${unpacked}`, installer]);
const files = readdirSync(unpacked).filter((n) => statSync(join(unpacked, n)).isFile() && isBundled(n));
for (const r of REQUIRED) if (!files.includes(r)) fail(`${r} not found in ${OPENCONNECT.installer}`);

rmSync(destDir, { recursive: true, force: true });
mkdirSync(destDir, { recursive: true });
for (const n of files) copyFileSync(join(unpacked, n), join(destDir, n));
cpSync(licenseSrc, join(destDir, 'licenses'), { recursive: true });

// The DLL set must be complete: openconnect.exe has to start from the staged directory.
let version;
try {
  version = run(join(destDir, 'openconnect.exe'), ['--version'], { cwd: destDir }).toString();
} catch (e) {
  fail(`openconnect.exe --version failed from ${destDir}: ${e.message}`);
}
if (!version.includes(`OpenConnect version v${OPENCONNECT.version}`)) fail(`unexpected version output:\n${version}`);

const notices = [
  'GP Connect bundles the following third-party software in this directory, unmodified.',
  `Source: OpenConnect ${OPENCONNECT.version} official Windows build (MinGW64/GnuTLS),`,
  `${OPENCONNECT.url}`,
  'Source code: https://gitlab.com/openconnect/openconnect (and the projects linked below).',
  'Licence texts: licenses/ (GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, Wintun prebuilt binaries licence).',
  '',
  ...files.sort().map((n) => {
    const c = COMPONENTS.find(([re]) => re.test(n));
    const [component, licence, home] = c
      ? c.slice(1)
      : ['(MinGW-w64 runtime dependency of OpenConnect)', 'see upstream', ''];
    return `${n}\n  ${component} — ${licence}${home ? ` — ${home}` : ''}\n  sha256 ${sha256(join(destDir, n))}`;
  }),
  '',
].join('\n');
writeFileSync(join(destDir, 'THIRD-PARTY-NOTICES.txt'), notices);

console.log(version.split('\n')[0].trim());
console.log(`Staged ${files.length} files in ${destDir}`);
