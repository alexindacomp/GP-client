/**
 * Windows security probe for files that will run elevated.
 *
 * Nothing here trusts the process environment (%ProgramFiles%, %SystemRoot%,
 * PATH can all be set by a same-user attacker): PowerShell is started from a
 * hard-coded System32 path, Program Files locations are read from HKLM, and the
 * decision is made from SIDs (locale-independent), not account names.
 */
import { execFile } from 'node:child_process';
import path from 'node:path';

/** Hard-coded; if Windows lives elsewhere, elevation fails closed. */
export const WINDOWS_DIR = 'C:\\Windows';
export const WINDOWS_POWERSHELL = `${WINDOWS_DIR}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
/** Module path restricted to modules shipped with Windows (no user Documents folder). */
export const SYSTEM_PS_MODULES = `${WINDOWS_DIR}\\System32\\WindowsPowerShell\\v1.0\\Modules`;

export interface AclEntry {
  sid: string;
  /** Numeric FileSystemRights. */
  rights: number;
  type: 'Allow' | 'Deny';
  /** Inherit-only ACEs (e.g. CREATOR OWNER templates) do not apply to the object itself. */
  inheritOnly: boolean;
}

export interface AclItem {
  path: string;
  ownerSid: string;
  entries: AclEntry[];
}

export interface WindowsProbeResult {
  /** Program Files directories as registered in HKLM. */
  programFiles: string[];
  items: AclItem[];
}

/** Injected for tests; the default implementation runs PowerShell. */
export type WindowsSecurityProbe = (paths: string[]) => Promise<WindowsProbeResult>;

/** Principals that may legitimately own/modify admin-only install folders. */
export const TRUSTED_SIDS: ReadonlySet<string> = new Set([
  'S-1-5-18', // LocalSystem
  'S-1-5-32-544', // BUILTIN\Administrators
  'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', // NT SERVICE\TrustedInstaller
]);

/**
 * Rights that let a principal change the file/directory or what it contains:
 * WriteData/AddFile, AppendData/AddSubdirectory, WriteExtendedAttributes,
 * DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership,
 * GENERIC_ALL, GENERIC_WRITE.
 */
export const WRITE_RIGHTS_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

/** Returns a reason when `item` can be modified by a non-admin principal, else null. */
export function aclProblem(item: AclItem): string | null {
  if (!TRUSTED_SIDS.has(item.ownerSid)) return `${item.path} is owned by ${item.ownerSid}`;
  for (const e of item.entries) {
    if (e.type !== 'Allow' || e.inheritOnly) continue;
    if ((e.rights & WRITE_RIGHTS_MASK) !== 0 && !TRUSTED_SIDS.has(e.sid)) {
      return `${item.path} is writable by ${e.sid}`;
    }
  }
  return null;
}

/** `real` and its parents up to and including `root` (all lower-cased comparisons by caller). */
export function pathsUpTo(real: string, root: string): string[] {
  const out: string[] = [];
  let cur = real;
  const rootLower = root.toLowerCase();
  for (;;) {
    out.push(cur);
    if (cur.toLowerCase() === rootLower) break;
    const parent = path.win32.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return out;
}

const PROBE_SCRIPT = String.raw`
$env:PSModulePath = "$PSHOME\Modules"
$ErrorActionPreference = 'Stop'
$paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATHS__')) | ConvertFrom-Json
$cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
$pf = @($cv.ProgramFilesDir, $cv.'ProgramFilesDir (x86)', $cv.ProgramW6432Dir) | Where-Object { $_ }
$items = @()
foreach ($p in $paths) {
  $acl = Get-Acl -LiteralPath $p
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  $entries = @()
  foreach ($a in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    $entries += [pscustomobject]@{
      sid = $a.IdentityReference.Value
      rights = [int64]$a.FileSystemRights
      type = [string]$a.AccessControlType
      inheritOnly = (($a.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
    }
  }
  $items += [pscustomobject]@{ path = $p; ownerSid = $owner; entries = $entries }
}
[pscustomobject]@{ programFiles = @($pf); items = $items } | ConvertTo-Json -Depth 5 -Compress
`;

function parseProbe(json: string): WindowsProbeResult {
  const raw = JSON.parse(json) as {
    programFiles?: unknown;
    items?: unknown;
  };
  const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
  const programFiles = asArray(raw.programFiles).filter((p): p is string => typeof p === 'string');
  const items = asArray(raw.items).map((it) => {
    const o = it as { path?: unknown; ownerSid?: unknown; entries?: unknown };
    return {
      path: String(o.path),
      ownerSid: String(o.ownerSid),
      entries: asArray(o.entries).map((e) => {
        const x = e as { sid?: unknown; rights?: unknown; type?: unknown; inheritOnly?: unknown };
        return {
          sid: String(x.sid),
          rights: Number(x.rights),
          type: x.type === 'Deny' ? ('Deny' as const) : ('Allow' as const),
          inheritOnly: x.inheritOnly === true,
        };
      }),
    };
  });
  return { programFiles, items };
}

/** Default probe: one PowerShell run (hard-coded path) for all requested paths. */
export const powershellProbe: WindowsSecurityProbe = (paths) => {
  const script = PROBE_SCRIPT.replace('__PATHS__', Buffer.from(JSON.stringify(paths), 'utf8').toString('base64'));
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    execFile(
      WINDOWS_POWERSHELL,
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      {
        windowsHide: true,
        timeout: 20_000,
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, PSModulePath: SYSTEM_PS_MODULES },
      },
      (err, stdout) => {
        if (err) return reject(new Error(`ACL check failed: ${err.message}`));
        try {
          resolve(parseProbe(String(stdout).trim()));
        } catch (e) {
          reject(new Error(`ACL check returned invalid data: ${(e as Error).message}`));
        }
      },
    );
  });
};
