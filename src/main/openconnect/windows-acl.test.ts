import { describe, expect, it } from 'vitest';
import { aclProblem, pathsUpTo, WINDOWS_POWERSHELL } from './windows-acl';

describe('aclProblem', () => {
  const base = { path: 'C:\\Program Files\\X', ownerSid: 'S-1-5-32-544' };

  it('accepts admin/system/TrustedInstaller write access and read-only access for others', () => {
    expect(
      aclProblem({
        ...base,
        entries: [
          { sid: 'S-1-5-18', rights: 0x1f01ff, type: 'Allow', inheritOnly: false },
          { sid: 'S-1-5-32-545', rights: 0x1200a9, type: 'Allow', inheritOnly: false },
          { sid: 'S-1-15-2-1', rights: 0x1200a9, type: 'Allow', inheritOnly: false },
        ],
      }),
    ).toBeNull();
  });

  it.each([
    ['WriteData', 0x2],
    ['AppendData/AddSubdirectory', 0x4],
    ['DeleteChild', 0x40],
    ['Delete', 0x10000],
    ['ChangePermissions', 0x40000],
    ['TakeOwnership', 0x80000],
    ['GENERIC_ALL', 0x10000000],
    ['GENERIC_WRITE', 0x40000000],
  ])('flags %s for a non-admin SID', (_n, rights) => {
    expect(aclProblem({ ...base, entries: [{ sid: 'S-1-5-11', rights, type: 'Allow', inheritOnly: false }] })).toMatch(
      /writable by S-1-5-11/,
    );
  });

  it('flags a non-admin owner', () => {
    expect(aclProblem({ ...base, ownerSid: 'S-1-5-21-9-9-9-1001', entries: [] })).toMatch(/owned by/);
  });
});

describe('pathsUpTo', () => {
  it('lists the file and its parents up to the root (inclusive)', () => {
    expect(pathsUpTo('C:\\Program Files\\A\\b.exe', 'c:\\program files')).toEqual([
      'C:\\Program Files\\A\\b.exe',
      'C:\\Program Files\\A',
      'C:\\Program Files',
    ]);
  });
});

it('uses a hard-coded System32 PowerShell, never %SystemRoot%', () => {
  expect(WINDOWS_POWERSHELL).toBe('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
});
