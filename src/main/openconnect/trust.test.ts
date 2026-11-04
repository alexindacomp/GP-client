import { describe, expect, it } from 'vitest';
import { createTrustCache, isTrustedFile, verifyTrustedFile, type TrustFs, type TrustStat } from './trust';
import type { AclItem, WindowsSecurityProbe } from './windows-acl';

interface Node {
  uid: number;
  mode: number;
  dir?: boolean;
}

/** In-memory filesystem: path → owner/mode, plus symlinks. */
function fakeFs(nodes: Record<string, Node>, links: Record<string, string> = {}): TrustFs {
  return {
    realpath: async (p) => {
      const target = links[p] ?? p;
      if (!(target in nodes)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return target;
    },
    stat: async (p): Promise<TrustStat> => {
      const n = nodes[p];
      if (!n) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return { uid: n.uid, mode: n.mode, isFile: () => !n.dir, isDirectory: () => n.dir === true };
    },
  };
}

const ROOT_DIR = { uid: 0, mode: 0o40755, dir: true };
const linuxTree: Record<string, Node> = {
  '/': ROOT_DIR,
  '/usr': ROOT_DIR,
  '/usr/sbin': ROOT_DIR,
  '/usr/sbin/openconnect': { uid: 0, mode: 0o100755 },
  '/usr/sbin/groupw': { uid: 0, mode: 0o100775 },
  '/home': ROOT_DIR,
  '/home/alice': { uid: 1000, mode: 0o40755, dir: true },
  '/home/alice/openconnect': { uid: 1000, mode: 0o100755 },
  '/home/alice/rootowned': { uid: 0, mode: 0o100755 },
  '/opt': ROOT_DIR,
  '/opt/homebrew': { uid: 501, mode: 0o40755, dir: true },
  '/opt/homebrew/bin': { uid: 501, mode: 0o40755, dir: true },
  '/opt/homebrew/bin/openconnect': { uid: 501, mode: 0o100755 },
  '/tmp': { uid: 0, mode: 0o41777, dir: true },
  '/tmp/oc': { uid: 0, mode: 0o100755 },
};

describe('verifyTrustedFile (Unix)', () => {
  const opts = {
    platform: 'linux' as const,
    fs: fakeFs(linuxTree, {
      '/usr/bin/openconnect': '/usr/sbin/openconnect',
      '/usr/local/bin/oc': '/home/alice/openconnect',
    }),
  };

  it('accepts a root-owned file in root-owned, non-writable directories and returns the real path', async () => {
    await expect(verifyTrustedFile('/usr/sbin/openconnect', opts)).resolves.toBe('/usr/sbin/openconnect');
    await expect(verifyTrustedFile('/usr/bin/openconnect', opts)).resolves.toBe('/usr/sbin/openconnect');
  });

  it.each([
    ['/home/alice/openconnect', /not owned by root/],
    ['/home/alice/rootowned', /\/home\/alice is not owned by root/],
    ['/opt/homebrew/bin/openconnect', /not owned by root/],
    ['/usr/sbin/groupw', /writable by group or others/],
    ['/tmp/oc', /\/tmp is writable/],
    ['/usr/local/bin/oc', /not owned by root/], // symlink into the user's home
    ['/nope', /does not exist/],
    ['relative/openconnect', /absolute/],
  ])('rejects %s', async (file, reason) => {
    await expect(verifyTrustedFile(file, opts)).rejects.toMatchObject({
      code: 'PRIVILEGES_DENIED',
      message: expect.stringMatching(reason),
    });
    expect(await isTrustedFile(file, opts)).toBe(false);
  });

  it('rejects directories', async () => {
    await expect(verifyTrustedFile('/usr/sbin', opts)).rejects.toThrow(/not a regular file/);
  });

  it('converts unexpected fs errors into an untrusted-path error', async () => {
    const broken: TrustFs = {
      realpath: async (p) => p,
      stat: async () => {
        throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
      },
    };
    await expect(verifyTrustedFile('/usr/sbin/openconnect', { platform: 'linux', fs: broken })).rejects.toMatchObject({
      code: 'PRIVILEGES_DENIED',
    });
  });
});

describe('verifyTrustedFile (Windows)', () => {
  const SYSTEM = 'S-1-5-18';
  const ADMINS = 'S-1-5-32-544';
  const TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
  const USERS = 'S-1-5-32-545';
  const AUTH_USERS = 'S-1-5-11';
  const ME = 'S-1-5-21-1-2-3-1001';
  const FULL = 0x1f01ff;
  const RX = 0x1200a9;
  const MODIFY = 0x1301bf;

  const adminOnly = (p: string): AclItem => ({
    path: p,
    ownerSid: TI,
    entries: [
      { sid: SYSTEM, rights: FULL, type: 'Allow', inheritOnly: false },
      { sid: ADMINS, rights: FULL, type: 'Allow', inheritOnly: false },
      { sid: USERS, rights: RX, type: 'Allow', inheritOnly: false },
      // CREATOR OWNER template: does not apply to the object itself
      { sid: 'S-1-3-0', rights: 0x10000000, type: 'Allow', inheritOnly: true },
    ],
  });

  const files: Record<string, Node> = {
    'C:\\Program Files\\OpenConnect-GUI\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Program Files\\GP Connect\\resources\\bin\\win32\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Program Files\\Loose\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Program Files\\Mine\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Windows\\Temp\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Windows\\System32\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Users\\alice\\AppData\\Local\\Programs\\GP Connect\\openconnect.exe': { uid: 0, mode: 0 },
    'C:\\Program Files Evil\\openconnect.exe': { uid: 0, mode: 0 },
  };

  /** Fake registry + ACLs: everything admin-only except the overrides. */
  function probe(overrides: Record<string, AclItem> = {}): WindowsSecurityProbe & { calls: string[][] } {
    const calls: string[][] = [];
    const fn = (async (paths: string[]) => {
      calls.push(paths);
      return {
        programFiles: ['C:\\Program Files', 'C:\\Program Files (x86)'],
        items: paths.map((p) => overrides[p] ?? adminOnly(p)),
      };
    }) as WindowsSecurityProbe & { calls: string[][] };
    fn.calls = calls;
    return fn;
  }
  const opts = (windowsProbe: WindowsSecurityProbe) => ({
    platform: 'win32' as const,
    fs: fakeFs(files),
    windowsProbe,
  });

  it.each([
    'C:\\Program Files\\OpenConnect-GUI\\openconnect.exe',
    // per-machine install of GP Connect with the bundled binary
    'C:\\Program Files\\GP Connect\\resources\\bin\\win32\\openconnect.exe',
  ])('accepts admin-only %s and checks every parent up to Program Files', async (file) => {
    const pr = probe();
    await expect(verifyTrustedFile(file, opts(pr))).resolves.toBe(file);
    const chain = pr.calls.at(-1)!;
    expect(chain[0]).toBe(file);
    expect(chain.at(-1)).toBe('C:\\Program Files');
  });

  it.each([
    // %SystemRoot% is not a trusted root: it contains user-writable folders
    ['C:\\Windows\\Temp\\openconnect.exe', /Program Files/],
    ['C:\\Windows\\System32\\openconnect.exe', /Program Files/],
    ['C:\\Users\\alice\\AppData\\Local\\Programs\\GP Connect\\openconnect.exe', /Program Files/],
    ['C:\\Program Files Evil\\openconnect.exe', /Program Files/],
    ['\\\\server\\share\\openconnect.exe', /local absolute path/],
    ['relative\\openconnect.exe', /local absolute path/],
  ])('rejects %s', async (file, reason) => {
    await expect(verifyTrustedFile(file, opts(probe()))).rejects.toMatchObject({
      code: 'PRIVILEGES_DENIED',
      message: expect.stringMatching(reason),
    });
  });

  it('ignores the process environment entirely (no env-derived roots)', async () => {
    const saved = process.env.ProgramFiles;
    process.env.ProgramFiles = 'C:\\Windows\\Temp';
    try {
      await expect(verifyTrustedFile('C:\\Windows\\Temp\\openconnect.exe', opts(probe()))).rejects.toThrow();
    } finally {
      if (saved === undefined) delete process.env.ProgramFiles;
      else process.env.ProgramFiles = saved;
    }
  });

  it.each([
    ['a parent folder writable by Users', 'C:\\Program Files\\Loose', USERS, MODIFY],
    ['the file writable by Authenticated Users', 'C:\\Program Files\\Loose\\openconnect.exe', AUTH_USERS, 0x2],
    ['the file with full control for the user', 'C:\\Program Files\\Loose\\openconnect.exe', ME, FULL],
    ['a parent with GENERIC_WRITE for Everyone', 'C:\\Program Files\\Loose', 'S-1-1-0', 0x40000000],
  ])('rejects %s', async (_name, aclPath, sid, rights) => {
    const pr = probe({
      [aclPath]: {
        ...adminOnly(aclPath),
        entries: [...adminOnly(aclPath).entries, { sid, rights, type: 'Allow', inheritOnly: false }],
      },
    });
    await expect(verifyTrustedFile('C:\\Program Files\\Loose\\openconnect.exe', opts(pr))).rejects.toMatchObject({
      code: 'PRIVILEGES_DENIED',
      message: expect.stringContaining(`writable by ${sid}`),
    });
  });

  it('rejects a file owned by the user even without write ACEs (owner can rewrite the DACL)', async () => {
    const f = 'C:\\Program Files\\Mine\\openconnect.exe';
    const pr = probe({ [f]: { ...adminOnly(f), ownerSid: ME } });
    await expect(verifyTrustedFile(f, opts(pr))).rejects.toThrow(/owned by S-1-5-21-1-2-3-1001/);
  });

  it('ignores Deny and inherit-only entries', async () => {
    const f = 'C:\\Program Files\\Loose\\openconnect.exe';
    const pr = probe({
      [f]: {
        ...adminOnly(f),
        entries: [
          ...adminOnly(f).entries,
          { sid: USERS, rights: FULL, type: 'Deny', inheritOnly: false },
          { sid: USERS, rights: FULL, type: 'Allow', inheritOnly: true },
        ],
      },
    });
    await expect(verifyTrustedFile(f, opts(pr))).resolves.toBe(f);
  });

  it('fails closed when the probe fails', async () => {
    const broken: WindowsSecurityProbe = async () => {
      throw new Error('powershell missing');
    };
    await expect(
      verifyTrustedFile('C:\\Program Files\\OpenConnect-GUI\\openconnect.exe', opts(broken)),
    ).rejects.toMatchObject({ code: 'PRIVILEGES_DENIED', message: expect.stringContaining('powershell missing') });
  });
});

describe('createTrustCache', () => {
  it('memoises by path+mtime for the TTL only', async () => {
    let calls = 0;
    const counting: TrustFs = {
      realpath: async (p) => {
        calls++;
        return p;
      },
      stat: async (p) => fakeFs(linuxTree).stat(p),
    };
    let t = 0;
    let mtime = 1;
    const check = createTrustCache(
      { platform: 'linux', fs: counting },
      1000,
      () => t,
      async () => mtime,
    );
    expect(await check('/usr/sbin/openconnect')).toBe(true);
    expect(await check('/usr/sbin/openconnect')).toBe(true);
    expect(calls).toBe(1);
    mtime = 2; // file replaced → re-checked
    await check('/usr/sbin/openconnect');
    expect(calls).toBe(2);
    t = 1001; // TTL expired → re-checked
    await check('/usr/sbin/openconnect');
    expect(calls).toBe(3);
  });

  it('reports missing files as untrusted', async () => {
    const check = createTrustCache(
      { platform: 'linux', fs: fakeFs(linuxTree) },
      1000,
      () => 0,
      async () => {
        throw new Error('ENOENT');
      },
    );
    expect(await check('/nope')).toBe(false);
  });
});
