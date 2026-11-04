import { describe, expect, it } from 'vitest';
import { candidatePaths, locateOpenconnect } from './locate';
import { parseOpenconnectVersion, majorVersion } from './version';

describe('locateOpenconnect', () => {
  it('orders candidates: settings → bundled → PATH → well-known', () => {
    const c = candidatePaths({
      platform: 'linux',
      configuredPath: '/opt/oc/openconnect',
      bundledBinDir: '/app/resources/bin',
      envPath: '/usr/local/bin:relative/dir:/usr/bin',
    });
    expect(c.slice(0, 4)).toEqual([
      { path: '/opt/oc/openconnect', source: 'settings' },
      { path: '/app/resources/bin/linux/openconnect', source: 'bundled' },
      { path: '/usr/local/bin/openconnect', source: 'path' },
      { path: '/usr/bin/openconnect', source: 'path' },
    ]);
    expect(c.some((x) => x.path === '/usr/sbin/openconnect' && x.source === 'well-known')).toBe(true);
    // duplicates are removed
    expect(c.filter((x) => x.path === '/usr/bin/openconnect')).toHaveLength(1);
  });

  it('uses openconnect.exe and ; separator on Windows', () => {
    const c = candidatePaths({ platform: 'win32', envPath: 'C:\\Tools;"C:\\Quoted Dir"' });
    expect(c[0]).toEqual({ path: 'C:\\Tools\\openconnect.exe', source: 'path' });
    expect(c[1]).toEqual({ path: 'C:\\Quoted Dir\\openconnect.exe', source: 'path' });
  });

  it('returns the first executable candidate or null', async () => {
    const exists = new Set(['/usr/sbin/openconnect']);
    const found = await locateOpenconnect({
      platform: 'linux',
      configuredPath: '/missing/openconnect',
      envPath: '/usr/bin',
      isExecutable: async (p) => exists.has(p),
    });
    expect(found).toEqual({ path: '/usr/sbin/openconnect', source: 'well-known', trusted: true });
    expect(await locateOpenconnect({ platform: 'linux', envPath: '', isExecutable: async () => false })).toBeNull();
  });
});

describe('locateOpenconnect trust preference', () => {
  it('prefers a trusted binary over an earlier untrusted PATH hit', async () => {
    const found = await locateOpenconnect({
      platform: 'linux',
      envPath: '/home/alice/bin:/usr/bin',
      isExecutable: async (p) => p === '/home/alice/bin/openconnect' || p === '/usr/sbin/openconnect',
      isTrusted: async (p) => p.startsWith('/usr/'),
    });
    expect(found).toEqual({ path: '/usr/sbin/openconnect', source: 'well-known', trusted: true });
  });

  it('reports an untrusted binary when nothing trusted exists', async () => {
    const found = await locateOpenconnect({
      platform: 'darwin',
      envPath: '/opt/homebrew/bin',
      isExecutable: async (p) => p === '/opt/homebrew/bin/openconnect',
      isTrusted: async () => false,
    });
    expect(found).toEqual({ path: '/opt/homebrew/bin/openconnect', source: 'path', trusted: false });
  });
});

describe('parseOpenconnectVersion', () => {
  it.each([
    ['OpenConnect version v9.12-188-gaebd3bd\nUsing GnuTLS 3.8.3.', '9.12-188-gaebd3bd', 9],
    ['OpenConnect version v8.20', '8.20', 8],
    ['OpenConnect version 9.01', '9.01', 9],
  ])('%s', (out, version, major) => {
    expect(parseOpenconnectVersion(out)).toBe(version);
    expect(majorVersion(parseOpenconnectVersion(out))).toBe(major);
  });

  it('returns undefined for garbage', () => {
    expect(parseOpenconnectVersion('command not found')).toBeUndefined();
  });
});
