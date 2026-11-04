import { describe, expect, it } from 'vitest';
import { createDiscoveryReporter, discoveryLines, openconnectSystemInfo, type DiscoveryLine } from './discovery-log';

const untrusted = { path: 'C:\\Users\\a\\oc\\openconnect.exe', source: 'settings' as const, trusted: false };

describe('discovery logging (B4)', () => {
  it('logs each discovery result once, and again only when it changes', () => {
    const out: DiscoveryLine[] = [];
    const report = createDiscoveryReporter((l) => out.push(l));
    report(untrusted, undefined); // bootstrap
    report(untrusted, undefined); // system.info
    report(untrusted, undefined); // connect
    expect(out).toEqual([
      { level: 'warn', msg: expect.stringContaining('is not admin-owned') },
      { level: 'info', msg: 'Using C:\\Users\\a\\oc\\openconnect.exe (settings), version unknown' },
    ]);
    report({ ...untrusted, trusted: true }, '9.12');
    expect(out).toHaveLength(3);
    expect(out[2]!.msg).toMatch(/version 9.12$/);
  });

  it('describes missing and old binaries', () => {
    expect(discoveryLines(null, undefined)).toEqual([{ level: 'warn', msg: 'openconnect not found' }]);
    expect(
      discoveryLines({ path: '/usr/sbin/openconnect', source: 'well-known', trusted: true }, '8.20').at(-1),
    ).toEqual({
      level: 'warn',
      msg: expect.stringContaining('older than 9'),
    });
  });
});

describe('openconnectSystemInfo (DR-15)', () => {
  it('reports path and trust for a found binary', () => {
    expect(openconnectSystemInfo({ path: 'C:\\Users\\a\\openconnect.exe', version: '9.12', trusted: false })).toEqual({
      openconnectFound: true,
      openconnectVersion: '9.12',
      openconnectPath: 'C:\\Users\\a\\openconnect.exe',
      openconnectTrusted: false,
    });
    expect(openconnectSystemInfo({ path: '/usr/sbin/openconnect', trusted: true })).toEqual({
      openconnectFound: true,
      openconnectPath: '/usr/sbin/openconnect',
      openconnectTrusted: true,
    });
  });

  it('omits path/trust when not found', () => {
    expect(openconnectSystemInfo({ path: null })).toEqual({ openconnectFound: false });
  });
});
