import { describe, expect, it } from 'vitest';
import { buildOpenconnectArgs, openconnectOs, validateExtraArgs } from './args';

describe('buildOpenconnectArgs', () => {
  it('builds password-auth arguments with the server last', () => {
    expect(
      buildOpenconnectArgs({
        portalUrl: 'https://vpn.example.com',
        platform: 'linux',
        username: 'alice',
        auth: { kind: 'password' },
      }),
    ).toEqual(['--protocol=gp', '--os=linux-64', '--passwd-on-stdin', '--user=alice', '--', 'https://vpn.example.com']);
  });

  it('builds SAML arguments with usergroup, gateway, HIP and extra args', () => {
    const args = buildOpenconnectArgs({
      portalUrl: 'https://vpn.example.com:8443',
      platform: 'win32',
      username: 'bob@example.com',
      auth: { kind: 'saml', cookieName: 'portal-userauthcookie' },
      gateway: 'US East',
      hipScriptPath: 'C:\\Program Files\\OpenConnect\\hipreport.js',
      extraArgs: ['--servercert=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', '-v'],
    });
    expect(args).toEqual([
      '--protocol=gp',
      '--os=win',
      '--passwd-on-stdin',
      '--user=bob@example.com',
      '--usergroup=portal:portal-userauthcookie',
      '--authgroup=US East',
      '--csd-wrapper=C:\\Program Files\\OpenConnect\\hipreport.js',
      '--servercert=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      '-v',
      '--',
      'https://vpn.example.com:8443',
    ]);
  });

  it('never contains secrets: there is no password/cookie input at all', () => {
    const args = buildOpenconnectArgs({
      portalUrl: 'https://vpn.example.com',
      platform: 'darwin',
      auth: { kind: 'saml', cookieName: 'prelogin-cookie' },
    });
    expect(args.join(' ')).not.toMatch(/cookie=|passwd=/);
    expect(args).toContain('--os=mac-intel');
  });

  it('rejects non-https portals and control characters', () => {
    expect(() =>
      buildOpenconnectArgs({ portalUrl: 'http://vpn.example.com', platform: 'linux', auth: { kind: 'password' } }),
    ).toThrow(/https/);
    expect(() =>
      buildOpenconnectArgs({
        portalUrl: 'https://vpn.example.com',
        platform: 'linux',
        username: 'a\nb',
        auth: { kind: 'password' },
      }),
    ).toThrow(/username/);
  });
});

describe('validateExtraArgs (allowlist)', () => {
  const PIN = 'pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  it('accepts allowlisted options with valid values', () => {
    expect(
      validateExtraArgs([
        ' --no-dtls ',
        `--servercert=${PIN}`,
        '-v',
        '--verbose',
        '--disable-ipv6',
        '--mtu=1400',
        '--base-mtu=1500',
        '--reconnect-timeout=600',
        '--force-dpd=30',
        '--dtls-ciphers=AES256-GCM-SHA384:PSK-NEGOTIATE',
      ]),
    ).toEqual([
      '--no-dtls',
      `--servercert=${PIN}`,
      '-v',
      '--verbose',
      '--disable-ipv6',
      '--mtu=1400',
      '--base-mtu=1500',
      '--reconnect-timeout=600',
      '--force-dpd=30',
      '--dtls-ciphers=AES256-GCM-SHA384:PSK-NEGOTIATE',
    ]);
  });

  it.each([
    // code execution / file loading as root
    ['--script=/tmp/evil.sh'],
    ['-s'],
    ['--script-tun'],
    ['--external-browser=/tmp/x'],
    ['--config=/tmp/oc.conf'],
    ['--csd-wrapper=/tmp/x'],
    ['--cafile=/tmp/ca.pem'],
    ['-c'],
    ['--certificate=/tmp/c.pem'],
    ['-k'],
    ['--sslkey=/tmp/k'],
    ['-D'],
    ['--syslog'],
    ['--pid-file=/etc/passwd'],
    // traffic redirection / trust weakening
    ['--proxy=http://evil:8080'],
    ['--resolve=vpn.example.com:1.2.3.4'],
    ['--no-system-trust'],
    ['--servercert=sha1:0123'],
    ['--servercert=pin-sha256:short'],
    ['--allow-insecure-crypto'],
    ['--dump-http-traffic'],
    // app-managed options and tricks
    ['--protocol=anyconnect'],
    ['--user=root'],
    ['-uroot'],
    ['--passwd'],
    ['--no-d'],
    ['--'],
    ['-vs'],
    ['--mtu'],
    ['--mtu=abc'],
    ['--mtu=100'],
    ['--no-dtls=1'],
    ['positional'],
  ])('rejects %s', (arg) => {
    expect(() => validateExtraArgs([arg])).toThrow();
  });

  it.each([[[1]], ['not-an-array'], [new Array(33).fill('-v')]])('rejects malformed input %#', (args) => {
    expect(() => validateExtraArgs(args)).toThrow();
  });
});

describe('openconnectOs', () => {
  it('matches the prelogin clientos', () => {
    expect([openconnectOs('win32'), openconnectOs('darwin'), openconnectOs('linux')]).toEqual([
      'win',
      'mac-intel',
      'linux-64',
    ]);
  });
});
