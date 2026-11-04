import { describe, expect, it } from 'vitest';
import { fixture } from '../__fixtures__';
import { LineSplitter, OutputParser, parseLine, parsePrompt, type OcEvent } from './output-parser';

describe('OutputParser on a full GlobalProtect session', () => {
  const events = (() => {
    const parser = new OutputParser();
    return fixture('openconnect-gp-session.txt')
      .split('\n')
      .map((l) => parser.parse(l))
      .filter((e): e is OcEvent => e !== null);
  })();

  it('reports the gateway list', () => {
    expect(events.filter((e) => e.type === 'gateway-list')).toEqual([{ type: 'gateway-list', count: 2 }]);
    expect(events.filter((e) => e.type === 'gateway')).toEqual([
      { type: 'gateway', gateway: { name: 'Europe', address: 'gw-eu.example.com', priority: 1 } },
      { type: 'gateway', gateway: { name: 'US East', address: 'gw-us.example.com', priority: 2 } },
    ]);
  });

  it('reports authentication, the assigned IP and ESP in order', () => {
    const types = events.map((e) => e.type).filter((t) => t !== 'gateway' && t !== 'gateway-list');
    expect(types).toEqual(['authenticated', 'authenticated', 'connected', 'esp']);
    expect(events.find((e) => e.type === 'connected')).toEqual({ type: 'connected', ip: '10.8.0.42' });
  });

  it('produces no error events for a healthy session', () => {
    expect(events.some((e) => e.type === 'error' || e.type === 'auth-failed')).toBe(false);
  });

  it('parses gateway entries without priority', () => {
    const p = new OutputParser();
    p.parse('1 gateway server available:');
    expect(p.parse('  Only (only.example.com)')).toEqual({
      type: 'gateway',
      gateway: { name: 'Only', address: 'only.example.com' },
    });
    // the list is over: indented lines are no longer gateways
    expect(p.parse('  Other (x.example.com)')).toBeNull();
  });
});

describe('parseLine', () => {
  it.each([
    ['Connected as 10.0.0.5, using SSL, with ESP in progress', { type: 'connected', ip: '10.0.0.5' }],
    ['Connected as fd00::5, using SSL', { type: 'connected', ip: 'fd00::5' }],
    ['Configured as 192.168.10.2, with SSL connected and ESP in progress', { type: 'connected', ip: '192.168.10.2' }],
    ['ESP session established with server', { type: 'esp' }],
  ])('%s', (line, ev) => {
    expect(parseLine(line)).toEqual(ev);
  });

  it.each([
    'Login failed.',
    'Invalid username or password',
    'Unexpected 512 result from server',
    'Authentication failed',
  ])('auth failure: %s', (line) => {
    expect(parseLine(line)?.type).toBe('auth-failed');
  });

  it.each([
    ["getaddrinfo failed for host 'vpn.example.com': Name or service not known", 'PORTAL_UNREACHABLE'],
    ['Failed to connect to host vpn.example.com', 'PORTAL_UNREACHABLE'],
    ['Failed to open HTTPS connection to vpn.example.com', 'PORTAL_UNREACHABLE'],
    ['Server certificate verify failed: signer not found', 'TLS_ERROR'],
    ['SSL connection failure: The TLS connection was non-properly terminated.', 'TLS_ERROR'],
    ['Failed to bind local tun device (TUNSETIFF): Operation not permitted', 'PRIVILEGES_DENIED'],
    ['Error executing command as another user: Not authorized', 'PRIVILEGES_DENIED'],
    ['Error executing command as another user: Request dismissed', 'PRIVILEGES_DENIED'],
    ['sudo: a password is required', 'PRIVILEGES_DENIED'],
    ['Failed to create Wintun adapter: Access is denied.', 'PRIVILEGES_DENIED'],
    ["Script '/usr/share/vpnc-scripts/vpnc-script' returned error 1", 'TUNNEL_FAILED'],
    ['Set up tun device failed', 'TUNNEL_FAILED'],
    ["openconnect: unrecognized option '--bogus'", 'UNKNOWN'],
  ])('%s → %s', (line, code) => {
    expect(parseLine(line)).toEqual({ type: 'error', code, message: line });
  });

  it.each([
    'Session terminated by server; exiting.',
    'Unrecoverable I/O error; exiting.',
    'Cookie was rejected by server; exiting.',
  ])('session lost: %s', (line) => {
    expect(parseLine(line)?.type).toBe('session-lost');
  });

  it.each([
    'User cancelled (SIGINT/SIGTERM); exiting.',
    'POST https://vpn.example.com/ssl-vpn/login.esp',
    'Connected to 203.0.113.10:443',
    'Using Wintun device "GP Connect"',
    'Idle timeout is 180 minutes.',
    '',
  ])('ignores informational line %j', (line) => {
    expect(parseLine(line)).toBeNull();
  });
});

describe('parsePrompt', () => {
  it('recognises the gateway select prompt', () => {
    expect(parsePrompt('GATEWAY: [Europe|US East]:')).toEqual({
      kind: 'select',
      label: 'GATEWAY',
      options: ['Europe', 'US East'],
    });
  });

  it.each(['Password:', 'Challenge: ', 'Enter passcode:', 'Token code:'])('secret prompt %j', (p) => {
    expect(parsePrompt(p)?.kind).toBe('secret');
  });

  it('recognises a username prompt as text', () => {
    expect(parsePrompt('Username:')).toEqual({ kind: 'text', label: 'Username' });
  });

  it('uses only the last line of a fragment', () => {
    expect(parsePrompt('Enter the code\nResponse:')).toEqual({ kind: 'secret', label: 'Response' });
  });

  it('recognises the untrusted certificate question', () => {
    expect(parsePrompt("Enter 'yes' to accept, 'no' to abort; anything else to view: ")).toEqual({
      kind: 'cert-confirm',
    });
  });

  it.each(['', 'Connected as 10.0.0.1', '10:20:', 'POST https://vpn.example.com/x'])('no prompt in %j', (p) => {
    expect(parsePrompt(p)).toBeNull();
  });
});

describe('LineSplitter', () => {
  it('joins chunks, splits CRLF/LF and keeps the trailing fragment', () => {
    const s = new LineSplitter();
    expect(s.push('Conn')).toEqual([]);
    expect(s.push('ected as 1.2.3.4\r\nESP')).toEqual(['Connected as 1.2.3.4']);
    expect(s.push(' ok\nPassword:')).toEqual(['ESP ok']);
    expect(s.partial).toBe('Password:');
    expect(s.takePartial()).toBe('Password:');
    expect(s.partial).toBe('');
    s.push('tail');
    expect(s.flush()).toEqual(['tail']);
  });
});

describe('CRLF / lone CR tolerance', () => {
  it('splits CRLF even when CR and LF arrive in different chunks', () => {
    const s = new LineSplitter();
    expect(s.push('Connected as 1.2.3.4\r')).toEqual([]);
    expect(s.partial).toBe('Connected as 1.2.3.4\r');
    expect(s.push('\nESP session established with server\r\n')).toEqual([
      'Connected as 1.2.3.4',
      'ESP session established with server',
    ]);
    expect(s.partial).toBe('');
  });

  it('treats a lone CR followed by more text as a line break', () => {
    const s = new LineSplitter();
    expect(s.push('progress 10%\rprogress 20%\n')).toEqual(['progress 10%', 'progress 20%']);
  });

  it('keeps a prompt terminated by a lone CR as the partial line', () => {
    const s = new LineSplitter();
    expect(s.push('Enter code\r\nPassword:\r')).toEqual(['Enter code']);
    expect(parsePrompt(s.partial)).toEqual({ kind: 'secret', label: 'Password' });
    expect(s.takePartial()).toBe('Password:\r');
  });

  it('drops a dangling CR at end of stream', () => {
    const s = new LineSplitter();
    s.push('Session terminated by server; exiting.\r');
    expect(s.flush()).toEqual(['Session terminated by server; exiting.']);
  });

  it('handles CR CR LF without producing garbage lines', () => {
    const s = new LineSplitter();
    expect(s.push('a\r\r\nb\r\n').filter((l) => l !== '')).toEqual(['a', 'b']);
  });

  it.each([
    ['GATEWAY: [Europe|US East]:\r', { kind: 'select', label: 'GATEWAY', options: ['Europe', 'US East'] }],
    ['Username:\r', { kind: 'text', label: 'Username' }],
    ["Enter 'yes' to accept, 'no' to abort; anything else to view: \r", { kind: 'cert-confirm' }],
  ])('parsePrompt(%j)', (fragment, expected) => {
    expect(parsePrompt(fragment)).toEqual(expected);
  });

  it('classifies CRLF-terminated lines like LF ones', () => {
    const p = new OutputParser();
    expect(p.parse('2 gateway servers available:\r')).toEqual({ type: 'gateway-list', count: 2 });
    expect(p.parse('  Europe (gw-eu.example.com) [1]\r')).toEqual({
      type: 'gateway',
      gateway: { name: 'Europe', address: 'gw-eu.example.com', priority: 1 },
    });
    expect(parseLine('Connected as 10.0.0.5, using SSL\r')).toEqual({ type: 'connected', ip: '10.0.0.5' });
  });
});
