import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildBridgeScript, waitForBridgeClient } from './win32-elevated-spawner';

// The pipe logic is platform-neutral. On Windows net.Server needs a real named
// pipe (\\.\pipe\<name>); elsewhere a Unix socket in a temp dir stands in for it.
let dir: string | undefined;
let sock: string;
let server: net.Server;
/** Server-side sockets, destroyed in afterEach so close() cannot hang (named pipes on Windows). */
let accepted: net.Socket[] = [];

function listenPath(): string {
  if (process.platform === 'win32') {
    dir = undefined; // named pipes are not files: nothing to clean up on disk
    return `\\\\.\\pipe\\gp-bridge-test-${randomBytes(8).toString('hex')}`;
  }
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-bridge-'));
  return path.join(dir, 's');
}

beforeEach(async () => {
  sock = listenPath();
  accepted = [];
  server = net.createServer();
  server.on('connection', (c) => accepted.push(c));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(sock, () => {
      server.off('error', reject);
      resolve();
    });
  });
});
afterEach(async () => {
  for (const c of accepted) c.destroy();
  if (server.listening) await new Promise<void>((r) => server.close(() => r()));
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const TOKEN = 'a'.repeat(64);

function connect(): Promise<net.Socket> {
  return new Promise((resolve) => {
    const c = net.createConnection(sock, () => resolve(c));
    c.on('error', () => undefined);
  });
}
function closed(c: net.Socket): Promise<void> {
  return new Promise((r) => (c.destroyed ? r() : c.once('close', () => r())));
}

describe('waitForBridgeClient', () => {
  it('drops an idle client after the hello deadline and still accepts the real bridge', async () => {
    const w = waitForBridgeClient(server, TOKEN, 100);
    const idle = await connect();
    await closed(idle); // dropped by the deadline
    const real = await connect();
    real.write(`H:${TOKEN}\nO:aGk=\n`);
    const client = await w.promise;
    expect(client.rest).toBe('O:aGk=\n');
    client.socket.destroy();
    real.destroy();
    w.dispose();
  });

  it('drops a client with a wrong token and keeps listening', async () => {
    const w = waitForBridgeClient(server, TOKEN, 1000);
    const bad = await connect();
    bad.write(`H:${'b'.repeat(64)}\n`);
    await closed(bad);
    const real = await connect();
    real.write(`H:${TOKEN}\n`);
    const client = await w.promise;
    expect(client.rest).toBe('');
    client.socket.destroy();
    real.destroy();
    w.dispose();
  });

  it('drops oversized hellos and late clients after a winner', async () => {
    const w = waitForBridgeClient(server, TOKEN, 1000);
    const big = await connect();
    big.write('x'.repeat(300));
    await closed(big);
    const real = await connect();
    real.write(`H:${TOKEN}\n`);
    const client = await w.promise;
    const late = await connect();
    late.write(`H:${TOKEN}\n`);
    await closed(late);
    client.socket.destroy();
    real.destroy();
    w.dispose();
  });
});

describe('buildBridgeScript', () => {
  it('embeds only the config path and hash, and compiles Add-Type outside the user TEMP', () => {
    const script = buildBridgeScript('C:\\Users\\a\\AppData\\Local\\Temp\\gp-connect-x\\bridge.json', 'f'.repeat(64));
    expect(script).not.toContain('__CONFIG');
    expect(script).toContain("'" + 'f'.repeat(64) + "'");
    expect(script).toMatch(/GetFolderPath\('CommonApplicationData'\)[\s\S]*\$env:TEMP = \$tmp[\s\S]*Add-Type/);
    expect(() => buildBridgeScript('x', 'nothex')).toThrow();
  });
});
