import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConfirmedSettingsGuard } from './confirmed-settings';
import type { SecretCipher } from './profiles-store';

/** Reversible fake "OS encryption" (a real one is not available in tests). */
const cipher = (available = true): SecretCipher => ({
  isAvailable: () => available,
  encrypt: (s) => Buffer.from(`enc:${s}`),
  decrypt: (b) => {
    const t = b.toString();
    if (!t.startsWith('enc:')) throw new Error('bad ciphertext');
    return t.slice(4);
  },
});

let dir: string;
let file: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-confirm-'));
  file = path.join(dir, 'confirmed-settings.json');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const custom = { openconnectPath: '/usr/local/sbin/openconnect', hipScriptPath: undefined, extraArgs: ['-v'] };

describe('ConfirmedSettingsGuard', () => {
  it('does not require confirmation for defaults', () => {
    expect(new ConfirmedSettingsGuard(file, cipher()).isConfirmed({ extraArgs: [] })).toBe(true);
  });

  it('requires confirmation for unconfirmed (e.g. disk-edited) values', () => {
    expect(new ConfirmedSettingsGuard(file, cipher()).isConfirmed(custom)).toBe(false);
  });

  it('remembers confirmed values across restarts', () => {
    new ConfirmedSettingsGuard(file, cipher()).confirm(custom);
    const g = new ConfirmedSettingsGuard(file, cipher());
    expect(g.isConfirmed(custom)).toBe(true);
    // a disk tamper of any guarded value invalidates the confirmation
    expect(g.isConfirmed({ ...custom, extraArgs: ['-v', '--no-dtls'] })).toBe(false);
    expect(g.isConfirmed({ ...custom, openconnectPath: '/tmp/openconnect' })).toBe(false);
    expect(g.isConfirmed({ ...custom, hipScriptPath: '/tmp/hip.sh' })).toBe(false);
  });

  it('cannot be forged by editing the record without the keystore key', () => {
    new ConfirmedSettingsGuard(file, cipher()).confirm(custom);
    const rec = JSON.parse(fs.readFileSync(file, 'utf8')) as { key: string; mac: string };
    // attacker replaces the key with one they know
    rec.key = Buffer.from('not-encrypted').toString('base64');
    fs.writeFileSync(file, JSON.stringify(rec));
    expect(new ConfirmedSettingsGuard(file, cipher()).isConfirmed(custom)).toBe(false);
  });

  it('without a keystore keeps the confirmation in memory only', () => {
    const g = new ConfirmedSettingsGuard(file, cipher(false));
    g.confirm(custom);
    expect(g.isConfirmed(custom)).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
    expect(new ConfirmedSettingsGuard(file, cipher(false)).isConfirmed(custom)).toBe(false);
  });
});

describe('ConfirmedSettingsGuard per-field (SEC-S3)', () => {
  it('confirming one field does not confirm another edited on disk', () => {
    const g = new ConfirmedSettingsGuard(file, cipher());
    const s = { openconnectPath: '/usr/local/sbin/openconnect', hipScriptPath: '/tmp/evil.sh', extraArgs: ['-v'] };
    expect(g.unconfirmedFields(s)).toEqual(['openconnectPath', 'hipScriptPath', 'extraArgs']);
    g.confirm(s, ['openconnectPath']);
    expect(g.unconfirmedFields(s)).toEqual(['hipScriptPath', 'extraArgs']);
    expect(new ConfirmedSettingsGuard(file, cipher()).unconfirmedFields(s)).toEqual(['hipScriptPath', 'extraArgs']);
  });

  it('default fields are never reported', () => {
    const g = new ConfirmedSettingsGuard(file, cipher());
    expect(g.unconfirmedFields({ openconnectPath: undefined, hipScriptPath: undefined, extraArgs: [] })).toEqual([]);
  });

  it('ignores records of the old (whole-object) format', () => {
    fs.writeFileSync(file, JSON.stringify({ version: 1, key: 'x', mac: 'f'.repeat(64) }));
    expect(new ConfirmedSettingsGuard(file, cipher()).isConfirmed(custom)).toBe(false);
  });
});
