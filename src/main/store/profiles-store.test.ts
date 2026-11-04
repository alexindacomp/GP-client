import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ProfileInput } from '../../shared/ipc';
import { parseIpcError } from '../../shared/validation';
import { ProfilesStore, type SecretCipher } from './profiles-store';

/** Reversible fake "OS encryption" whose availability can be switched at runtime. */
function fakeCipher(): SecretCipher & { available: boolean } {
  const c = {
    available: true,
    isAvailable: () => c.available,
    encrypt: (s: string) => Buffer.from(`enc:${Buffer.from(s).toString('hex')}`),
    decrypt: (b: Buffer) => {
      const t = b.toString();
      if (!t.startsWith('enc:')) throw new Error('bad ciphertext');
      return Buffer.from(t.slice(4), 'hex').toString();
    },
  };
  return c;
}

const ID_A = '11111111-1111-4111-8111-111111111111';
const ID_B = '22222222-2222-4222-8222-222222222222';
const INPUT: ProfileInput = {
  name: 'Work',
  portalUrl: 'https://vpn.example.com',
  username: 'alice',
  authMode: 'password',
  savePassword: true,
};

let dir: string;
let file: string;
let warnings: string[];
let cipher: ReturnType<typeof fakeCipher>;

const open = (): ProfilesStore => new ProfilesStore(file, cipher, (m) => warnings.push(m));
const onDisk = (): { profiles: unknown[]; passwords: Record<string, string> } =>
  JSON.parse(fs.readFileSync(file, 'utf8')) as { profiles: unknown[]; passwords: Record<string, string> };

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-profiles-'));
  file = path.join(dir, 'profiles.json');
  warnings = [];
  cipher = fakeCipher();
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('ProfilesStore: CRUD and persistence', () => {
  it('starts empty without a file and persists created profiles across restarts', () => {
    const store = open();
    expect(store.list()).toEqual([]);
    const saved = store.save(INPUT, 'S3cret!');
    expect(saved.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(open().list()).toEqual([saved]);
    expect(open().getPassword(saved.id)).toBe('S3cret!');
  });

  it('updates in place by id and refuses to update an unknown id', () => {
    const store = open();
    const a = store.save(INPUT);
    store.save({ ...INPUT, id: a.id, name: 'Renamed', username: undefined });
    // Cleared optional fields disappear instead of keeping the old value.
    expect(open().list()).toEqual([
      { id: a.id, name: 'Renamed', portalUrl: 'https://vpn.example.com', authMode: 'password', savePassword: true },
    ]);

    let err: unknown;
    try {
      store.save({ ...INPUT, id: ID_B });
    } catch (e) {
      err = e;
    }
    expect(parseIpcError(err)).toEqual({ field: 'id', code: 'not_found', message: 'Profile not found' });
    expect(open().list()).toHaveLength(1);
  });

  it('remove deletes the profile and its stored password', () => {
    const store = open();
    const a = store.save(INPUT, 'S3cret!');
    const b = store.save({ ...INPUT, name: 'Other' }, 'Other-pw');
    store.remove(a.id);
    const reopened = open();
    expect(reopened.list().map((p) => p.id)).toEqual([b.id]);
    expect(reopened.getPassword(a.id)).toBeUndefined();
    expect(Object.keys(onDisk().passwords)).toEqual([b.id]);
  });

  it('list/get return copies: mutating them does not change the store', () => {
    const store = open();
    const a = store.save(INPUT);
    store.list()[0]!.name = 'hacked';
    store.get(a.id)!.portalUrl = 'https://evil.example.com';
    expect(store.get(a.id)).toMatchObject({ name: 'Work', portalUrl: 'https://vpn.example.com' });
  });
});

describe('ProfilesStore: saved passwords', () => {
  it('stores only ciphertext on disk, never the plain password', () => {
    const store = open();
    const a = store.save(INPUT, 'S3cret!');
    const raw = fs.readFileSync(file, 'utf8');
    expect(raw).not.toContain('S3cret!');
    expect(onDisk().passwords[a.id]).toBe(cipher.encrypt('S3cret!').toString('base64'));
    expect(store.hasSavedPassword(a.id)).toBe(true);
  });

  it('keeps the stored password when a profile is edited without re-entering it', () => {
    const store = open();
    const a = store.save(INPUT, 'S3cret!');
    store.save({ ...INPUT, id: a.id, name: 'Renamed' });
    expect(open().getPassword(a.id)).toBe('S3cret!');
  });

  it('turning savePassword off deletes the stored password', () => {
    const store = open();
    const a = store.save(INPUT, 'S3cret!');
    store.save({ ...INPUT, id: a.id, savePassword: false });
    expect(store.getPassword(a.id)).toBeUndefined();
    expect(onDisk().passwords).toEqual({});
  });

  it('never stores a password for a SAML profile', () => {
    const store = open();
    const a = store.save({ ...INPUT, authMode: 'saml' }, 'S3cret!');
    expect(store.hasSavedPassword(a.id)).toBe(false);
    expect(fs.readFileSync(file, 'utf8')).not.toContain('enc:');
  });

  it('without OS secure storage: keeps savePassword on the profile but stores nothing, and warns', () => {
    cipher.available = false;
    const store = open();
    const a = store.save(INPUT, 'S3cret!');
    expect(a.savePassword).toBe(true);
    expect(store.hasSavedPassword(a.id)).toBe(false);
    expect(store.getPassword(a.id)).toBeUndefined();
    expect(fs.readFileSync(file, 'utf8')).not.toContain('S3cret!');
    expect(warnings).toEqual(['OS secure storage is unavailable; the password was not saved']);
  });

  it('a new password entered while secure storage is unavailable drops the older stored one', () => {
    const store = open();
    const a = store.save(INPUT, 'Old-pass');
    cipher.available = false;
    store.save({ ...INPUT, id: a.id }, 'New-pass');
    cipher.available = true;
    expect(store.getPassword(a.id)).toBeUndefined(); // never silently uses the stale password
  });

  it('does not decrypt while secure storage is unavailable (e.g. keyring locked at startup)', () => {
    const a = open().save(INPUT, 'S3cret!');
    cipher.available = false;
    expect(open().getPassword(a.id)).toBeUndefined();
    cipher.available = true;
    expect(open().getPassword(a.id)).toBe('S3cret!');
  });

  it('a ciphertext that cannot be decrypted (other OS user / reinstalled keyring) yields no password and a warning', () => {
    const a = open().save(INPUT, 'S3cret!');
    const data = onDisk();
    data.passwords[a.id] = Buffer.from('garbage').toString('base64');
    fs.writeFileSync(file, JSON.stringify(data));
    expect(open().getPassword(a.id)).toBeUndefined();
    expect(warnings.join('\n')).toMatch(/cannot be decrypted: bad ciphertext/);
  });
});

describe('ProfilesStore: corrupted or tampered profiles.json', () => {
  it('unparseable JSON is moved aside and the app starts with no profiles', () => {
    fs.writeFileSync(file, '{"version":1,"profiles":[{');
    const store = open();
    expect(store.list()).toEqual([]);
    const files = fs.readdirSync(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^profiles\.json\.corrupt-\d+$/);
    expect(fs.readFileSync(path.join(dir, files[0]!), 'utf8')).toBe('{"version":1,"profiles":[{');
    expect(warnings[0]).toMatch(/profiles\.json is unreadable .*; moved to .*profiles\.json\.corrupt-\d+/);
    // Saving afterwards writes a fresh, valid file.
    store.save(INPUT);
    expect(open().list()).toHaveLength(1);
  });

  it.each([['null'], ['"text"'], ['42'], ['[]']])('a JSON value of the wrong shape (%s) yields no profiles', (raw) => {
    fs.writeFileSync(file, raw);
    expect(open().list()).toEqual([]);
  });

  it('drops invalid profiles individually (http portal, bad id, unknown fields), keeps valid ones normalised', () => {
    fs.writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        profiles: [
          {
            id: ID_A,
            name: ' Good ',
            portalUrl: 'VPN.example.com/global-protect',
            authMode: 'auto',
            savePassword: false,
          },
          { id: ID_B, name: 'Http', portalUrl: 'http://vpn.example.com', authMode: 'auto', savePassword: false },
          { id: '../../x', name: 'BadId', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false },
          { name: 'NoId', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false },
          { id: ID_B, name: 'Extra', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false, cmd: 'x' },
          'not an object',
        ],
        passwords: {},
      }),
    );
    expect(open().list()).toEqual([
      { id: ID_A, name: 'Good', portalUrl: 'https://vpn.example.com', authMode: 'auto', savePassword: false },
    ]);
    expect(warnings).toHaveLength(5);
    expect(warnings.every((w) => w.startsWith('Skipping invalid profile in profiles.json'))).toBe(true);
  });

  it('ignores stored passwords of unknown profiles and non-string ciphertexts', () => {
    fs.writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        profiles: [{ id: ID_A, name: 'A', portalUrl: 'vpn.example.com', authMode: 'password', savePassword: true }],
        passwords: { [ID_B]: cipher.encrypt('orphan').toString('base64'), [ID_A]: { x: 1 } },
      }),
    );
    const store = open();
    expect(store.hasSavedPassword(ID_A)).toBe(false);
    expect(store.hasSavedPassword(ID_B)).toBe(false);
    store.save({ ...INPUT, id: ID_A });
    expect(onDisk().passwords).toEqual({});
  });
});
