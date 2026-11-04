import { randomUUID } from 'node:crypto';
import type { Profile, ProfileInput } from '../../shared/ipc';
import { quarantineFile, readJsonFile, writeJsonFile } from './json-file';
import { validateId, validateProfileInput, ValidationError } from './validation';

/** OS-backed encryption (Electron `safeStorage`), injected for testability. */
export interface SecretCipher {
  /** False when no real OS keystore is available (e.g. Linux without a keyring). */
  isAvailable(): boolean;
  encrypt(plain: string): Buffer;
  decrypt(data: Buffer): string;
}

interface ProfilesFile {
  version: 1;
  profiles: Profile[];
  /** profileId → base64 of the safeStorage-encrypted password. */
  passwords: Record<string, string>;
}

export class ProfilesStore {
  private data: ProfilesFile;

  constructor(
    private readonly file: string,
    private readonly cipher: SecretCipher,
    private readonly onWarning: (msg: string) => void = () => undefined,
  ) {
    this.data = this.load();
  }

  list(): Profile[] {
    return structuredClone(this.data.profiles);
  }

  get(id: string): Profile | undefined {
    const p = this.data.profiles.find((x) => x.id === id);
    return p ? structuredClone(p) : undefined;
  }

  /**
   * Creates or updates a profile. The password is stored only when
   * `savePassword` is set and OS encryption is available; turning
   * `savePassword` off deletes a stored password.
   */
  save(input: ProfileInput, password?: string): Profile {
    const id = input.id ?? randomUUID();
    const idx = this.data.profiles.findIndex((x) => x.id === id);
    if (input.id !== undefined && idx === -1)
      throw new ValidationError('Profile not found', { field: 'id', code: 'not_found' });

    const profile: Profile = {
      id,
      name: input.name,
      portalUrl: input.portalUrl,
      authMode: input.authMode,
      savePassword: input.savePassword,
    };
    if (input.username !== undefined) profile.username = input.username;
    if (input.preferredGateway !== undefined) profile.preferredGateway = input.preferredGateway;

    const passwords = { ...this.data.passwords };
    if (!profile.savePassword || profile.authMode === 'saml') {
      delete passwords[id];
    } else if (password !== undefined) {
      if (this.cipher.isAvailable()) {
        passwords[id] = this.cipher.encrypt(password).toString('base64');
      } else {
        this.onWarning('OS secure storage is unavailable; the password was not saved');
        delete passwords[id];
      }
    }
    const profiles = [...this.data.profiles];
    if (idx === -1) profiles.push(profile);
    else profiles[idx] = profile;
    this.persist({ version: 1, profiles, passwords });
    return structuredClone(profile);
  }

  remove(id: string): void {
    const profiles = this.data.profiles.filter((p) => p.id !== id);
    const passwords = { ...this.data.passwords };
    delete passwords[id];
    this.persist({ version: 1, profiles, passwords });
  }

  hasSavedPassword(id: string): boolean {
    return id in this.data.passwords;
  }

  /** Decrypted saved password; never exposed over IPC. */
  getPassword(id: string): string | undefined {
    const enc = this.data.passwords[id];
    if (!enc || !this.cipher.isAvailable()) return undefined;
    try {
      return this.cipher.decrypt(Buffer.from(enc, 'base64'));
    } catch (err) {
      this.onWarning(`Stored password for profile ${id} cannot be decrypted: ${(err as Error).message}`);
      return undefined;
    }
  }

  private persist(next: ProfilesFile): void {
    writeJsonFile(this.file, next);
    this.data = next;
  }

  private load(): ProfilesFile {
    const empty: ProfilesFile = { version: 1, profiles: [], passwords: {} };
    let raw: unknown;
    try {
      raw = readJsonFile(this.file);
    } catch (err) {
      const moved = quarantineFile(this.file);
      this.onWarning(`profiles.json is unreadable (${(err as Error).message})${moved ? `; moved to ${moved}` : ''}`);
      return empty;
    }
    if (raw === undefined) return empty;
    if (typeof raw !== 'object' || raw === null) return empty;
    const obj = raw as Partial<ProfilesFile>;
    const profiles: Profile[] = [];
    for (const p of Array.isArray(obj.profiles) ? obj.profiles : []) {
      try {
        const v = validateProfileInput(p);
        const id = validateId((p as { id?: unknown }).id);
        profiles.push({ ...v, id } as Profile);
      } catch (err) {
        this.onWarning(`Skipping invalid profile in profiles.json: ${(err as Error).message}`);
      }
    }
    const passwords: Record<string, string> = {};
    if (obj.passwords && typeof obj.passwords === 'object') {
      for (const [id, v] of Object.entries(obj.passwords)) {
        if (typeof v === 'string' && profiles.some((p) => p.id === id)) passwords[id] = v;
      }
    }
    return { version: 1, profiles, passwords };
  }
}
