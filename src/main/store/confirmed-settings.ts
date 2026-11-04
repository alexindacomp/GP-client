/**
 * Remembers which values of the elevation-relevant settings (openconnectPath,
 * hipScriptPath, extraArgs) the user confirmed in the main-process dialog.
 *
 * A value set edited on disk (bypassing the IPC confirmation) has a different
 * fingerprint and must be confirmed again before the next elevated spawn. The
 * fingerprint is an HMAC whose key is protected by the OS keystore (safeStorage),
 * so an attacker who can only edit files cannot forge it. Without a keystore the
 * key lives in memory only: confirmation is then asked once per app run.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Settings } from '../../shared/ipc';
import type { SecretCipher } from './profiles-store';
import { readJsonFile, writeJsonFile } from './json-file';

export type GuardedSettings = Pick<Settings, 'openconnectPath' | 'hipScriptPath' | 'extraArgs'>;
export const GUARDED_KEYS = ['openconnectPath', 'hipScriptPath', 'extraArgs'] as const;
export type GuardedKey = (typeof GUARDED_KEYS)[number];

interface ConfirmedFile {
  version: 2;
  /** safeStorage-encrypted HMAC key, base64. */
  key: string;
  /** Per-field HMAC-SHA256 (hex) of the confirmed value. */
  macs: Partial<Record<GuardedKey, string>>;
}

function canonicalValue(key: GuardedKey, s: GuardedSettings): string {
  return JSON.stringify([key, key === 'extraArgs' ? [...(s.extraArgs ?? [])] : (s[key] ?? null)]);
}

/** A field at its default needs no confirmation: nothing user-chosen runs elevated. */
export function isDefaultField(key: GuardedKey, s: GuardedSettings): boolean {
  return key === 'extraArgs' ? (s.extraArgs ?? []).length === 0 : s[key] === undefined;
}

export function isDefaultGuarded(s: GuardedSettings): boolean {
  return GUARDED_KEYS.every((k) => isDefaultField(k, s));
}

/**
 * Per-field confirmation record. Confirming one field never confirms another,
 * so a value edited on disk cannot ride along with an unrelated confirmed change.
 */
export class ConfirmedSettingsGuard {
  private key: Buffer | null = null;
  private macs: Partial<Record<GuardedKey, string>> = {};

  constructor(
    private readonly file: string,
    private readonly cipher: SecretCipher,
    private readonly onWarning: (msg: string) => void = () => undefined,
  ) {
    this.load();
  }

  /** Guarded fields of `s` that are neither default nor confirmed. */
  unconfirmedFields(s: GuardedSettings): GuardedKey[] {
    return GUARDED_KEYS.filter((k) => !isDefaultField(k, s) && !this.matches(k, s));
  }

  /** True when every guarded field is default or exactly what the user confirmed. */
  isConfirmed(s: GuardedSettings): boolean {
    return this.unconfirmedFields(s).length === 0;
  }

  /** Records the given fields of `s` (the ones shown to the user) as confirmed. */
  confirm(s: GuardedSettings, keys: readonly GuardedKey[] = GUARDED_KEYS): void {
    if (!this.key) this.key = randomBytes(32);
    for (const k of keys) {
      if (isDefaultField(k, s)) delete this.macs[k];
      else this.macs[k] = this.compute(k, s);
    }
    if (!this.cipher.isAvailable()) return; // in-memory only
    try {
      const data: ConfirmedFile = {
        version: 2,
        key: this.cipher.encrypt(this.key.toString('base64')).toString('base64'),
        macs: this.macs,
      };
      writeJsonFile(this.file, data);
    } catch (err) {
      this.onWarning(`Cannot persist confirmed settings: ${(err as Error).message}`);
    }
  }

  private matches(k: GuardedKey, s: GuardedSettings): boolean {
    const mac = this.macs[k];
    if (!this.key || !mac) return false;
    const want = Buffer.from(mac, 'hex');
    const got = Buffer.from(this.compute(k, s), 'hex');
    return want.length === got.length && timingSafeEqual(want, got);
  }

  private compute(k: GuardedKey, s: GuardedSettings): string {
    return createHmac('sha256', this.key!).update(canonicalValue(k, s)).digest('hex');
  }

  private load(): void {
    try {
      const raw = readJsonFile(this.file) as Partial<ConfirmedFile> | undefined;
      if (!raw || raw.version !== 2 || typeof raw.key !== 'string' || typeof raw.macs !== 'object' || !raw.macs) return;
      if (!this.cipher.isAvailable()) return;
      const key = Buffer.from(this.cipher.decrypt(Buffer.from(raw.key, 'base64')), 'base64');
      if (key.length !== 32) return;
      const macs: Partial<Record<GuardedKey, string>> = {};
      for (const k of GUARDED_KEYS) {
        const m = (raw.macs as Record<string, unknown>)[k];
        if (typeof m === 'string' && /^[0-9a-f]{64}$/.test(m)) macs[k] = m;
      }
      this.key = key;
      this.macs = macs;
    } catch (err) {
      this.onWarning(`Ignoring confirmed-settings record: ${(err as Error).message}`);
    }
  }
}
