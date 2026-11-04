import { DEFAULT_SETTINGS, type Settings } from '../../shared/ipc';
import { quarantineFile, readJsonFile, writeJsonFile } from './json-file';
import { validateSettingsPatch } from './validation';

export type SettingsListener = (next: Settings, prev: Settings) => void;

/** `settings.json` in userData. Invalid values on disk are dropped field-by-field. */
export class SettingsStore {
  private settings: Settings;
  private readonly listeners = new Set<SettingsListener>();

  constructor(
    private readonly file: string,
    private readonly onWarning: (msg: string) => void = () => undefined,
  ) {
    this.settings = this.load();
  }

  get(): Settings {
    return structuredClone(this.settings);
  }

  /** Applies an already validated patch (see {@link validateSettingsPatch}). */
  set(patch: Partial<Settings>): Settings {
    const prev = this.settings;
    const next: Settings = { ...prev };
    for (const [k, v] of Object.entries(patch) as [keyof Settings, unknown][]) {
      if (v === undefined) delete (next as unknown as Record<string, unknown>)[k];
      else (next as unknown as Record<string, unknown>)[k] = v;
    }
    writeJsonFile(this.file, next);
    this.settings = next;
    for (const l of this.listeners) l(this.get(), structuredClone(prev));
    return this.get();
  }

  onChange(l: SettingsListener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  private load(): Settings {
    let raw: unknown;
    try {
      raw = readJsonFile(this.file);
    } catch (err) {
      const moved = quarantineFile(this.file);
      this.onWarning(
        `settings.json is unreadable (${(err as Error).message}); using defaults${moved ? `, old file kept at ${moved}` : ''}`,
      );
      return { ...DEFAULT_SETTINGS };
    }
    const result: Settings = { ...DEFAULT_SETTINGS, extraArgs: [...DEFAULT_SETTINGS.extraArgs] };
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return result;
    for (const [k, v] of Object.entries(raw)) {
      try {
        Object.assign(result, validateSettingsPatch({ [k]: v }));
      } catch (err) {
        this.onWarning(`Ignoring invalid setting "${k}": ${(err as Error).message}`);
      }
    }
    return result;
  }
}
