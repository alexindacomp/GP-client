import type { Settings } from '../../shared/ipc';

/** Settings that influence what runs with administrator rights. */
export const SENSITIVE_SETTINGS = ['openconnectPath', 'hipScriptPath', 'extraArgs'] as const;
export type SensitiveSetting = (typeof SENSITIVE_SETTINGS)[number];

export interface SensitiveChange {
  key: SensitiveSetting;
  value: string;
}

/** Human-readable value for the confirmation dialog. */
export function showSettingValue(v: unknown): string {
  if (v === undefined) return '(default)';
  if (Array.isArray(v)) return v.length ? v.join(' ') : '(none)';
  return String(v);
}

/**
 * Sensitive settings that a (validated) patch actually changes, with the new
 * value rendered for a confirmation dialog shown by the main process.
 */
export function sensitiveChanges(current: Settings, patch: Partial<Settings>): SensitiveChange[] {
  const out: SensitiveChange[] = [];
  for (const key of SENSITIVE_SETTINGS) {
    if (!Object.prototype.hasOwnProperty.call(patch, key)) continue;
    const next = patch[key];
    const prev = current[key];
    const same = Array.isArray(next) && Array.isArray(prev) ? next.join('\0') === prev.join('\0') : next === prev;
    if (!same) out.push({ key, value: showSettingValue(next) });
  }
  return out;
}
