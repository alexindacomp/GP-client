/**
 * Texts of the native confirmation dialog for elevation-relevant settings
 * (pure, testable). Localized with human labels; Cancel is button 0 and is both
 * the default and the cancel button.
 */
import type { Language, Settings } from '../../shared/ipc';
import type { GuardedKey } from './confirmed-settings';

export type ConfirmKind = 'change' | 'external';

export interface ConfirmItem {
  key: GuardedKey;
  value: Settings[GuardedKey];
  /** Value was changed outside the app (on disk) and is shown for confirmation too. */
  external?: boolean;
}

export interface ConfirmDialogText {
  title: string;
  message: string;
  detail: string;
  /** [cancel, apply] — index 0 is default and cancel. */
  buttons: [string, string];
}

interface Strings {
  labels: Record<GuardedKey, string>;
  default: string;
  none: string;
  externalSuffix: string;
  change: string;
  external: string;
  buttons: [string, string];
}

const STRINGS: Record<Language, Strings> = {
  ru: {
    labels: {
      openconnectPath: 'Путь к openconnect',
      hipScriptPath: 'HIP-скрипт',
      extraArgs: 'Дополнительные аргументы',
    },
    default: 'по умолчанию',
    none: 'нет',
    externalSuffix: ' (изменено вне GP Connect)',
    change: 'Подтвердите изменения: эти параметры определяют, что запускается с правами администратора.',
    external: 'Эти настройки изменены вне GP Connect. Использовать их при запуске с правами администратора?',
    buttons: ['Отмена', 'Применить'],
  },
  en: {
    labels: {
      openconnectPath: 'OpenConnect path',
      hipScriptPath: 'HIP script',
      extraArgs: 'Extra arguments',
    },
    default: 'default',
    none: 'none',
    externalSuffix: ' (changed outside GP Connect)',
    change: 'Confirm the changes: these settings control what runs with administrator rights.',
    external: 'These settings were changed outside GP Connect. Use them when running with administrator rights?',
    buttons: ['Cancel', 'Apply'],
  },
  uk: {
    labels: {
      openconnectPath: 'Шлях до openconnect',
      hipScriptPath: 'HIP-скрипт',
      extraArgs: 'Додаткові аргументи',
    },
    default: 'за замовчуванням',
    none: 'немає',
    externalSuffix: ' (змінено поза GP Connect)',
    change: 'Підтвердьте зміни: ці параметри визначають, що запускається з правами адміністратора.',
    external: 'Ці налаштування змінено поза GP Connect. Використовувати їх під час запуску з правами адміністратора?',
    buttons: ['Скасувати', 'Застосувати'],
  },
};

function formatValue(item: ConfirmItem, s: Strings): string {
  const v = item.value;
  if (v === undefined) return s.default;
  if (Array.isArray(v)) return v.length ? v.join(' ') : s.none;
  return v;
}

export function confirmDialogText(kind: ConfirmKind, lang: Language, items: readonly ConfirmItem[]): ConfirmDialogText {
  const s = STRINGS[lang];
  return {
    title: 'GP Connect',
    message: kind === 'change' ? s.change : s.external,
    detail: items
      .map((it) => `${s.labels[it.key]}: ${formatValue(it, s)}${it.external ? s.externalSuffix : ''}`)
      .join('\n'),
    buttons: [...s.buttons],
  };
}
