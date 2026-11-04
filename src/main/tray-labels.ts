/** Tray menu / tooltip strings (pure, testable). */
import type { Language, VpnStatus } from '../shared/ipc';

export type TrayLabelKey = 'connect' | 'disconnect' | 'profiles' | 'noProfiles' | 'show' | 'quit' | VpnStatus;

export const TRAY_LABELS: Record<Language, Record<TrayLabelKey, string>> = {
  ru: {
    connect: 'Подключить',
    disconnect: 'Отключить',
    profiles: 'Профиль',
    noProfiles: 'Нет профилей',
    show: 'Показать окно',
    quit: 'Выход',
    disconnected: 'Отключено',
    prelogin: 'Подготовка…',
    authenticating: 'Вход…',
    connecting: 'Подключение…',
    connected: 'Подключено',
    disconnecting: 'Отключение…',
    reconnecting: 'Переподключение…',
    error: 'Ошибка',
  },
  en: {
    connect: 'Connect',
    disconnect: 'Disconnect',
    profiles: 'Profile',
    noProfiles: 'No profiles',
    show: 'Show window',
    quit: 'Quit',
    disconnected: 'Disconnected',
    prelogin: 'Preparing…',
    authenticating: 'Signing in…',
    connecting: 'Connecting…',
    connected: 'Connected',
    disconnecting: 'Disconnecting…',
    reconnecting: 'Reconnecting…',
    error: 'Error',
  },
  uk: {
    connect: 'Підключити',
    disconnect: 'Відключити',
    profiles: 'Профіль',
    noProfiles: 'Немає профілів',
    show: 'Показати вікно',
    quit: 'Вихід',
    disconnected: 'Відключено',
    prelogin: 'Підготовка…',
    authenticating: 'Вхід…',
    connecting: 'Підключення…',
    connected: 'Підключено',
    disconnecting: 'Відключення…',
    reconnecting: 'Перепідключення…',
    error: 'Помилка',
  },
};

/** Tooltip text, e.g. "GP Connect: Подключено — 10.0.0.5". */
export function trayTooltip(lang: Language, status: VpnStatus, assignedIp?: string): string {
  const ip = status === 'connected' && assignedIp ? ` — ${assignedIp}` : '';
  return `GP Connect: ${TRAY_LABELS[lang][status]}${ip}`;
}
