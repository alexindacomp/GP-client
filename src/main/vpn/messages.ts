import type { Language, VpnErrorCode, VpnErrorHint } from '../../shared/ipc';

/**
 * `VpnState.error.message`: only the next step for the user. The renderer shows
 * its own title per error code (and per hint), the technical cause goes to
 * `error.detail`. Messages must not reference the README (installed users don't
 * have it) and must use paths/tools of the current platform.
 */
const MESSAGES: Record<Language, Record<VpnErrorCode, string>> = {
  ru: {
    OPENCONNECT_NOT_FOUND: 'Установите OpenConnect или укажите путь к нему в настройках.',
    AUTH_FAILED: 'Проверьте логин, пароль или одноразовый код и попробуйте снова.',
    AUTH_CANCELLED: 'Нажмите «Подключить», чтобы войти снова.',
    PORTAL_UNREACHABLE: 'Проверьте адрес портала и подключение к сети.',
    TLS_ERROR:
      'Сервер предъявил неизвестный сертификат. Если вы доверяете ему, добавьте в доп. аргументы --servercert=pin-sha256:<…> — значение pin есть в журнале.',
    PRIVILEGES_DENIED: 'Подтвердите запрос прав администратора при подключении.',
    TUNNEL_FAILED: 'Попробуйте подключиться снова; подробности — в журнале.',
    UNKNOWN: 'Попробуйте подключиться снова; подробности — в журнале.',
  },
  en: {
    OPENCONNECT_NOT_FOUND: 'Install OpenConnect or set its path in Settings.',
    AUTH_FAILED: 'Check your username, password or one-time code and try again.',
    AUTH_CANCELLED: 'Press Connect to sign in again.',
    PORTAL_UNREACHABLE: 'Check the portal address and your network connection.',
    TLS_ERROR:
      'The server presented an unknown certificate. If you trust it, add --servercert=pin-sha256:<…> to extra arguments — the pin value is in the log.',
    PRIVILEGES_DENIED: 'Approve the administrator prompt when connecting.',
    TUNNEL_FAILED: 'Try connecting again; see the log for details.',
    UNKNOWN: 'Try connecting again; see the log for details.',
  },
  uk: {
    OPENCONNECT_NOT_FOUND: 'Встановіть OpenConnect або вкажіть шлях до нього в налаштуваннях.',
    AUTH_FAILED: 'Перевірте логін, пароль або одноразовий код і спробуйте ще раз.',
    AUTH_CANCELLED: 'Натисніть «Підключити», щоб увійти знову.',
    PORTAL_UNREACHABLE: 'Перевірте адресу порталу та підключення до мережі.',
    TLS_ERROR:
      'Сервер надав невідомий сертифікат. Якщо ви йому довіряєте, додайте в додаткові аргументи --servercert=pin-sha256:<…> — значення pin є в журналі.',
    PRIVILEGES_DENIED: 'Підтвердьте запит прав адміністратора під час підключення.',
    TUNNEL_FAILED: 'Спробуйте підключитися ще раз; подробиці — у журналі.',
    UNKNOWN: 'Спробуйте підключитися ще раз; подробиці — у журналі.',
  },
};

/** Cause-specific next steps that override the per-code text. */
export type ErrorHint = VpnErrorHint;

type HintPlatform = 'win32' | 'darwin' | 'linux';

const UNTRUSTED_BINARY: Record<Language, Record<HintPlatform, string>> = {
  ru: {
    win32:
      'Установите OpenConnect в «Program Files» (через установщик OpenConnect-GUI) — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
    darwin:
      'Установите OpenConnect через MacPorts: sudo port install openconnect — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
    linux:
      'Установите OpenConnect из репозитория (sudo apt install openconnect — он окажется в /usr/sbin или /usr/bin) — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
  },
  en: {
    win32:
      'Install OpenConnect into “Program Files” (with the OpenConnect-GUI installer) — the client only runs openconnect from folders that only an administrator can change.',
    darwin:
      'Install OpenConnect with MacPorts: sudo port install openconnect — the client only runs openconnect from folders that only an administrator can change.',
    linux:
      'Install OpenConnect from your distribution (sudo apt install openconnect — it goes to /usr/sbin or /usr/bin) — the client only runs openconnect from folders that only an administrator can change.',
  },
  uk: {
    win32:
      'Встановіть OpenConnect у «Program Files» (через інсталятор OpenConnect-GUI) — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
    darwin:
      'Встановіть OpenConnect через MacPorts: sudo port install openconnect — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
    linux:
      'Встановіть OpenConnect із репозиторію (sudo apt install openconnect — він опиниться в /usr/sbin або /usr/bin) — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор.',
  },
};

const OTHER_HINTS: Record<Language, Record<Exclude<ErrorHint, 'untrusted_binary'>, string>> = {
  ru: {
    untrusted_homebrew:
      'OpenConnect из Homebrew может изменить любая программа пользователя. Установите его через MacPorts: sudo port install openconnect.',
    stop_failed:
      'VPN может быть ещё активен: для остановки openconnect нужна авторизация администратора. Нажмите «Отключить» ещё раз.',
    settings_not_confirmed:
      'Подключитесь снова и подтвердите изменённые настройки openconnect или исправьте их в настройках.',
  },
  en: {
    untrusted_homebrew:
      'Homebrew’s OpenConnect can be modified by any of your programs. Install it with MacPorts: sudo port install openconnect.',
    stop_failed:
      'The VPN may still be active: stopping openconnect needs administrator authorization. Press Disconnect again.',
    settings_not_confirmed: 'Connect again and confirm the changed openconnect settings, or correct them in Settings.',
  },
  uk: {
    untrusted_homebrew:
      'OpenConnect із Homebrew може змінити будь-яка програма користувача. Встановіть його через MacPorts: sudo port install openconnect.',
    stop_failed:
      'VPN може бути ще активним: для зупинки openconnect потрібна авторизація адміністратора. Натисніть «Відключити» ще раз.',
    settings_not_confirmed:
      'Підключіться знову й підтвердьте змінені налаштування openconnect або виправте їх у налаштуваннях.',
  },
};

const PROMPTS: Record<Language, { username: string; password: string }> = {
  ru: { username: 'Имя пользователя', password: 'Пароль' },
  en: { username: 'Username', password: 'Password' },
  uk: { username: 'Ім’я користувача', password: 'Пароль' },
};

const MAX_DETAIL = 300;

function hintPlatform(platform: NodeJS.Platform): HintPlatform {
  return platform === 'win32' || platform === 'darwin' ? platform : 'linux';
}

/** User-facing next step for an error code (or a cause-specific hint), for the given platform. */
export function errorMessage(
  code: VpnErrorCode,
  lang: Language,
  hint?: ErrorHint,
  platform: NodeJS.Platform = process.platform,
): string {
  if (hint === 'untrusted_binary') return UNTRUSTED_BINARY[lang][hintPlatform(platform)];
  if (hint) return OTHER_HINTS[lang][hint];
  return MESSAGES[lang][code];
}

/** Technical detail for `VpnState.error.detail` (already masked by the caller), trimmed and capped. */
export function errorDetail(detail: string | undefined): string | undefined {
  const d = detail?.trim();
  if (!d) return undefined;
  return d.length > MAX_DETAIL ? `${d.slice(0, MAX_DETAIL)}…` : d;
}

export function promptLabel(kind: 'username' | 'password', lang: Language): string {
  return PROMPTS[lang][kind];
}

/** Shown when openconnect survives both the graceful stop and the kill. */
export function stopFailedMessage(lang: Language): string {
  return OTHER_HINTS[lang].stop_failed;
}

/** For tests: every language/hint/platform combination that can be rendered. */
export const ALL_LANGUAGES: readonly Language[] = ['ru', 'en', 'uk'];
export const ALL_HINTS: readonly ErrorHint[] = [
  'untrusted_binary',
  'untrusted_homebrew',
  'stop_failed',
  'settings_not_confirmed',
];
