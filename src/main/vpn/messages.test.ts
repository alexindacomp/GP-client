import { describe, expect, it } from 'vitest';
import type { VpnErrorCode } from '../../shared/ipc';
import { ALL_HINTS, ALL_LANGUAGES, errorMessage, promptLabel, stopFailedMessage } from './messages';

const CODES: VpnErrorCode[] = [
  'OPENCONNECT_NOT_FOUND',
  'AUTH_FAILED',
  'AUTH_CANCELLED',
  'PORTAL_UNREACHABLE',
  'TLS_ERROR',
  'PRIVILEGES_DENIED',
  'TUNNEL_FAILED',
  'UNKNOWN',
];
const PLATFORMS: NodeJS.Platform[] = ['win32', 'darwin', 'linux'];

describe('error messages', () => {
  it('exist for every language × code × hint × platform, without README references', () => {
    for (const lang of ALL_LANGUAGES) {
      for (const platform of PLATFORMS) {
        for (const code of CODES) {
          const m = errorMessage(code, lang, undefined, platform);
          expect(m.trim().length, `${lang}/${code}`).toBeGreaterThan(10);
          expect(m).not.toMatch(/README/i);
        }
        for (const hint of ALL_HINTS) {
          const m = errorMessage('PRIVILEGES_DENIED', lang, hint, platform);
          expect(m.trim().length, `${lang}/${hint}`).toBeGreaterThan(10);
          expect(m).not.toMatch(/README/i);
        }
      }
      expect(promptLabel('username', lang)).not.toBe('');
      expect(promptLabel('password', lang)).not.toBe('');
      expect(stopFailedMessage(lang)).toBe(errorMessage('PRIVILEGES_DENIED', lang, 'stop_failed'));
    }
  });

  it('uk is a real translation (differs from ru and en)', () => {
    for (const code of CODES) {
      const uk = errorMessage(code, 'uk', undefined, 'linux');
      expect(uk).not.toBe(errorMessage(code, 'ru', undefined, 'linux'));
      expect(uk).not.toBe(errorMessage(code, 'en', undefined, 'linux'));
    }
  });

  it.each(ALL_LANGUAGES)('untrusted_binary is platform-specific (%s)', (lang) => {
    const win = errorMessage('PRIVILEGES_DENIED', lang, 'untrusted_binary', 'win32');
    const mac = errorMessage('PRIVILEGES_DENIED', lang, 'untrusted_binary', 'darwin');
    const lin = errorMessage('PRIVILEGES_DENIED', lang, 'untrusted_binary', 'linux');
    expect(win).toMatch(/Program Files/);
    expect(win).toMatch(/OpenConnect-GUI/);
    expect(win).not.toMatch(/\/usr\/|apt|MacPorts|port install/);
    expect(mac).toMatch(/MacPorts/);
    expect(mac).not.toMatch(/Program Files|apt install/);
    expect(lin).toMatch(/apt install openconnect/);
    expect(lin).toMatch(/\/usr\/sbin/);
    expect(lin).not.toMatch(/Program Files|MacPorts/);
  });

  it('the ru Windows text matches the agreed copy', () => {
    expect(errorMessage('PRIVILEGES_DENIED', 'ru', 'untrusted_binary', 'win32')).toBe(
      'Установите OpenConnect в «Program Files» (через установщик OpenConnect-GUI) — клиент запускает openconnect только из папок, которые может менять лишь администратор.',
    );
  });
});

describe('Ukrainian typography (DR-18)', () => {
  it('uses the typographic apostrophe inside words, never a straight one', () => {
    const texts: string[] = [promptLabel('username', 'uk'), promptLabel('password', 'uk')];
    for (const platform of PLATFORMS) {
      for (const code of CODES) texts.push(errorMessage(code, 'uk', undefined, platform));
      for (const hint of ALL_HINTS) texts.push(errorMessage('PRIVILEGES_DENIED', 'uk', hint, platform));
    }
    for (const t of texts) expect(t).not.toMatch(/[\u0400-\u04FF]'[\u0400-\u04FF]/u);
    expect(promptLabel('username', 'uk')).toBe('Ім’я користувача');
  });
});
