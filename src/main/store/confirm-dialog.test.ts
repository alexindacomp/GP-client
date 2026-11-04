import { describe, expect, it } from 'vitest';
import { confirmDialogText } from './confirm-dialog';

describe('confirmDialogText', () => {
  it('uses human labels and localized values (ru)', () => {
    const t = confirmDialogText('change', 'ru', [
      { key: 'openconnectPath', value: 'C:\\Program Files\\OpenConnect-GUI\\openconnect.exe' },
      { key: 'hipScriptPath', value: undefined },
      { key: 'extraArgs', value: ['-v', '--no-dtls'], external: true },
    ]);
    expect(t.title).toBe('GP Connect');
    expect(t.message).toMatch(/правами администратора/);
    expect(t.detail).toBe(
      [
        'Путь к openconnect: C:\\Program Files\\OpenConnect-GUI\\openconnect.exe',
        'HIP-скрипт: по умолчанию',
        'Дополнительные аргументы: -v --no-dtls (изменено вне GP Connect)',
      ].join('\n'),
    );
    expect(t.buttons).toEqual(['Отмена', 'Применить']);
    expect(t.detail).not.toMatch(/openconnectPath|hipScriptPath|extraArgs/);
  });

  it.each([
    ['en', 'OpenConnect path', 'Extra arguments: none', ['Cancel', 'Apply']],
    ['uk', 'Шлях до openconnect', 'Додаткові аргументи: немає', ['Скасувати', 'Застосувати']],
  ] as const)('%s', (lang, pathLabel, emptyArgs, buttons) => {
    const t = confirmDialogText('external', lang, [
      { key: 'openconnectPath', value: '/usr/sbin/openconnect', external: true },
      { key: 'extraArgs', value: [] },
    ]);
    expect(t.detail.split('\n')[0]).toMatch(new RegExp(`^${pathLabel}: /usr/sbin/openconnect`));
    expect(t.detail.split('\n')[1]).toBe(emptyArgs);
    expect(t.buttons).toEqual(buttons);
  });

  it('cancel is always the first button and the two kinds differ', () => {
    for (const lang of ['ru', 'en', 'uk'] as const) {
      const a = confirmDialogText('change', lang, []);
      const b = confirmDialogText('external', lang, []);
      expect(a.message).not.toBe(b.message);
      expect(a.buttons[0]).toMatch(/Отмена|Cancel|Скасувати/);
    }
  });
});
