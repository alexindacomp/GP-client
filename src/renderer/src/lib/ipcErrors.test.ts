import { describe, expect, it } from 'vitest';
import { translate, type MessageKey, type Params } from '../i18n/dictionary';
import { localizeIpcError } from './ipcErrors';

const t = (key: MessageKey, params?: Params): string => translate('ru', key, params);
const wrap = (text: string): Error => new Error(text); // as the Tauri bridge rejects

describe('localizeIpcError', () => {
  it('localizes by field + code', () => {
    expect(localizeIpcError(t, wrap('[field:portalUrl][code:not_https] Only https'))).toEqual({
      field: 'portalUrl',
      code: 'not_https',
      text: 'Поддерживаются только порталы https://.',
    });
    expect(localizeIpcError(t, wrap('[field:extraArgs][code:not_allowed] Option "--x" is not allowed')).text).toBe(
      'Одна из опций не разрешена.',
    );
    expect(localizeIpcError(t, wrap('[field:openconnectPath][code:not_absolute] must be absolute')).text).toBe(
      'Укажите абсолютный путь.',
    );
  });

  it('localizes generic codes without a field', () => {
    expect(localizeIpcError(t, wrap('[code:busy] Cannot connect while connecting'))).toEqual({
      code: 'busy',
      text: 'Дождитесь завершения текущей операции.',
    });
  });

  it('falls back to the English message for unknown codes or unmarked errors', () => {
    expect(localizeIpcError(t, wrap('[field:name][code:unknown_field] Unknown profile field "x"')).text).toBe(
      'Unknown profile field "x"',
    );
    expect(localizeIpcError(t, new Error('boom')).text).toBe('boom');
  });
});
