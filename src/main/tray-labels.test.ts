import { describe, expect, it } from 'vitest';
import { TRAY_LABELS, trayTooltip } from './tray-labels';

describe('tray labels', () => {
  it('all languages have the same keys and non-empty values', () => {
    const keys = Object.keys(TRAY_LABELS.ru).sort();
    for (const lang of ['en', 'uk'] as const) {
      expect(Object.keys(TRAY_LABELS[lang]).sort()).toEqual(keys);
      for (const k of keys) expect(TRAY_LABELS[lang][k as keyof typeof TRAY_LABELS.ru]).not.toBe('');
    }
  });

  it('tooltip is localized and shows the IP only when connected', () => {
    expect(trayTooltip('uk', 'connected', '10.0.0.5')).toBe('GP Connect: Підключено — 10.0.0.5');
    expect(trayTooltip('en', 'connecting', '10.0.0.5')).toBe('GP Connect: Connecting…');
    expect(trayTooltip('ru', 'disconnected')).toBe('GP Connect: Отключено');
  });
});
