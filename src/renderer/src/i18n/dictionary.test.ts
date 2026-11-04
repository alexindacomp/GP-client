import { describe, expect, it } from 'vitest';
import { DICTIONARIES, translate } from './dictionary';

const placeholders = (s: string): string[] => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort();

describe('dictionaries', () => {
  const [base, ...others] = Object.entries(DICTIONARIES);
  const [, ru] = base!;

  it.each(others)('%s has exactly the same keys as ru', (_lang, dict) => {
    expect(Object.keys(dict).sort()).toEqual(Object.keys(ru).sort());
  });

  it.each(others)('%s uses the same {placeholders} as ru in every message', (_lang, dict) => {
    for (const key of Object.keys(ru) as (keyof typeof ru)[]) {
      expect({ key, params: placeholders(dict[key]) }).toEqual({ key, params: placeholders(ru[key]) });
    }
  });

  it('has no empty messages', () => {
    for (const dict of Object.values(DICTIONARIES)) {
      for (const value of Object.values(dict)) expect(value.trim()).not.toBe('');
    }
  });

  it('covers ru, en and uk', () => {
    expect(Object.keys(DICTIONARIES).sort()).toEqual(['en', 'ru', 'uk']);
    expect(translate('uk', 'nav.settings')).toBe('Налаштування');
  });
});
