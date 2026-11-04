import { createContext, useContext, useMemo, type ReactNode } from 'react';
import type { Language } from '@shared/ipc';
import { translate, type MessageKey, type Params } from './dictionary';

export type Translate = (key: MessageKey, params?: Params) => string;

interface I18nValue {
  lang: Language;
  t: Translate;
}

const I18nContext = createContext<I18nValue>({
  lang: 'ru',
  t: (key, params) => translate('ru', key, params),
});

export function I18nProvider({ lang, children }: { lang: Language; children: ReactNode }): React.JSX.Element {
  const value = useMemo<I18nValue>(() => ({ lang, t: (key, params) => translate(lang, key, params) }), [lang]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}
