import type { VpnErrorHint, VpnState } from '@shared/ipc';
import type { MessageKey } from '../../i18n/dictionary';
import type { Translate } from '../../i18n/I18nContext';

/** A specific cause (`error.hint`) gets a more precise title than its error code. */
const HINT_TITLES: Record<VpnErrorHint, MessageKey> = {
  untrusted_binary: 'error.hint.untrusted.title',
  untrusted_homebrew: 'error.hint.untrusted.title',
  stop_failed: 'connect.stopFailed',
  settings_not_confirmed: 'error.hint.settings_not_confirmed.title',
};

export function errorTitle(t: Translate, error: NonNullable<VpnState['error']>): string {
  return error.hint ? t(HINT_TITLES[error.hint]) : t(`error.${error.code}.title` as const);
}
