import { parseIpcError, type ExtraArgErrorCode, type PortalUrlErrorCode } from '@shared/validation';
import type { MessageKey } from '../i18n/dictionary';
import type { Translate } from '../i18n/I18nContext';

export const PORTAL_ERROR_KEYS: Record<PortalUrlErrorCode, MessageKey> = {
  empty: 'form.error.portalRequired',
  too_long: 'form.error.portalInvalid',
  invalid: 'form.error.portalInvalid',
  not_https: 'form.error.portalNotHttps',
  credentials: 'form.error.portalCredentials',
};

/** Arg-less texts for main's extraArgs rejections (the client check names the argument). */
const EXTRA_ARGS_KEYS: Record<ExtraArgErrorCode, MessageKey> = {
  not_allowed: 'ipc.extraArgs.not_allowed',
  bad_value: 'ipc.extraArgs.bad_value',
  too_many: 'ipc.extraArgs.too_many',
  too_long: 'ipc.extraArgs.too_long',
  not_name_value: 'ipc.extraArgs.not_name_value',
};

const GENERAL_KEYS: Record<string, MessageKey> = {
  required: 'ipc.required',
  too_long: 'ipc.too_long',
  invalid_chars: 'form.error.singleLine',
  not_absolute: 'settings.error.absolutePath',
  not_openconnect: 'settings.error.notOpenconnect',
  not_found: 'ipc.not_found',
  not_confirmed: 'settings.notConfirmed',
  busy: 'ipc.busy',
  internal: 'ipc.internal',
  prompt_expired: 'ipc.prompt_expired',
};

export interface LocalizedIpcError {
  field?: string;
  code?: string;
  /** Localized by code, or main's (English) message when the code is unknown/generic. */
  text: string;
}

/** Turns a rejected `window.gp` call into a field + user-facing text. */
export function localizeIpcError(t: Translate, err: unknown): LocalizedIpcError {
  const info = parseIpcError(err);
  let key: MessageKey | undefined;
  if (info.code) {
    if (info.field === 'portalUrl') key = PORTAL_ERROR_KEYS[info.code as PortalUrlErrorCode];
    else if (info.field === 'extraArgs') key = EXTRA_ARGS_KEYS[info.code as ExtraArgErrorCode];
    key ??= GENERAL_KEYS[info.code];
  }
  const out: LocalizedIpcError = { text: key ? t(key) : info.message || t('ipc.internal') };
  if (info.field) out.field = info.field;
  if (info.code) out.code = info.code;
  return out;
}
