import type { AuthMode, Profile, ProfileInput } from '@shared/ipc';
import type { MessageKey } from '../../i18n/dictionary';
import { CONTROL_CHARS_RE, normalizePortalUrl } from '@shared/validation';
import { PORTAL_ERROR_KEYS } from '../../lib/ipcErrors';

export interface ProfileFormValues {
  name: string;
  portalUrl: string;
  username: string;
  authMode: AuthMode;
  preferredGateway: string;
  savePassword: boolean;
  password: string;
}

export type ProfileFormErrors = Partial<
  Record<keyof ProfileFormValues, { key: MessageKey; params?: Record<string, number> }>
>;

export const NAME_MAX = 100;
const USERNAME_MAX = 256;
const GATEWAY_MAX = 255;

export function initialValues(profile?: Profile): ProfileFormValues {
  return {
    name: profile?.name ?? '',
    portalUrl: profile?.portalUrl ?? '',
    username: profile?.username ?? '',
    authMode: profile?.authMode ?? 'auto',
    preferredGateway: profile?.preferredGateway ?? '',
    savePassword: profile?.savePassword ?? false,
    password: '',
  };
}

export function validateProfileForm(v: ProfileFormValues): ProfileFormErrors {
  const errors: ProfileFormErrors = {};
  const name = v.name.trim();
  if (name === '') errors.name = { key: 'form.error.nameRequired' };
  else if (name.length > NAME_MAX) errors.name = { key: 'form.error.nameTooLong', params: { max: NAME_MAX } };
  else if (CONTROL_CHARS_RE.test(name)) errors.name = { key: 'form.error.singleLine' };

  const portal = normalizePortalUrl(v.portalUrl);
  if (!portal.ok) errors.portalUrl = { key: PORTAL_ERROR_KEYS[portal.code] };

  const username = v.username.trim();
  if (username.length > USERNAME_MAX || CONTROL_CHARS_RE.test(username))
    errors.username = { key: 'form.error.singleLine' };
  const gateway = v.preferredGateway.trim();
  if (gateway.length > GATEWAY_MAX || CONTROL_CHARS_RE.test(gateway)) {
    errors.preferredGateway = { key: 'form.error.singleLine' };
  }
  if (/[\r\n\0]/.test(v.password)) errors.password = { key: 'form.error.singleLine' };
  return errors;
}

/** Builds the `profiles.save` arguments; call only after validation passed. */
export function toProfileInput(v: ProfileFormValues, id?: string): { input: ProfileInput; password?: string } {
  const portal = normalizePortalUrl(v.portalUrl);
  if (!portal.ok) throw new Error('Invalid portal URL');
  const savePassword = v.authMode !== 'saml' && v.savePassword;
  const input: ProfileInput = { name: v.name.trim(), portalUrl: portal.url, authMode: v.authMode, savePassword };
  if (id) input.id = id;
  const username = v.username.trim();
  if (username) input.username = username;
  const gateway = v.preferredGateway.trim();
  if (gateway) input.preferredGateway = gateway;
  return savePassword && v.password !== '' ? { input, password: v.password } : { input };
}
