import { useState, type FormEvent } from 'react';
import type { AuthMode, Profile } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useAppData } from '../../state/AppData';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { normalizePortalUrl } from '@shared/validation';
import { localizeIpcError } from '../../lib/ipcErrors';
import { TextField, SelectField } from '../../components/ui/Field';
import { Checkbox } from '../../components/ui/Toggle';
import { Button } from '../../components/ui/Button';
import { Banner } from '../../components/ui/Banner';
import {
  initialValues,
  toProfileInput,
  validateProfileForm,
  NAME_MAX,
  type ProfileFormErrors,
  type ProfileFormValues,
} from './profileFormModel';
import styles from './ProfileForm.module.css';

const FIELD_ORDER: (keyof ProfileFormValues)[] = ['name', 'portalUrl', 'username', 'preferredGateway', 'password'];

interface Props {
  profile?: Profile;
  onSaved: (p: Profile) => void;
  onCancel?: () => void;
}

/** Create/edit a portal profile. Validates locally (mirrors main) and shows main's rejection if any. */
export function ProfileForm({ profile, onSaved, onCancel }: Props): React.JSX.Element {
  const { t } = useI18n();
  const { saveProfile } = useAppData();
  const [values, setValues] = useState<ProfileFormValues>(() => initialValues(profile));
  const [touched, setTouched] = useState<Partial<Record<keyof ProfileFormValues, boolean>>>({});
  const [submitted, setSubmitted] = useState(false);
  const save = useAsyncAction();

  const errors: ProfileFormErrors = validateProfileForm(values);
  const saveError = save.error ? localizeIpcError(t, save.error) : null;
  const saveErrorField =
    saveError?.field && (FIELD_ORDER as string[]).includes(saveError.field) ? saveError.field : undefined;
  const shown = (field: keyof ProfileFormValues): string | null => {
    const e = errors[field];
    if (e && (submitted || touched[field])) return t(e.key, e.params);
    return saveErrorField === field && saveError ? saveError.text : null;
  };
  const set =
    <K extends keyof ProfileFormValues>(field: K) =>
    (value: ProfileFormValues[K]): void => {
      setValues((v) => ({ ...v, [field]: value }));
      save.clearError();
    };
  const blur = (field: keyof ProfileFormValues) => (): void => setTouched((s) => ({ ...s, [field]: true }));

  const portal = normalizePortalUrl(values.portalUrl);
  const portalHint =
    portal.ok && portal.url !== values.portalUrl.trim() ? t('form.portalHint', { url: portal.url }) : undefined;
  const saml = values.authMode === 'saml';

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    setSubmitted(true);
    const firstInvalid = FIELD_ORDER.find((f) => errors[f]);
    if (firstInvalid) {
      const el = (e.currentTarget as HTMLFormElement).elements.namedItem(firstInvalid);
      if (el instanceof HTMLElement) el.focus();
      return;
    }
    const { input, password } = toProfileInput(values, profile?.id);
    void save.run(async () => onSaved(await saveProfile(input, password)));
  };

  return (
    <form className={styles.form} onSubmit={onSubmit} noValidate>
      <TextField
        label={t('form.name')}
        placeholder={t('form.namePlaceholder')}
        name="name"
        value={values.name}
        onChange={(e) => set('name')(e.target.value)}
        onBlur={blur('name')}
        error={shown('name')}
        maxLength={NAME_MAX}
        autoComplete="off"
        required
      />
      <TextField
        label={t('form.portal')}
        placeholder={t('form.portalPlaceholder')}
        name="portalUrl"
        value={values.portalUrl}
        onChange={(e) => set('portalUrl')(e.target.value)}
        onBlur={blur('portalUrl')}
        error={shown('portalUrl')}
        hint={portalHint}
        inputMode="url"
        autoComplete="url"
        required
      />
      <SelectField
        label={t('form.authMode')}
        value={values.authMode}
        onChange={(e) => set('authMode')(e.target.value as AuthMode)}
        options={[
          { value: 'auto', label: t('profiles.authMode.auto') },
          { value: 'password', label: t('profiles.authMode.password') },
          { value: 'saml', label: t('profiles.authMode.saml') },
        ]}
      />
      <TextField
        label={t('form.username')}
        optionalLabel={t('common.optional')}
        name="username"
        value={values.username}
        onChange={(e) => set('username')(e.target.value)}
        onBlur={blur('username')}
        error={shown('username')}
        autoComplete="username"
      />
      <TextField
        label={t('form.preferredGateway')}
        optionalLabel={t('common.optional')}
        hint={t('form.preferredGatewayHint')}
        name="preferredGateway"
        value={values.preferredGateway}
        onChange={(e) => set('preferredGateway')(e.target.value)}
        onBlur={blur('preferredGateway')}
        error={shown('preferredGateway')}
        autoComplete="off"
      />
      <Checkbox
        label={t('form.savePassword')}
        hint={saml ? t('form.savePasswordSamlHint') : undefined}
        checked={!saml && values.savePassword}
        disabled={saml}
        onChange={(e) => set('savePassword')(e.target.checked)}
      />
      {!saml && values.savePassword ? (
        <TextField
          type="password"
          label={t('form.password')}
          optionalLabel={t('common.optional')}
          hint={profile?.savePassword ? t('form.passwordKeep') : t('form.passwordLater')}
          name="password"
          value={values.password}
          onChange={(e) => set('password')(e.target.value)}
          error={shown('password')}
          autoComplete="new-password"
        />
      ) : null}

      {saveError && !saveErrorField ? (
        <Banner tone="error" role="alert" title={t('form.error.save', { message: saveError.text })} />
      ) : null}

      <div className={styles.actions}>
        {onCancel ? (
          <Button onClick={onCancel} disabled={save.pending}>
            {t('common.cancel')}
          </Button>
        ) : null}
        <Button type="submit" variant="primary" disabled={save.pending}>
          {save.pending ? t('common.saving') : t('common.save')}
        </Button>
      </div>
    </form>
  );
}
