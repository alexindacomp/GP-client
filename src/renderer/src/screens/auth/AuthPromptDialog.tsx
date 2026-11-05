import { useState, type FormEvent } from 'react';
import type { AuthPrompt, Profile } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import type { ActivePrompt } from '../../hooks/useAuthPrompt';
import { Dialog, DialogActions } from '../../components/ui/Dialog';
import { TextField } from '../../components/ui/Field';
import { Checkbox } from '../../components/ui/Toggle';
import { RadioGroup } from '../../components/ui/RadioGroup';
import { Button } from '../../components/ui/Button';
import styles from './AuthPromptDialog.module.css';

interface Props {
  active: ActivePrompt;
  profile: Profile | undefined;
  onAnswer: (id: string, value: string | null) => Promise<void>;
  /** Called with the typed password when "Remember password" is checked. */
  onRemember: (profileId: string, password: string) => void;
}

/** Splits the backend's prompt text: the last line is the field label, earlier lines are server context. */
function splitMessage(message: string): { context: string; label: string | undefined } {
  const lines = message
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  const label = lines.pop();
  return { context: lines.join('\n'), label };
}

const INPUT_PROPS: Record<Exclude<AuthPrompt['kind'], 'select'>, React.InputHTMLAttributes<HTMLInputElement>> = {
  password: { type: 'password', autoComplete: 'current-password' },
  otp: { type: 'text', inputMode: 'numeric', autoComplete: 'one-time-code' },
  text: { type: 'text', autoComplete: 'username' },
};

/** Password / OTP / free text / choice prompt during sign-in. Escape or Cancel aborts the attempt. */
export function AuthPromptDialog({ active, profile, onAnswer, onRemember }: Props): React.JSX.Element {
  const { t } = useI18n();
  const { prompt, offerRemember } = active;
  const [value, setValue] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const canRemember = offerRemember && profile !== undefined && profile.authMode !== 'saml';
  const [remember, setRemember] = useState(canRemember && profile.savePassword);
  const send = useAsyncAction();

  const { context, label } = splitMessage(prompt.message);
  const fieldLabel = label ?? t(`prompt.title.${prompt.kind}` as const);
  const error = !value
    ? t(prompt.kind === 'select' ? 'prompt.chooseOne' : 'prompt.required')
    : /[\r\n\0]/.test(value)
      ? t('prompt.singleLine')
      : null;
  const description = [profile ? t('prompt.profile', { name: profile.name }) : null, context || null]
    .filter(Boolean)
    .join('\n');

  const submit = (e: FormEvent): void => {
    e.preventDefault();
    setSubmitted(true);
    if (error) return;
    void send.run(async () => {
      await onAnswer(prompt.id, value);
      if (canRemember && remember && profile) onRemember(profile.id, value);
    });
  };
  const cancel = (): void => {
    void send.run(() => onAnswer(prompt.id, null));
  };

  return (
    <Dialog title={t(`prompt.title.${prompt.kind}` as const)} description={description || undefined} onCancel={cancel}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {prompt.kind === 'select' ? (
          <RadioGroup
            legend={fieldLabel}
            layout="list"
            value={value}
            onChange={setValue}
            options={(prompt.options ?? []).map((o) => ({ value: o, label: o }))}
          />
        ) : (
          <TextField
            label={fieldLabel}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            error={submitted ? error : null}
            data-autofocus
            {...INPUT_PROPS[prompt.kind]}
          />
        )}
        {prompt.kind === 'select' && submitted && error ? (
          <p role="alert" className={styles.error}>
            {error}
          </p>
        ) : null}
        {canRemember ? (
          <Checkbox
            label={t('prompt.remember')}
            hint={t('prompt.rememberHint')}
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
          />
        ) : null}
        <DialogActions>
          <Button onClick={cancel} disabled={send.pending}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" disabled={send.pending}>
            {prompt.kind === 'password' ? t('prompt.submit') : t('prompt.continue')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
