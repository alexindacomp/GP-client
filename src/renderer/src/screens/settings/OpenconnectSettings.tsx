import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { Settings } from '@shared/ipc';
import {
  ALLOWED_EXTRA_OPTIONS,
  checkExtraArgs,
  extraOptionTakesValue,
  isAbsolutePath,
  isOpenconnectBinaryPath,
  MAX_EXTRA_ARGS,
  parseIpcError,
  type ExtraArgErrorCode,
} from '@shared/validation';
import { useI18n, type Translate } from '../../i18n/I18nContext';
import { useAppData } from '../../state/AppData';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { localizeIpcError } from '../../lib/ipcErrors';
import { Card } from '../../components/layout/Card';
import { TextAreaField, TextField } from '../../components/ui/Field';
import { Button } from '../../components/ui/Button';
import { Banner } from '../../components/ui/Banner';
import { CheckIcon, ErrorIcon, WarningIcon } from '../../components/ui/Icon';
import { CodeText } from '../../components/ui/CodeText';
import styles from './SettingsScreen.module.css';

/** Splits the "one argument per line" textarea (blank lines ignored). */
export function extraArgLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

function extraArgsMessage(t: Translate, code: ExtraArgErrorCode, arg: string): string {
  const name = arg.split('=')[0] ?? arg;
  switch (code) {
    case 'too_many':
      return t('settings.error.extraTooMany', { max: MAX_EXTRA_ARGS });
    case 'too_long':
      return t('settings.error.extraTooLong', { arg });
    case 'not_allowed':
      return t('settings.error.extraNotAllowed', { arg: name });
    case 'not_name_value':
      return extraOptionTakesValue(name)
        ? t('settings.error.extraNeedsValue', { arg: name })
        : t('settings.error.extraNoValue', { arg: name });
    case 'bad_value':
      return t('settings.error.extraBadValue', { arg });
  }
}

function pathError(t: Translate, value: string, binary: boolean): string | null {
  const p = value.trim();
  if (!p) return null;
  if (!isAbsolutePath(p)) return t('settings.error.absolutePath');
  if (binary && !isOpenconnectBinaryPath(p)) return t('settings.error.notOpenconnect');
  return null;
}

/** Id of the OpenConnect section heading in SettingsScreen (deep-link scroll target). */
export const OPENCONNECT_SECTION_ID = 'settings-openconnect';

type Field = 'openconnectPath' | 'hipScriptPath' | 'extraArgs';

/**
 * openconnect path, HIP script and extra arguments: edited together, saved explicitly.
 * Main asks for a native confirmation when any of them changes, so `settings.set` may stay
 * pending for a while and rejects with code `not_confirmed` on cancel.
 */
export function OpenconnectSettings({ focusPath }: { focusPath: boolean }): React.JSX.Element {
  const { t } = useI18n();
  const { settings, info, updateSettings, refreshInfo } = useAppData();
  const [path, setPath] = useState(settings.openconnectPath ?? '');
  const [hip, setHip] = useState(settings.hipScriptPath ?? '');
  const [extra, setExtra] = useState(settings.extraArgs.join('\n'));
  const [outcome, setOutcome] = useState<'saved' | 'notConfirmed' | null>(null);
  const save = useAsyncAction();
  const form = useRef<HTMLFormElement>(null);

  // Deep link from an error action: bring the whole OpenConnect section into view, then focus the path.
  useEffect(() => {
    if (!focusPath) return;
    const heading = document.getElementById(OPENCONNECT_SECTION_ID);
    heading?.scrollIntoView?.({ block: 'start' });
    const input = form.current?.elements.namedItem('openconnectPath');
    if (input instanceof HTMLInputElement) input.focus({ preventScroll: true });
  }, [focusPath]);

  const ocPathError = pathError(t, path, true);
  const hipError = pathError(t, hip, false);
  const parsed = checkExtraArgs(extraArgLines(extra));
  const extraError = parsed.ok ? null : extraArgsMessage(t, parsed.code, parsed.arg);

  const saveError = save.error ? localizeIpcError(t, save.error) : null;
  const saveErrorField =
    saveError?.field === 'openconnectPath' || saveError?.field === 'hipScriptPath' || saveError?.field === 'extraArgs'
      ? (saveError.field as Field)
      : null;
  const serverError = (field: Field): string | null => (saveErrorField === field && saveError ? saveError.text : null);

  const edit =
    (setter: (v: string) => void) =>
    (e: { target: { value: string } }): void => {
      setter(e.target.value);
      setOutcome(null);
      save.clearError();
    };

  const revert = (): void => {
    setPath(settings.openconnectPath ?? '');
    setHip(settings.hipScriptPath ?? '');
    setExtra(settings.extraArgs.join('\n'));
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    if (ocPathError || hipError || !parsed.ok) return;
    // Send only real changes: each one triggers a confirmation dialog in main. '' clears a path.
    const patch: Partial<Settings> = {};
    if (path.trim() !== (settings.openconnectPath ?? '')) patch.openconnectPath = path.trim();
    if (hip.trim() !== (settings.hipScriptPath ?? '')) patch.hipScriptPath = hip.trim();
    if (parsed.args.join('\n') !== settings.extraArgs.join('\n')) patch.extraArgs = parsed.args;
    if (Object.keys(patch).length === 0) {
      setOutcome('saved');
      return;
    }
    setOutcome(null);
    let confirmed = true;
    void save
      .run(async () => {
        try {
          await updateSettings(patch);
        } catch (err) {
          // A cancelled confirmation is not an error: restore the saved values and say so calmly.
          if (parseIpcError(err).code !== 'not_confirmed') throw err;
          confirmed = false;
          revert();
          return;
        }
        if ('openconnectPath' in patch) await refreshInfo();
      })
      .then((ok) => {
        if (ok) setOutcome(confirmed ? 'saved' : 'notConfirmed');
      });
  };

  // openconnect --version prints "v9.12"; the label already says "version".
  const version = info.openconnectVersion?.replace(/^v/i, '');
  const untrusted = info.openconnectFound && info.openconnectTrusted === false;
  return (
    <Card>
      <div className={styles.status}>
        {!info.openconnectFound ? (
          <ErrorIcon size={16} className={styles.missing} />
        ) : untrusted ? (
          <WarningIcon size={16} className={styles.untrusted} />
        ) : (
          <CheckIcon size={16} className={styles.found} />
        )}
        <div className={styles.statusText}>
          <p>
            {!info.openconnectFound
              ? t('settings.openconnectMissing')
              : untrusted
                ? t('settings.openconnectUntrusted', { path: info.openconnectPath ?? '—' })
                : version
                  ? t('settings.openconnectFound', { version })
                  : t('settings.openconnectFoundNoVersion')}
          </p>
          {untrusted ? (
            <p className={styles.statusHint}>
              <CodeText text={t(`settings.openconnectUntrustedHint.${info.platform}` as const)} />
            </p>
          ) : null}
        </div>
      </div>
      <form ref={form} className={styles.section} onSubmit={onSubmit} noValidate aria-busy={save.pending}>
        <TextField
          label={t('settings.openconnectPath')}
          hint={t('settings.openconnectPathHint')}
          value={path}
          onChange={edit(setPath)}
          error={ocPathError ?? serverError('openconnectPath')}
          readOnly={save.pending}
          name="openconnectPath"
          placeholder={info.openconnectPath}
          autoComplete="off"
        />
        <TextField
          label={t('settings.hipScriptPath')}
          hint={t('settings.hipScriptPathHint')}
          value={hip}
          onChange={edit(setHip)}
          error={hipError ?? serverError('hipScriptPath')}
          readOnly={save.pending}
          autoComplete="off"
        />
        <TextAreaField
          label={t('settings.extraArgs')}
          hint={
            <>
              {t('settings.extraArgsHint')}{' '}
              <span className={styles.allowed}>
                {t('settings.extraArgsAllowed')}{' '}
                {ALLOWED_EXTRA_OPTIONS.map((o) => (
                  <code key={o} className={styles.chip}>
                    {extraOptionTakesValue(o) ? `${o}=…` : o}
                  </code>
                ))}
              </span>
            </>
          }
          value={extra}
          onChange={edit(setExtra)}
          error={extraError ?? serverError('extraArgs')}
          readOnly={save.pending}
          rows={3}
        />
        {saveError && !saveErrorField ? (
          <Banner tone="error" role="alert" title={t('settings.error.save', { message: saveError.text })} />
        ) : null}
        {outcome === 'notConfirmed' ? (
          <Banner tone="info" title={t('settings.notConfirmed')} onDismiss={() => setOutcome(null)} />
        ) : null}
        <div className={styles.actions}>
          <span className={styles.saved} role="status">
            {save.pending ? t('settings.confirmPending') : outcome === 'saved' ? t('settings.saved') : ''}
          </span>
          <Button type="submit" variant="primary" disabled={save.pending}>
            {save.pending ? t('common.saving') : t('settings.advancedSave')}
          </Button>
        </div>
      </form>
    </Card>
  );
}
