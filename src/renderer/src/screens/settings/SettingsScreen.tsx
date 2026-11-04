import type { Language, Settings, Theme } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useAppData } from '../../state/AppData';
import { useState } from 'react';
import { localizeIpcError } from '../../lib/ipcErrors';
import { Page } from '../../components/layout/Page';
import { Card } from '../../components/layout/Card';
import { RadioGroup } from '../../components/ui/RadioGroup';
import { Switch } from '../../components/ui/Toggle';
import { SelectField } from '../../components/ui/Field';
import { Banner } from '../../components/ui/Banner';
import { OPENCONNECT_SECTION_ID, OpenconnectSettings } from './OpenconnectSettings';
import styles from './SettingsScreen.module.css';

type BoolKey = 'launchAtLogin' | 'connectOnStartup' | 'autoReconnect';

const LANGUAGES: { value: Language; label: string }[] = [
  { value: 'ru', label: 'Русский' },
  { value: 'en', label: 'English' },
  { value: 'uk', label: 'Українська' },
];

export function SettingsScreen({ focusPath = false }: { focusPath?: boolean }): React.JSX.Element {
  const { t } = useI18n();
  const { settings, info, updateSettings } = useAppData();
  const [error, setError] = useState<string | null>(null);

  // Setting patches are idempotent: no double-submit guard, so quick successive clicks all apply.
  const patch = (p: Partial<Settings>): void => {
    setError(null);
    updateSettings(p).catch((err: unknown) => setError(localizeIpcError(t, err).text));
  };
  const toggles: { key: BoolKey; label: string }[] = [
    { key: 'launchAtLogin', label: t('settings.launchAtLogin') },
    { key: 'connectOnStartup', label: t('settings.connectOnStartup') },
    { key: 'autoReconnect', label: t('settings.autoReconnect') },
  ];

  return (
    <Page title={t('settings.title')}>
      {error ? (
        <Banner
          tone="error"
          role="alert"
          title={t('settings.error.save', { message: error })}
          onDismiss={() => setError(null)}
        />
      ) : null}

      <section className={styles.section} aria-labelledby="settings-appearance">
        <h2 id="settings-appearance" className={styles.heading}>
          {t('settings.appearance')}
        </h2>
        <Card>
          <RadioGroup<Theme>
            legend={t('settings.theme')}
            value={settings.theme}
            onChange={(theme) => patch({ theme })}
            options={[
              { value: 'system', label: t('settings.theme.system') },
              { value: 'light', label: t('settings.theme.light') },
              { value: 'dark', label: t('settings.theme.dark') },
            ]}
          />
          {/* A select, not a segmented control: three native names don't fit 360px side by side. */}
          <SelectField
            label={t('settings.language')}
            value={settings.language}
            onChange={(e) => patch({ language: e.target.value as Language })}
            options={LANGUAGES}
          />
        </Card>
      </section>

      <section className={styles.section} aria-labelledby="settings-behavior">
        <h2 id="settings-behavior" className={styles.heading}>
          {t('settings.behavior')}
        </h2>
        <Card>
          {toggles.map(({ key, label }) => (
            <Switch
              key={key}
              label={label}
              checked={settings[key]}
              onChange={(e) => patch({ [key]: e.target.checked })}
            />
          ))}
        </Card>
      </section>

      <section className={styles.section} aria-labelledby={OPENCONNECT_SECTION_ID}>
        <h2 id={OPENCONNECT_SECTION_ID} className={styles.heading}>
          {t('settings.openconnect')}
        </h2>
        <OpenconnectSettings focusPath={focusPath} />
      </section>

      <section className={styles.section} aria-labelledby="settings-about">
        <h2 id="settings-about" className={styles.heading}>
          {t('settings.about')}
        </h2>
        <p className={styles.about}>
          {t('app.name')} · {t('settings.version', { version: info.appVersion })}
        </p>
      </section>
    </Page>
  );
}
