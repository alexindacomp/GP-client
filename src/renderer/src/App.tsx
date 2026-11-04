import { useEffect, useState } from 'react';
import { I18nProvider, useI18n } from './i18n/I18nContext';
import { AppDataProvider, useAppData, type BootState } from './state/AppData';
import { useApplyTheme } from './hooks/useTheme';
import { useVpnState } from './hooks/useVpnState';
import { useAuthPrompt } from './hooks/useAuthPrompt';
import { useRememberPassword } from './hooks/useRememberPassword';
import type { NavTarget } from './navigation';
import { TitleBar } from './components/layout/TitleBar';
import { NavBar } from './components/layout/NavBar';
import { Button } from './components/ui/Button';
import { Spinner } from './components/ui/Spinner';
import { ConnectScreen } from './screens/connect/ConnectScreen';
import { OpenconnectMissing } from './screens/onboarding/OpenconnectMissing';
import { NoProfiles } from './screens/onboarding/NoProfiles';
import { ProfilesScreen } from './screens/profiles/ProfilesScreen';
import { SettingsScreen } from './screens/settings/SettingsScreen';
import { LogScreen } from './screens/log/LogScreen';
import { AuthPromptDialog } from './screens/auth/AuthPromptDialog';
import styles from './App.module.css';

export function App(): React.JSX.Element {
  return (
    <AppDataProvider fallback={(boot) => <BootScreen boot={boot} />}>
      <Shell />
    </AppDataProvider>
  );
}

function BootScreen({ boot }: { boot: Exclude<BootState, { status: 'ready' }> }): React.JSX.Element {
  const { t } = useI18n();
  return (
    <div className={styles.boot}>
      {boot.status === 'loading' ? (
        <Spinner size={24} label={t('app.loading')} />
      ) : (
        <>
          <p role="alert">{t('app.loadFailed')}</p>
          <Button variant="primary" onClick={boot.retry}>
            {t('common.retry')}
          </Button>
        </>
      )}
    </div>
  );
}

function Shell(): React.JSX.Element {
  const { info, settings, profiles, saveProfile } = useAppData();
  useApplyTheme(settings.theme, info);
  const state = useVpnState();
  const prompt = useAuthPrompt();
  const remember = useRememberPassword(profiles, saveProfile);
  // `seq` remounts the target screen so a new intent (e.g. "edit profile") is applied.
  const [nav, setNav] = useState<NavTarget & { seq: number }>({ view: 'connect', seq: 0 });
  const navigate = (target: NavTarget): void => setNav((n) => ({ ...target, seq: n.seq + 1 }));

  useEffect(() => {
    document.documentElement.lang = settings.language;
  }, [settings.language]);

  const promptProfile = profiles.find((p) => p.id === state?.profileId);

  return (
    <I18nProvider lang={settings.language}>
      <div className={styles.app}>
        <TitleBar platform={info.platform} />
        <main className={styles.main}>
          <Screen nav={nav} navigate={navigate} key={`${nav.view}-${nav.seq}`} state={state} />
        </main>
        <NavBar current={nav.view} onNavigate={(view) => navigate({ view })} />
      </div>
      {prompt.active ? (
        <AuthPromptDialog
          key={prompt.active.prompt.id}
          active={prompt.active}
          profile={promptProfile}
          onAnswer={prompt.answer}
          onRemember={remember}
        />
      ) : null}
    </I18nProvider>
  );
}

interface ScreenProps {
  nav: NavTarget;
  navigate: (t: NavTarget) => void;
  state: ReturnType<typeof useVpnState>;
}

function Screen({ nav, navigate, state }: ScreenProps): React.JSX.Element {
  const { t } = useI18n();
  const { info, profiles } = useAppData();
  switch (nav.view) {
    case 'profiles':
      return <ProfilesScreen state={state} initialEditId={nav.editProfileId} />;
    case 'settings':
      return <SettingsScreen focusPath={nav.focus === 'openconnectPath'} />;
    case 'log':
      return <LogScreen />;
    case 'connect':
      if (!info.openconnectFound) return <OpenconnectMissing onNavigate={navigate} />;
      if (profiles.length === 0) return <NoProfiles />;
      if (!state) {
        return (
          <div className={styles.boot}>
            <Spinner size={24} label={t('app.loading')} />
          </div>
        );
      }
      return <ConnectScreen state={state} onNavigate={navigate} />;
  }
}
