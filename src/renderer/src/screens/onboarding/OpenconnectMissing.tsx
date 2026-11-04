import { useState } from 'react';
import type { SystemInfo } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import type { MessageKey } from '../../i18n/dictionary';
import { useAppData } from '../../state/AppData';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { useCopy } from '../../hooks/useCopy';
import type { Navigate } from '../../navigation';
import { Page } from '../../components/layout/Page';
import { Card } from '../../components/layout/Card';
import { Button } from '../../components/ui/Button';
import { Banner } from '../../components/ui/Banner';
import { CheckIcon, CopyIcon } from '../../components/ui/Icon';
import styles from './Onboarding.module.css';

interface InstallGuide {
  /** Terminal commands, each copyable on its own. */
  commands: string[];
  /** Shown before `commands` when they are an alternative to the link. */
  commandsLabel?: MessageKey;
  link?: { url: string; label: MessageKey };
}

/** Per-OS instructions, consistent with README "Установка OpenConnect". */
export const INSTALL_GUIDES: Record<SystemInfo['platform'], InstallGuide> = {
  win32: {
    commands: ['winget search openconnect'],
    commandsLabel: 'onboarding.missing.win32Alt',
    link: { url: 'https://gitlab.com/openconnect/openconnect-gui/-/releases', label: 'onboarding.missing.win32Link' },
  },
  darwin: {
    commands: ['sudo port install openconnect'],
    link: { url: 'https://www.macports.org/install.php', label: 'onboarding.missing.darwinLink' },
  },
  linux: { commands: ['sudo apt update', 'sudo apt install openconnect'] },
};

function CommandLine({ command }: { command: string }): React.JSX.Element {
  const { t } = useI18n();
  const copy = useCopy();
  return (
    <li className={styles.command}>
      <code className={styles.code}>{command}</code>
      <Button
        variant="subtle"
        iconOnly
        label={copy.copied ? t('common.copied') : t('onboarding.missing.copyCommand', { command })}
        icon={copy.copied ? <CheckIcon size={16} /> : <CopyIcon size={16} />}
        onClick={() => void copy.copy(command)}
      />
    </li>
  );
}

export function OpenconnectMissing({ onNavigate }: { onNavigate: Navigate }): React.JSX.Element {
  const { t } = useI18n();
  const { info, refreshInfo } = useAppData();
  const check = useAsyncAction();
  const open = useAsyncAction();
  const [checkedOnce, setCheckedOnce] = useState(false);
  const guide = INSTALL_GUIDES[info.platform];

  const recheck = (): void => {
    void check.run(async () => {
      await refreshInfo();
      setCheckedOnce(true);
    });
  };

  return (
    <Page title={t('onboarding.missing.title')}>
      <p className={styles.lead}>{t('onboarding.missing.text')}</p>
      <Card>
        <p>{t(`onboarding.missing.${info.platform}` as const)}</p>
        {guide.link ? (
          <div>
            <Button
              className={styles.wrapButton}
              onClick={() => void open.run(() => window.gp.system.openExternal(guide.link?.url ?? ''))}
            >
              {t(guide.link.label)}
            </Button>
          </div>
        ) : null}
        {guide.commandsLabel ? <p className={styles.alt}>{t(guide.commandsLabel)}</p> : null}
        {guide.commands.length > 0 ? (
          <ul className={styles.commands}>
            {guide.commands.map((c) => (
              <CommandLine key={c} command={c} />
            ))}
          </ul>
        ) : null}
      </Card>
      {open.error ? (
        <Banner tone="error" role="alert" title={t('onboarding.missing.linkFailed')} onDismiss={open.clearError} />
      ) : null}
      {checkedOnce && !check.pending && !check.error ? (
        <Banner tone="warning" title={t('onboarding.missing.stillMissing')} />
      ) : null}
      {check.error ? <Banner tone="error" role="alert" title={t('app.loadFailed')} /> : null}
      <div className={styles.actions}>
        <Button variant="primary" onClick={recheck} disabled={check.pending}>
          {check.pending ? t('onboarding.missing.checking') : t('onboarding.missing.recheck')}
        </Button>
        <Button onClick={() => onNavigate({ view: 'settings', focus: 'openconnectPath' })}>
          {t('onboarding.missing.setPath')}
        </Button>
      </div>
    </Page>
  );
}
