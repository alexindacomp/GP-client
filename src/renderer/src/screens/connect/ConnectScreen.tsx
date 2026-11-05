import { useEffect, useRef, useState } from 'react';
import type { Profile, VpnState } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import type { MessageKey } from '../../i18n/dictionary';
import { useAppData } from '../../state/AppData';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { isIdle } from '../../hooks/useVpnState';
import { localizeIpcError } from '../../lib/ipcErrors';
import type { Navigate } from '../../navigation';
import { Page } from '../../components/layout/Page';
import { Banner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { SelectField, type SelectOption } from '../../components/ui/Field';
import { ConnectToggle } from './ConnectToggle';
import { StatusCard } from './StatusCard';
import { ErrorBanner } from './ErrorBanner';
import { ErrorDetail } from './ErrorDetail';
import { errorTitle } from './errorTitle';
import styles from './ConnectScreen.module.css';

const AUTO = '';

const DETAIL: Partial<Record<VpnState['status'], MessageKey>> = {
  prelogin: 'status.detail.prelogin',
  authenticating: 'status.detail.authenticating',
  connecting: 'status.detail.connecting',
  reconnecting: 'status.detail.reconnecting',
};

interface Props {
  state: VpnState;
  onNavigate: Navigate;
}

export function ConnectScreen({ state, onNavigate }: Props): React.JSX.Element {
  const { t } = useI18n();
  const { profiles, settings, updateSettings } = useAppData();
  const action = useAsyncAction();
  const [picked, setPicked] = useState<string | null>(null);
  const [gatewayChoice, setGatewayChoice] = useState<{ profileId: string; gateway: string } | null>(null);
  const [dismissed, setDismissed] = useState<VpnState | null>(null);

  const idle = isIdle(state.status);
  // While an attempt/connection runs, the active profile is the one the backend reports.
  const wantedId = !idle && state.profileId ? state.profileId : (picked ?? settings.lastProfileId ?? state.profileId);
  const profile: Profile | undefined = profiles.find((p) => p.id === wantedId) ?? profiles[0];

  const knownGateways = profile && state.profileId === profile.id ? (state.gateways ?? []) : [];
  const chosenGateway =
    gatewayChoice && profile && gatewayChoice.profileId === profile.id ? gatewayChoice.gateway : AUTO;
  const gatewayValue = !idle && state.gateway ? state.gateway.name : chosenGateway;
  const gatewayOptions: SelectOption[] = [
    {
      value: AUTO,
      label: profile?.preferredGateway
        ? t('connect.gatewayAutoPreferred', { name: profile.preferredGateway })
        : t('connect.gatewayAuto'),
    },
    ...knownGateways.map((g) => ({ value: g.name, label: g.name === g.address ? g.name : `${g.name} (${g.address})` })),
  ];
  if (gatewayValue !== AUTO && !gatewayOptions.some((o) => o.value === gatewayValue)) {
    gatewayOptions.push({ value: gatewayValue, label: gatewayValue });
  }

  const selectProfile = (id: string): void => {
    setPicked(id);
    // Keeps the tray menu in sync; a failure here is not worth interrupting the user.
    updateSettings({ lastProfileId: id }).catch((err: unknown) => console.error('Failed to store profile choice', err));
  };

  const connect = (): void => {
    if (!profile) return;
    void action.run(() => window.gp.vpn.connect(profile.id, chosenGateway ? { gateway: chosenGateway } : undefined));
  };
  const disconnect = (): void => {
    void action.run(() => window.gp.vpn.disconnect());
  };

  const showError = state.status === 'error' && state.error !== undefined && dismissed !== state;
  // B4: openconnect could not be stopped — still connected/authenticating, Disconnect stays available.
  const stopWarning = state.error && state.status !== 'error' && state.status !== 'reconnecting' ? state.error : null;
  const hasBanner = Boolean(
    showError || stopWarning || action.error || (state.status === 'reconnecting' && state.error),
  );
  const cancelled = state.error?.code === 'AUTH_CANCELLED';

  // Keep a newly shown error (and its actions) in view.
  const alerts = useRef<HTMLDivElement>(null);
  const errorKey = showError ? state : stopWarning ? state : action.error;
  useEffect(() => {
    if (errorKey) alerts.current?.scrollIntoView?.({ block: 'nearest' });
  }, [errorKey]);

  const detailKey = DETAIL[state.status];
  const detail =
    state.status === 'connected'
      ? profile?.name
      : detailKey
        ? t(detailKey)
        : idle && profile
          ? profile.name
          : undefined;
  const statusTitle =
    state.status === 'error' && state.error ? errorTitle(t, state.error) : t(`status.${state.status}` as const);
  const statusClass =
    state.status === 'connected' ? styles.connected : state.status === 'error' && !cancelled ? styles.failed : '';

  return (
    <Page title={t('connect.title')} hideTitle>
      <div className={styles.pickers}>
        <SelectField
          label={t('connect.profile')}
          value={profile?.id ?? ''}
          options={profiles.map((p) => ({ value: p.id, label: p.name }))}
          onChange={(e) => selectProfile(e.target.value)}
          disabled={!idle || action.pending}
        />
        <SelectField
          label={t('connect.gateway')}
          value={gatewayValue}
          options={gatewayOptions}
          onChange={(e) => profile && setGatewayChoice({ profileId: profile.id, gateway: e.target.value })}
          disabled={!idle || action.pending}
        />
      </div>

      {hasBanner ? (
        <div ref={alerts} className={styles.alerts}>
          {action.error ? (
            <Banner tone="error" role="alert" title={t('connect.failed')} onDismiss={action.clearError}>
              {localizeIpcError(t, action.error).text}
            </Banner>
          ) : null}
          {stopWarning ? (
            <Banner
              tone="warning"
              role="alert"
              title={t('connect.stopFailed')}
              actions={
                <Button variant="primary" onClick={disconnect} disabled={action.pending}>
                  {t('connect.action.disconnect')}
                </Button>
              }
            >
              {stopWarning.message}
            </Banner>
          ) : null}
          {state.status === 'reconnecting' && state.error ? (
            <Banner tone="warning" title={t('connect.connectionLost')}>
              <p>{t('connect.reconnectingAuto')}</p>
              <ErrorDetail error={state.error} hideMessage />
            </Banner>
          ) : null}
          {showError && state.error ? (
            <ErrorBanner
              error={state.error}
              profileId={profile?.id}
              retryDisabled={action.pending || !profile}
              onRetry={connect}
              onNavigate={onNavigate}
              onDismiss={() => setDismissed(state)}
            />
          ) : null}
        </div>
      ) : null}

      <div className={styles.hero}>
        <ConnectToggle
          status={state.status}
          profileName={profile?.name}
          disabled={action.pending || !profile}
          compact={hasBanner}
          onConnect={connect}
          onDisconnect={disconnect}
        />
        <div className={styles.statusText} role="status" aria-live="polite">
          <p className={[styles.statusTitle, statusClass].join(' ')}>{statusTitle}</p>
          {detail ? <p className={styles.statusDetail}>{detail}</p> : null}
        </div>
      </div>

      <StatusCard state={state} />
    </Page>
  );
}
