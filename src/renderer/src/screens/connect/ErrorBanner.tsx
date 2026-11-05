import type { VpnErrorCode, VpnState } from '@shared/ipc';
import type { MessageKey } from '../../i18n/dictionary';
import { useI18n } from '../../i18n/I18nContext';
import type { Navigate } from '../../navigation';
import { Banner } from '../../components/ui/Banner';
import { Button } from '../../components/ui/Button';
import { ErrorDetail } from './ErrorDetail';
import { errorTitle } from './errorTitle';

type ActionId = 'retry' | 'setPath' | 'editProfile' | 'openLog' | 'openSettings';

/** Recovery actions per error code; the first one is the primary action. */
const ACTIONS: Record<VpnErrorCode, ActionId[]> = {
  OPENCONNECT_NOT_FOUND: ['setPath', 'retry'],
  AUTH_FAILED: ['retry', 'editProfile'],
  AUTH_CANCELLED: ['retry'],
  PORTAL_UNREACHABLE: ['retry', 'editProfile'],
  TLS_ERROR: ['openSettings', 'openLog'],
  // Also used for an untrusted openconnect binary; the backend's message explains the fix.
  PRIVILEGES_DENIED: ['openSettings', 'retry'],
  TUNNEL_FAILED: ['retry', 'openLog'],
  UNKNOWN: ['retry', 'openLog'],
};

const LABELS: Record<ActionId, MessageKey> = {
  retry: 'common.retry',
  setPath: 'error.action.setPath',
  editProfile: 'error.action.editProfile',
  openLog: 'error.action.openLog',
  openSettings: 'error.action.openSettings',
};

interface Props {
  error: NonNullable<VpnState['error']>;
  profileId: string | undefined;
  retryDisabled: boolean;
  onRetry: () => void;
  onNavigate: Navigate;
  onDismiss: () => void;
}

/** Actionable error InfoBar. A cancelled sign-in is shown as a calm info message, not an error. */
export function ErrorBanner({
  error,
  profileId,
  retryDisabled,
  onRetry,
  onNavigate,
  onDismiss,
}: Props): React.JSX.Element {
  const { t } = useI18n();
  const cancelled = error.code === 'AUTH_CANCELLED';
  const actions = ACTIONS[error.code].filter((a) => a !== 'editProfile' || profileId !== undefined);

  const run = (a: ActionId): void => {
    switch (a) {
      case 'retry':
        onRetry();
        return;
      case 'setPath':
        onNavigate({ view: 'settings', focus: 'openconnectPath' });
        return;
      case 'editProfile':
        onNavigate({ view: 'profiles', editProfileId: profileId });
        return;
      case 'openLog':
        onNavigate({ view: 'log' });
        return;
      case 'openSettings':
        onNavigate({ view: 'settings', focus: 'openconnectPath' });
    }
  };

  return (
    <Banner
      tone={cancelled ? 'info' : 'error'}
      role={cancelled ? 'status' : 'alert'}
      title={errorTitle(t, error)}
      onDismiss={onDismiss}
      actions={actions.map((a, i) => (
        <Button
          key={a}
          variant={i === 0 && !cancelled ? 'primary' : 'secondary'}
          disabled={a === 'retry' && retryDisabled}
          onClick={() => run(a)}
        >
          {t(LABELS[a])}
        </Button>
      ))}
    >
      {cancelled ? null : <ErrorDetail error={error} />}
    </Banner>
  );
}
