import type { VpnStatus } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { isBusy } from '../../hooks/useVpnState';
import { PowerIcon } from '../../components/ui/Icon';
import styles from './ConnectToggle.module.css';

interface Props {
  status: VpnStatus;
  profileName: string | undefined;
  disabled: boolean;
  /** Smaller toggle while an error banner needs the vertical space. */
  compact?: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
}

type Visual = 'off' | 'busy' | 'on' | 'stopping';

function visualOf(status: VpnStatus): Visual {
  if (status === 'connected') return 'on';
  if (status === 'disconnecting') return 'stopping';
  if (isBusy(status)) return 'busy';
  return 'off';
}

/** Big round connect/disconnect button. During an attempt it cancels; while disconnecting it is inert. */
export function ConnectToggle({
  status,
  profileName,
  disabled,
  compact = false,
  onConnect,
  onDisconnect,
}: Props): React.JSX.Element {
  const { t } = useI18n();
  const visual = visualOf(status);
  const profile = profileName ?? '';

  const action =
    visual === 'off'
      ? { text: t('connect.action.connect'), label: t('connect.toggleLabel.connect', { profile }), run: onConnect }
      : visual === 'on'
        ? {
            text: t('connect.action.disconnect'),
            label: t('connect.toggleLabel.disconnect', { profile }),
            run: onDisconnect,
          }
        : visual === 'busy'
          ? { text: t('connect.action.cancel'), label: t('connect.toggleLabel.cancel', { profile }), run: onDisconnect }
          : { text: t('connect.action.disconnecting'), label: t('connect.action.disconnecting'), run: () => undefined };

  return (
    <div className={[styles.wrap, styles[visual], compact ? styles.compact : ''].join(' ')}>
      <span className={styles.ring} aria-hidden="true" />
      <button
        type="button"
        className={styles.toggle}
        onClick={action.run}
        disabled={disabled || visual === 'stopping'}
        aria-label={profileName ? action.label : action.text}
        title={compact ? action.text : undefined}
      >
        <PowerIcon size={40} strokeWidth={1.75} />
        <span className={styles.text}>{action.text}</span>
      </button>
    </div>
  );
}
