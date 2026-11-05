import type { VpnState } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { useNow } from '../../hooks/useNow';
import { formatDuration } from '../../lib/format';
import { Card } from '../../components/layout/Card';
import styles from './StatusCard.module.css';

/** Connection details (no traffic counters: the backend does not report rx/tx). */
export function StatusCard({ state }: { state: VpnState }): React.JSX.Element | null {
  const { t } = useI18n();
  const connected = state.status === 'connected';
  const now = useNow(connected && state.connectedAt !== undefined);

  if (!connected && state.status !== 'reconnecting') return null;
  const gateway = state.gateway ? state.gateway.name || state.gateway.address : undefined;
  const rows: { label: string; value: string; mono?: boolean }[] = [];
  if (connected && state.assignedIp) rows.push({ label: t('connect.ip'), value: state.assignedIp, mono: true });
  if (gateway) rows.push({ label: t('connect.gatewayUsed'), value: gateway });
  if (connected && state.connectedAt !== undefined) {
    rows.push({ label: t('connect.duration'), value: formatDuration(now - state.connectedAt), mono: true });
  }
  if (rows.length === 0) return null;

  return (
    <Card>
      <dl className={styles.list}>
        {rows.map((r) => (
          <div key={r.label} className={styles.row}>
            <dt className={styles.term}>{r.label}</dt>
            <dd className={[styles.value, r.mono ? styles.mono : ''].join(' ')}>{r.value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
