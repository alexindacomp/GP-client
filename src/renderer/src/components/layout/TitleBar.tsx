import type { SystemInfo } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import { ShieldIcon } from '../ui/Icon';
import styles from './TitleBar.module.css';

/**
 * Draggable custom title area. Windows: the native controls overlay sits at the top-right
 * (titleBarOverlay); macOS: traffic lights at the top-left (hiddenInset). Linux keeps the
 * native frame, so nothing is rendered there.
 */
export function TitleBar({ platform }: { platform: SystemInfo['platform'] }): React.JSX.Element | null {
  const { t } = useI18n();
  if (platform === 'linux') return null;
  return (
    <header className={[styles.titleBar, styles[platform]].join(' ')}>
      <ShieldIcon size={16} className={styles.icon} />
      <span className={styles.title}>{t('app.name')}</span>
    </header>
  );
}
