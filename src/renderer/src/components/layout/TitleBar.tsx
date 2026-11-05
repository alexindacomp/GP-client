import type { SystemInfo } from '@shared/ipc';
import { useI18n } from '../../i18n/I18nContext';
import styles from './TitleBar.module.css';

/**
 * - `native`: the OS draws the title bar (Windows, Linux) — nothing to render.
 * - `overlay-mac`: macOS `titleBarStyle: "Overlay"`, traffic lights over the content.
 */
export type TitleBarMode = 'native' | 'overlay-mac';

export function titleBarMode(platform: SystemInfo['platform']): TitleBarMode {
  return platform === 'darwin' ? 'overlay-mac' : 'native';
}

/**
 * Draggable title area for the macOS overlay title bar. `data-tauri-drag-region` makes the header
 * drag the window; its children ignore pointer events so the header itself is the hit target.
 */
export function TitleBar({ mode }: { mode: TitleBarMode }): React.JSX.Element | null {
  const { t } = useI18n();
  if (mode === 'native') return null;
  return (
    <header className={styles.titleBar} data-tauri-drag-region>
      <span className={styles.title}>{t('app.name')}</span>
    </header>
  );
}
