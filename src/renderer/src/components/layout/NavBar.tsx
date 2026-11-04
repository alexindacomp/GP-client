import type { ComponentType, SVGProps } from 'react';
import type { MessageKey } from '../../i18n/dictionary';
import { useI18n } from '../../i18n/I18nContext';
import { LogIcon, PowerIcon, ProfilesIcon, SettingsIcon } from '../ui/Icon';
import styles from './NavBar.module.css';

export type View = 'connect' | 'profiles' | 'log' | 'settings';

const ITEMS: { view: View; label: MessageKey; Icon: ComponentType<SVGProps<SVGSVGElement>> }[] = [
  { view: 'connect', label: 'nav.connect', Icon: PowerIcon },
  { view: 'profiles', label: 'nav.profiles', Icon: ProfilesIcon },
  { view: 'log', label: 'nav.log', Icon: LogIcon },
  { view: 'settings', label: 'nav.settings', Icon: SettingsIcon },
];

export function NavBar({ current, onNavigate }: { current: View; onNavigate: (v: View) => void }): React.JSX.Element {
  const { t } = useI18n();
  return (
    <nav className={styles.nav} aria-label={t('nav.label')}>
      {ITEMS.map(({ view, label, Icon }) => (
        <button
          key={view}
          type="button"
          className={styles.item}
          aria-current={current === view ? 'page' : undefined}
          onClick={() => onNavigate(view)}
        >
          <Icon />
          <span className={styles.label}>{t(label)}</span>
        </button>
      ))}
    </nav>
  );
}
