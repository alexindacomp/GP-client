import type { ReactNode } from 'react';
import { useI18n } from '../../i18n/I18nContext';
import { Button } from './Button';
import { CloseIcon, ErrorIcon, InfoIcon, CheckIcon, WarningIcon } from './Icon';
import styles from './Banner.module.css';

export type BannerTone = 'error' | 'warning' | 'info' | 'success';

interface BannerProps {
  tone: BannerTone;
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
  onDismiss?: () => void;
  /** `alert` interrupts screen readers (errors), `status` is polite. */
  role?: 'alert' | 'status';
}

const ICONS = { error: ErrorIcon, warning: WarningIcon, info: InfoIcon, success: CheckIcon } as const;

/** Fluent InfoBar. */
export function Banner({ tone, title, children, actions, onDismiss, role = 'status' }: BannerProps): React.JSX.Element {
  const { t } = useI18n();
  const Icon = ICONS[tone];
  return (
    <div className={[styles.banner, styles[tone]].join(' ')} role={role}>
      <Icon className={styles.icon} />
      <div className={styles.body}>
        <p className={styles.title}>{title}</p>
        {children ? <div className={styles.text}>{children}</div> : null}
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </div>
      {onDismiss ? (
        <Button
          variant="subtle"
          iconOnly
          label={t('common.dismiss')}
          icon={<CloseIcon size={16} />}
          onClick={onDismiss}
          className={styles.dismiss}
        />
      ) : null}
    </div>
  );
}
