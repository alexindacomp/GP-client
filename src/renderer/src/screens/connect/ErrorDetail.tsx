import { useId, useState } from 'react';
import type { VpnState } from '@shared/ipc';
import { ChevronIcon } from '../../components/ui/Icon';
import { CodeText } from '../../components/ui/CodeText';
import { useI18n } from '../../i18n/I18nContext';
import styles from './ErrorDetail.module.css';

interface Props {
  error: NonNullable<VpnState['error']>;
  /** Hide the backend's next-step text (e.g. while it is already reconnecting by itself). */
  hideMessage?: boolean;
}

/**
 * Main's localized next step plus the raw technical cause (untranslated). The cause is
 * collapsed behind a "Details" disclosure so the banner stays short in a 600px window.
 */
export function ErrorDetail({ error, hideMessage = false }: Props): React.JSX.Element {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const detailId = useId();
  return (
    <>
      {error.message && !hideMessage ? (
        <p>
          <CodeText text={error.message} />
        </p>
      ) : null}
      {error.detail ? (
        <div className={styles.disclosure}>
          <button
            type="button"
            className={styles.toggle}
            aria-expanded={open}
            aria-controls={detailId}
            onClick={() => setOpen((o) => !o)}
          >
            <ChevronIcon size={12} className={open ? styles.chevronOpen : styles.chevron} />
            {t('error.details')}
          </button>
          <p id={detailId} className={styles.detail} hidden={!open}>
            {error.detail}
          </p>
        </div>
      ) : null}
    </>
  );
}
