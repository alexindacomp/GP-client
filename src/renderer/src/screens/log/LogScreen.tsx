import { useLayoutEffect, useRef, useState } from 'react';
import { useI18n } from '../../i18n/I18nContext';
import { useLogLines } from '../../hooks/useLogLines';
import { useCopy } from '../../hooks/useCopy';
import { useAsyncAction } from '../../hooks/useAsyncAction';
import { localizeIpcError } from '../../lib/ipcErrors';
import { Page } from '../../components/layout/Page';
import { Button } from '../../components/ui/Button';
import { Banner } from '../../components/ui/Banner';
import { Checkbox } from '../../components/ui/Toggle';
import { Spinner } from '../../components/ui/Spinner';
import { CopyIcon, FolderIcon } from '../../components/ui/Icon';
import styles from './LogScreen.module.css';

const BOTTOM_THRESHOLD_PX = 8;

/** Live log. Auto-scroll follows new lines; scrolling up pauses it, scrolling to the end resumes. */
export function LogScreen(): React.JSX.Element {
  const { t } = useI18n();
  const { lines, loaded } = useLogLines();
  const [autoscroll, setAutoscroll] = useState(true);
  const view = useRef<HTMLDivElement>(null);
  const copy = useCopy();
  const open = useAsyncAction();

  useLayoutEffect(() => {
    const el = view.current;
    if (autoscroll && el) el.scrollTop = el.scrollHeight;
  }, [lines, autoscroll]);

  const onScroll = (): void => {
    const el = view.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= BOTTOM_THRESHOLD_PX;
    if (atBottom !== autoscroll) setAutoscroll(atBottom);
  };

  const copyLabel = copy.copied ? t('common.copied') : copy.failed ? t('log.copyFailed') : t('log.copy');

  return (
    <Page
      title={t('log.title')}
      actions={
        <>
          <Button
            variant="subtle"
            iconOnly
            label={copyLabel}
            icon={<CopyIcon />}
            onClick={() => void copy.copy(lines.map((l) => l.text).join('\n'))}
            disabled={lines.length === 0}
          />
          <Button
            variant="subtle"
            iconOnly
            label={t('log.openFolder')}
            icon={<FolderIcon />}
            onClick={() => void open.run(() => window.gp.logs.openFolder())}
            disabled={open.pending}
          />
        </>
      }
    >
      <span className="visually-hidden" role="status">
        {copy.copied ? t('common.copied') : copy.failed ? t('log.copyFailed') : ''}
      </span>
      {open.error ? (
        <Banner
          tone="error"
          role="alert"
          title={t('log.openFailed', { message: localizeIpcError(t, open.error).text })}
          onDismiss={open.clearError}
        />
      ) : null}
      <div
        ref={view}
        className={styles.log}
        role="log"
        aria-live="off"
        aria-label={t('log.label')}
        tabIndex={0}
        onScroll={onScroll}
      >
        {!loaded ? (
          <Spinner label={t('app.loading')} />
        ) : lines.length === 0 ? (
          <p className={styles.empty}>{t('log.empty')}</p>
        ) : (
          lines.map((l) => (
            <div key={l.id} className={styles.line}>
              {l.text}
            </div>
          ))
        )}
      </div>
      <Checkbox label={t('log.autoscroll')} checked={autoscroll} onChange={(e) => setAutoscroll(e.target.checked)} />
    </Page>
  );
}
