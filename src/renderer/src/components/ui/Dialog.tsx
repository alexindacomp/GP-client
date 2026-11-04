import { useEffect, useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import styles from './Dialog.module.css';

interface DialogProps {
  title: string;
  description?: ReactNode;
  /** Escape key. Backdrop clicks never close the dialog (it may cancel a connection). */
  onCancel: () => void;
  children: ReactNode;
  /** Role `alertdialog` for destructive confirmations. */
  role?: 'dialog' | 'alertdialog';
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Modal dialog: focus moves in (first `[data-autofocus]` or focusable), is trapped, and restored on close. */
export function Dialog({ title, description, onCancel, children, role = 'dialog' }: DialogProps): React.JSX.Element {
  const titleId = useId();
  const descId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const cancelRef = useRef(onCancel);

  useEffect(() => {
    cancelRef.current = onCancel;
  });

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const node = panel.current;
    const target = node?.querySelector<HTMLElement>('[data-autofocus]') ?? node?.querySelector<HTMLElement>(FOCUSABLE);
    (target ?? node)?.focus();
    return () => {
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, []);

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>): void => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      cancelRef.current();
      return;
    }
    if (e.key !== 'Tab' || !panel.current) return;
    const items = [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) {
      e.preventDefault();
      return;
    }
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div className={styles.backdrop}>
      <div
        ref={panel}
        className={styles.panel}
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <h2 id={titleId} className={styles.title}>
          {title}
        </h2>
        {description ? (
          <div id={descId} className={styles.description}>
            {description}
          </div>
        ) : null}
        {children}
      </div>
    </div>,
    document.body,
  );
}

/** Footer with right-aligned actions (Fluent dialog layout). */
export function DialogActions({ children }: { children: ReactNode }): React.JSX.Element {
  return <div className={styles.actions}>{children}</div>;
}
