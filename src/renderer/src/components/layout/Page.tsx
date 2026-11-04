import { useId, type ReactNode } from 'react';
import styles from './Page.module.css';

interface PageProps {
  title: string;
  /** Keep the heading for screen readers but hide it visually. */
  hideTitle?: boolean;
  /** Controls shown at the right of the heading. */
  actions?: ReactNode;
  children: ReactNode;
}

export function Page({ title, hideTitle = false, actions, children }: PageProps): React.JSX.Element {
  const headingId = useId();
  return (
    <section className={styles.page} aria-labelledby={headingId}>
      <div className={hideTitle ? 'visually-hidden' : styles.header}>
        <h1 id={headingId} className={styles.title}>
          {title}
        </h1>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
