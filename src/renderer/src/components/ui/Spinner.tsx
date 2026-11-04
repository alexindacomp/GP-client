import styles from './Spinner.module.css';

/** Indeterminate progress ring; pass `label` when it is the only status indicator. */
export function Spinner({ size = 16, label }: { size?: number; label?: string }): React.JSX.Element {
  return (
    <span
      className={styles.spinner}
      style={{ width: size, height: size }}
      role={label ? 'progressbar' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  );
}
