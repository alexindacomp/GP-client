import { useId, type InputHTMLAttributes, type ReactNode } from 'react';
import styles from './Toggle.module.css';

type Base = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { label: string; hint?: ReactNode };

/** Fluent toggle switch (native checkbox with role="switch"). */
export function Switch({ label, hint, className, ...input }: Base): React.JSX.Element {
  const id = useId();
  return (
    <div className={[styles.row, className ?? ''].join(' ')}>
      <label htmlFor={id} className={styles.text}>
        <span>{label}</span>
        {hint ? <span className={styles.hint}>{hint}</span> : null}
      </label>
      <input id={id} type="checkbox" role="switch" className={styles.switch} {...input} />
    </div>
  );
}

export function Checkbox({ label, hint, className, ...input }: Base): React.JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className={[styles.checkRow, className ?? ''].join(' ')}>
      <input
        id={id}
        type="checkbox"
        className={styles.checkbox}
        aria-describedby={hint ? hintId : undefined}
        {...input}
      />
      <label htmlFor={id} className={styles.text}>
        <span>{label}</span>
        {hint ? (
          <span id={hintId} className={styles.hint}>
            {hint}
          </span>
        ) : null}
      </label>
    </div>
  );
}
