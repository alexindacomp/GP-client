import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import styles from './Field.module.css';

interface FieldFrameProps {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  optionalLabel?: string;
  /** Renders the control; receives ids for a11y wiring. */
  children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => ReactNode;
}

/** Label + control + hint/error, with aria-describedby/aria-invalid wired up. */
export function FieldFrame({ label, hint, error, optionalLabel, children }: FieldFrameProps): React.JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(' ') || undefined;
  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
        {optionalLabel ? <span className={styles.optional}> ({optionalLabel})</span> : null}
      </label>
      {children({ id, describedBy, invalid: Boolean(error) })}
      {error ? (
        <p id={errorId} className={styles.error}>
          {error}
        </p>
      ) : null}
      {hint ? (
        <p id={hintId} className={styles.hint}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

type Common = { label: string; hint?: ReactNode; error?: string | null; optionalLabel?: string };

export function TextField({
  label,
  hint,
  error,
  optionalLabel,
  className,
  ...input
}: Common & InputHTMLAttributes<HTMLInputElement>): React.JSX.Element {
  return (
    <FieldFrame label={label} hint={hint} error={error} optionalLabel={optionalLabel}>
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          className={[styles.control, className ?? ''].join(' ')}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          spellCheck={false}
          {...input}
        />
      )}
    </FieldFrame>
  );
}

export function TextAreaField({
  label,
  hint,
  error,
  optionalLabel,
  className,
  ...textarea
}: Common & TextareaHTMLAttributes<HTMLTextAreaElement>): React.JSX.Element {
  return (
    <FieldFrame label={label} hint={hint} error={error} optionalLabel={optionalLabel}>
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          className={[styles.control, styles.textarea, className ?? ''].join(' ')}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          spellCheck={false}
          {...textarea}
        />
      )}
    </FieldFrame>
  );
}

export interface SelectOption {
  value: string;
  label: string;
}

export function SelectField({
  label,
  hint,
  error,
  options,
  className,
  ...select
}: Common & { options: SelectOption[] } & SelectHTMLAttributes<HTMLSelectElement>): React.JSX.Element {
  return (
    <FieldFrame label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <select
          id={id}
          className={[styles.control, styles.select, className ?? ''].join(' ')}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          {...select}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      )}
    </FieldFrame>
  );
}
