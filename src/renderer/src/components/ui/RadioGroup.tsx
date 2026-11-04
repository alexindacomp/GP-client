import { useId } from 'react';
import styles from './RadioGroup.module.css';

export interface RadioOption<T extends string> {
  value: T;
  label: string;
}

interface Props<T extends string> {
  legend: string;
  name?: string;
  value: T;
  options: RadioOption<T>[];
  onChange: (value: T) => void;
  disabled?: boolean;
  /** `segmented` for 2-4 short options, `list` for a vertical list. */
  layout?: 'segmented' | 'list';
}

/** Native radio inputs inside a fieldset: arrow-key navigation comes for free. */
export function RadioGroup<T extends string>({
  legend,
  name,
  value,
  options,
  onChange,
  disabled,
  layout = 'segmented',
}: Props<T>): React.JSX.Element {
  const autoName = useId();
  const groupName = name ?? autoName;
  return (
    <fieldset className={styles.fieldset} disabled={disabled}>
      <legend className={styles.legend}>{legend}</legend>
      <div className={layout === 'segmented' ? styles.segmented : styles.list}>
        {options.map((o) => (
          <label key={o.value} className={styles.option}>
            <input
              type="radio"
              name={groupName}
              value={o.value}
              checked={o.value === value}
              onChange={() => onChange(o.value)}
              className={styles.input}
            />
            <span className={styles.label}>{o.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
