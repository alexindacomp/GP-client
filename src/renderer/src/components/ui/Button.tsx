import type { ButtonHTMLAttributes, ReactNode } from 'react';
import styles from './Button.module.css';

export type ButtonVariant = 'primary' | 'secondary' | 'subtle' | 'danger';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  icon?: ReactNode;
  /** Icon-only button: `label` becomes the accessible name and tooltip. */
  iconOnly?: boolean;
  label?: string;
}

export function Button({
  variant = 'secondary',
  icon,
  iconOnly = false,
  label,
  className,
  children,
  type = 'button',
  ...rest
}: ButtonProps): React.JSX.Element {
  const classes = [styles.button, styles[variant], iconOnly ? styles.iconOnly : '', className ?? '']
    .filter(Boolean)
    .join(' ');
  return (
    <button
      type={type}
      className={classes}
      aria-label={iconOnly ? label : undefined}
      title={iconOnly ? label : undefined}
      {...rest}
    >
      {icon}
      {iconOnly ? null : (children ?? label)}
    </button>
  );
}
