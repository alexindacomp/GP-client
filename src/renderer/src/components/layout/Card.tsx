import type { HTMLAttributes } from 'react';
import styles from './Card.module.css';

/** Fluent "card" layer (8px radius, subtle stroke). */
export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>): React.JSX.Element {
  return <div className={[styles.card, className ?? ''].join(' ')} {...rest} />;
}
