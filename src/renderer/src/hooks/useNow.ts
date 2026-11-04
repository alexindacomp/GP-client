import { useEffect, useState } from 'react';

/** Current time, re-rendering every `intervalMs` while `enabled`. */
export function useNow(enabled: boolean, intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return undefined;
    const tick = (): void => setNow(Date.now());
    const id = window.setInterval(tick, intervalMs);
    const first = window.setTimeout(tick, 0);
    return () => {
      window.clearInterval(id);
      window.clearTimeout(first);
    };
  }, [enabled, intervalMs]);
  return now;
}
