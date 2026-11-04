import { useCallback, useEffect, useRef, useState } from 'react';

const FEEDBACK_MS = 2000;

/** Clipboard write with a short-lived "copied" flag. */
export function useCopy(): { copy(text: string): Promise<boolean>; copied: boolean; failed: boolean } {
  const [result, setResult] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<number | undefined>(undefined);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      window.clearTimeout(timer.current);
    };
  }, []);

  const copy = useCallback(async (text: string) => {
    let ok: boolean;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (err) {
      console.error('Clipboard write failed', err);
      ok = false;
    }
    if (!mounted.current) return ok;
    window.clearTimeout(timer.current);
    setResult(ok ? 'copied' : 'failed');
    timer.current = window.setTimeout(() => setResult('idle'), FEEDBACK_MS);
    return ok;
  }, []);

  return { copy, copied: result === 'copied', failed: result === 'failed' };
}
