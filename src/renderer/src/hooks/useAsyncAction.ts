import { useCallback, useEffect, useRef, useState } from 'react';

export interface AsyncAction {
  pending: boolean;
  error: unknown;
  /** Runs `fn` unless another run is in flight; returns false if it was skipped or failed. */
  run(fn: () => Promise<unknown>): Promise<boolean>;
  clearError(): void;
}

/** Guards double submits and keeps the last error; no state updates after unmount. */
export function useAsyncAction(): AsyncAction {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inFlight = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (fn: () => Promise<unknown>) => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setPending(true);
    setError(null);
    try {
      await fn();
      return true;
    } catch (err) {
      if (mounted.current) setError(err);
      return false;
    } finally {
      inFlight.current = false;
      if (mounted.current) setPending(false);
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return { pending, error, run, clearError };
}
