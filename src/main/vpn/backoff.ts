/** Auto-reconnect delays from the spec: 2 / 5 / 10 / 30 s, then 30 s. */
export const DEFAULT_BACKOFF_MS: readonly number[] = [2_000, 5_000, 10_000, 30_000];

/** Delay before reconnect attempt number `attempt` (0-based). */
export function backoffDelay(attempt: number, schedule: readonly number[] = DEFAULT_BACKOFF_MS): number {
  if (schedule.length === 0) throw new RangeError('Backoff schedule must not be empty');
  const i = Math.min(Math.max(0, Math.floor(attempt)), schedule.length - 1);
  return schedule[i]!;
}
