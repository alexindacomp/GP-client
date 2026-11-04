/** `m:ss` below an hour, `h:mm:ss` above. */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const ss = String(s).padStart(2, '0');
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`;
}

/** Host part of a normalized portal URL, for compact display. */
export function portalHost(url: string): string {
  return url.replace(/^https:\/\//, '');
}
