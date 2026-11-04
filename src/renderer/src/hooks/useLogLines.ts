import { useEffect, useState } from 'react';

export const MAX_LOG_LINES = 2000;

export interface LogLine {
  /** Monotonic id, stable across front truncation (used as React key). */
  id: number;
  text: string;
}

function cap(lines: LogLine[]): LogLine[] {
  return lines.length > MAX_LOG_LINES ? lines.slice(lines.length - MAX_LOG_LINES) : lines;
}

/** Log snapshot plus live lines, capped like main's ring buffer. */
export function useLogLines(): { lines: LogLine[]; loaded: boolean } {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let live = true;
    let nextId = 0;
    let snapshotDone = false;
    const early: string[] = [];
    const toLines = (texts: string[]): LogLine[] => texts.map((text) => ({ id: nextId++, text }));

    const unsubscribe = window.gp.logs.onLine((text) => {
      if (!live) return;
      if (!snapshotDone) early.push(text);
      else setLines((prev) => cap([...prev, ...toLines([text])]));
    });
    const finish = (snapshot: string[]): void => {
      if (!live) return;
      snapshotDone = true;
      // Lines received while the snapshot was in flight may already be part of it.
      const tail = new Set(snapshot.slice(-early.length - 1));
      setLines(cap(toLines([...snapshot, ...early.filter((l) => !tail.has(l))])));
      setLoaded(true);
    };
    window.gp.logs.get().then(finish, (err: unknown) => {
      console.error('Failed to read the log', err);
      finish([]);
    });
    return () => {
      live = false;
      unsubscribe();
    };
  }, []);

  return { lines, loaded };
}
