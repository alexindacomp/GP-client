import { useCallback, useEffect, useRef, useState } from 'react';
import type { AuthPrompt, VpnStatus } from '@shared/ipc';

/** Prompts only make sense while an attempt is authenticating/connecting. */
const PROMPT_STATUSES: ReadonlySet<VpnStatus> = new Set(['prelogin', 'authenticating', 'connecting', 'reconnecting']);

export interface ActivePrompt {
  prompt: AuthPrompt;
  /** First password prompt of the attempt: the one "Remember password" applies to. */
  offerRemember: boolean;
}

export interface AuthPromptApi {
  active: ActivePrompt | null;
  /** Sends the answer (or `null` to cancel) and closes the dialog. Rejects with the IPC error. */
  answer(id: string, value: string | null): Promise<void>;
}

/**
 * Tracks the pending auth prompt. Main drops prompts silently when the attempt ends, so the
 * dialog is closed when the state leaves the connecting phases.
 */
export function useAuthPrompt(): AuthPromptApi {
  const [active, setActive] = useState<ActivePrompt | null>(null);
  const passwordPromptSeen = useRef(false);
  const shownId = useRef<string | null>(null);

  useEffect(() => {
    let live = true;
    let gotEvent = false;
    // Main re-pushes pending prompts after a reload as well: show each prompt id once.
    const show = (prompt: AuthPrompt): void => {
      if (!live || shownId.current === prompt.id) return;
      shownId.current = prompt.id;
      const offerRemember = prompt.kind === 'password' && !passwordPromptSeen.current;
      if (prompt.kind === 'password') passwordPromptSeen.current = true;
      setActive({ prompt, offerRemember });
    };
    const offState = window.gp.vpn.onState((s) => {
      if (s.status === 'prelogin') passwordPromptSeen.current = false;
      if (live && !PROMPT_STATUSES.has(s.status)) setActive(null);
    });
    const offPrompt = window.gp.vpn.onPrompt((prompt) => {
      gotEvent = true;
      show(prompt);
    });
    // Subscribe first, then read the snapshot: a prompt sent before mount is not lost,
    // and a newer pushed prompt wins over the snapshot.
    window.gp.vpn.getPendingPrompts().then(
      (pending) => {
        const latest = pending[pending.length - 1];
        if (!gotEvent && latest) show(latest);
      },
      (err: unknown) => console.error('Failed to read pending prompts', err),
    );
    return () => {
      live = false;
      offState();
      offPrompt();
    };
  }, []);

  const answer = useCallback(async (id: string, value: string | null) => {
    try {
      await window.gp.vpn.answerPrompt(id, value);
    } finally {
      setActive((a) => (a?.prompt.id === id ? null : a));
    }
  }, []);

  return { active, answer };
}
