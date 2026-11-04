import { useCallback, useEffect, useRef } from 'react';
import type { Profile, ProfileInput } from '@shared/ipc';

interface Pending {
  profileId: string;
  password: string;
}

/**
 * "Remember password" from the auth dialog. The password is stored only after the attempt
 * reaches `connected`, so a mistyped password is never persisted (otherwise every following
 * attempt would fail with the saved wrong password). Dropped on error/disconnect.
 */
export function useRememberPassword(
  profiles: Profile[],
  saveProfile: (input: ProfileInput, password?: string) => Promise<Profile>,
): (profileId: string, password: string) => void {
  const pending = useRef<Pending | null>(null);
  const latest = useRef({ profiles, saveProfile });

  useEffect(() => {
    latest.current = { profiles, saveProfile };
  });

  useEffect(
    () =>
      window.gp.vpn.onState((s) => {
        const p = pending.current;
        if (!p) return;
        if (s.status === 'connected' && s.profileId === p.profileId) {
          pending.current = null;
          const profile = latest.current.profiles.find((x) => x.id === p.profileId);
          if (!profile) return;
          latest.current
            .saveProfile({ ...profile, savePassword: true }, p.password)
            .catch((err: unknown) => console.error('Failed to save password', err));
        } else if (s.status === 'disconnected' || s.status === 'error') {
          pending.current = null;
        }
      }),
    [],
  );

  return useCallback((profileId: string, password: string) => {
    pending.current = { profileId, password };
  }, []);
}
