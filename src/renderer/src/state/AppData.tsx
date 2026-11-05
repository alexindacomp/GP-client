import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Profile, ProfileInput, Settings, SystemInfo } from '@shared/ipc';

export interface AppData {
  info: SystemInfo;
  settings: Settings;
  profiles: Profile[];
  /** Re-detects openconnect (the backend refreshes its lookup on every call). */
  refreshInfo(): Promise<SystemInfo>;
  updateSettings(patch: Partial<Settings>): Promise<Settings>;
  saveProfile(input: ProfileInput, password?: string): Promise<Profile>;
  removeProfile(id: string): Promise<void>;
}

const AppDataContext = createContext<AppData | null>(null);

export function useAppData(): AppData {
  const ctx = useContext(AppDataContext);
  if (!ctx) throw new Error('useAppData must be used inside <AppDataProvider>');
  return ctx;
}

interface Loaded {
  info: SystemInfo;
  settings: Settings;
  profiles: Profile[];
}

export type BootState = { status: 'loading' } | { status: 'error'; retry: () => void } | { status: 'ready' };

interface ProviderProps {
  /** Rendered instead of children until the initial data is loaded. */
  fallback: (boot: Exclude<BootState, { status: 'ready' }>) => ReactNode;
  children: ReactNode;
}

export function AppDataProvider({ fallback, children }: ProviderProps): React.JSX.Element {
  const [data, setData] = useState<Loaded | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    Promise.all([window.gp.system.info(), window.gp.settings.get(), window.gp.profiles.list()]).then(
      ([info, settings, profiles]) => {
        if (live) setData({ info, settings, profiles });
      },
      (err: unknown) => {
        console.error('Failed to load initial data', err);
        if (live) setFailed(true);
      },
    );
    return () => {
      live = false;
    };
  }, [attempt]);

  // Settings can also change from the tray (selected profile); re-read them when the window regains focus.
  useEffect(() => {
    const onFocus = (): void => {
      window.gp.settings.get().then(
        (settings) => setData((d) => (d ? { ...d, settings } : d)),
        (err: unknown) => console.error('Failed to refresh settings', err),
      );
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  const retry = useCallback(() => {
    setFailed(false);
    setAttempt((n) => n + 1);
  }, []);

  const refreshInfo = useCallback(async () => {
    const info = await window.gp.system.info();
    setData((d) => (d ? { ...d, info } : d));
    return info;
  }, []);

  const updateSettings = useCallback(async (patch: Partial<Settings>) => {
    const settings = await window.gp.settings.set(patch);
    setData((d) => (d ? { ...d, settings } : d));
    return settings;
  }, []);

  const saveProfile = useCallback(async (input: ProfileInput, password?: string) => {
    const saved = await window.gp.profiles.save(input, password);
    setData((d) => {
      if (!d) return d;
      const exists = d.profiles.some((p) => p.id === saved.id);
      const profiles = exists ? d.profiles.map((p) => (p.id === saved.id ? saved : p)) : [...d.profiles, saved];
      return { ...d, profiles };
    });
    return saved;
  }, []);

  const removeProfile = useCallback(async (id: string) => {
    await window.gp.profiles.remove(id);
    setData((d) => (d ? { ...d, profiles: d.profiles.filter((p) => p.id !== id) } : d));
  }, []);

  const value = useMemo<AppData | null>(
    () => (data ? { ...data, refreshInfo, updateSettings, saveProfile, removeProfile } : null),
    [data, refreshInfo, updateSettings, saveProfile, removeProfile],
  );

  if (!value) return <>{fallback(failed ? { status: 'error', retry } : { status: 'loading' })}</>;
  return <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>;
}
