import { useEffect, useState } from 'react';
import type { SystemInfo, Theme } from '@shared/ipc';

/** Resolved theme: explicit choice wins, `system` follows the OS (via main's nativeTheme). */
export function resolveTheme(theme: Theme, systemDark: boolean): 'light' | 'dark' {
  if (theme === 'system') return systemDark ? 'dark' : 'light';
  return theme;
}

/**
 * Applies `data-theme` and `data-platform` to <html>. Changing the setting applies immediately;
 * OS changes arrive through `system.onThemeChange`.
 */
export function useApplyTheme(theme: Theme, info: SystemInfo): 'light' | 'dark' {
  const [systemDark, setSystemDark] = useState(info.shouldUseDarkColors);

  useEffect(() => window.gp.system.onThemeChange(setSystemDark), []);

  const resolved = resolveTheme(theme, systemDark);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolved;
    root.dataset.platform = info.platform;
  }, [resolved, info.platform]);

  return resolved;
}
