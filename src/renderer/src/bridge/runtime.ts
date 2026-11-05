import { isTauri } from '@tauri-apps/api/core';
import { createTauriGp } from './tauri';

/**
 * Which host runs the renderer:
 * - `tauri`: the desktop app (window.gp is installed here from bridge/tauri.ts);
 * - `preview`: `npm run preview:web` with the mocked window.gp (marks itself with <html data-shell>);
 * - `browser`: a plain browser without any bridge.
 */
export type Shell = 'tauri' | 'preview' | 'browser';

let shell: Shell = 'browser';

export function currentShell(): Shell {
  return shell;
}

/** Must run before the app renders. */
export function installBridge(): Shell {
  const root = document.documentElement;
  if (isTauri()) {
    window.gp = createTauriGp();
    shell = 'tauri';
  } else if (root.dataset.shell === 'preview' && (window as Partial<Window>).gp) {
    shell = 'preview';
  } else {
    shell = 'browser';
  }
  root.dataset.shell = shell;
  return shell;
}

/** True when a `window.gp` implementation is available (false in a bare browser without the mock). */
export function hasBridge(): boolean {
  return Boolean((window as Partial<Window>).gp);
}
