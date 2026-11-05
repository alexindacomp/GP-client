/**
 * Global declaration of `window.gp` (installed by src/renderer/src/bridge on top of Tauri).
 * Usage in renderer code: `window.gp.vpn.connect(id)`.
 */
import type { GpApi } from './ipc';

declare global {
  interface Window {
    gp: GpApi;
  }
}

export {};
