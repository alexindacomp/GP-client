/**
 * Global declaration of the preload API for the renderer.
 * Usage in renderer code: `window.gp.vpn.connect(id)`.
 */
import type { GpApi } from '../shared/ipc';

declare global {
  interface Window {
    gp: GpApi;
  }
}

export {};
