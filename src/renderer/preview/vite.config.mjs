// DEV-ONLY: serves the renderer in a plain browser with a mocked window.gp (npm run preview:web).
// Not used by electron-vite; the Electron build only bundles src/renderer/index.html.
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const renderer = resolve(import.meta.dirname, '..');

export default defineConfig({
  root: renderer,
  plugins: [react()],
  resolve: {
    alias: {
      '@renderer': resolve(renderer, 'src'),
      '@shared': resolve(renderer, '../shared'),
    },
  },
  server: { port: 5199, strictPort: true, open: false },
});
