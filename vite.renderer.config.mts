/**
 * Vite config for the renderer under Tauri 2 (`tauri dev` / `tauri build`), per the Tauri + Vite guide.
 * src-tauri/tauri.conf.json must use:
 *   build.devUrl            = "http://localhost:1420"
 *   build.frontendDist      = "../dist-renderer"
 *   build.beforeDevCommand  = "npm run dev:renderer"
 *   build.beforeBuildCommand = "npm run build:renderer"
 */
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const host = process.env.TAURI_DEV_HOST; // set by `tauri dev` for mobile/remote devices only
const debug = Boolean(process.env.TAURI_ENV_DEBUG);
const rendererRoot = resolve(import.meta.dirname, 'src/renderer');

export default defineConfig({
  root: rendererRoot,
  plugins: [react()],
  resolve: {
    alias: {
      '@renderer': resolve(rendererRoot, 'src'),
      '@shared': resolve(import.meta.dirname, 'src/shared'),
    },
  },
  // Keep Rust/tauri-cli output visible.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: 'ws', host, port: 1421 } : undefined,
    watch: { ignored: ['**/src-tauri/**', '**/target/**', '**/crates/**'] },
  },
  // Exposes VITE_* and Tauri's TAURI_ENV_* (platform, arch, debug…) to import.meta.env.
  envPrefix: ['VITE_', 'TAURI_ENV_'],
  build: {
    // WebView2 (Chromium) on Windows, WKWebView/WebKitGTK elsewhere.
    target: process.env.TAURI_ENV_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    minify: !debug,
    sourcemap: debug,
    outDir: resolve(import.meta.dirname, 'dist-renderer'),
    emptyOutDir: true,
    rollupOptions: { input: resolve(rendererRoot, 'index.html') },
  },
});
