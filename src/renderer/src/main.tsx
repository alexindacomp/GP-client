import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { hasBridge, installBridge } from './bridge/runtime';
import './styles/tokens.css';
import './styles/base.css';

// Avoid a light flash before settings load: the webview's colour scheme already follows the OS/app theme.
if (window.matchMedia?.('(prefers-color-scheme: dark)').matches) {
  document.documentElement.dataset.theme = 'dark';
}

installBridge();

const root = document.getElementById('root');
if (root && !hasBridge()) {
  // Opened in a plain browser without the preview mock: nothing to talk to.
  root.textContent = 'GP Connect: window.gp is not available (run inside Tauri, or use npm run preview:web).';
} else if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
