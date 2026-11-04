import { BrowserWindow, nativeTheme, shell, type BrowserWindowConstructorOptions } from 'electron';
import { isAppUrl, type RendererLocation } from './security';

const TITLE_BAR_HEIGHT = 36;

export interface MainWindowOptions {
  preload: string;
  renderer: RendererLocation;
  icon?: string;
  isDev: boolean;
  show: boolean;
}

/** Window-controls overlay colours for the current theme (Windows only). */
export function titleBarOverlayFor(dark: boolean): Electron.TitleBarOverlayOptions {
  return {
    // Transparent so Mica shows through; symbols contrast with the theme background.
    color: '#00000000',
    symbolColor: dark ? '#FFFFFF' : '#1A1A1A',
    height: TITLE_BAR_HEIGHT,
  };
}

/** Solid fallback background (used where no material/vibrancy is available). */
export function backgroundFor(dark: boolean): string {
  return dark ? '#202020' : '#F3F3F3';
}

function platformOptions(dark: boolean): BrowserWindowConstructorOptions {
  switch (process.platform) {
    case 'win32':
      return {
        titleBarStyle: 'hidden',
        titleBarOverlay: titleBarOverlayFor(dark),
        backgroundMaterial: 'mica',
        backgroundColor: '#00000000',
      };
    case 'darwin':
      return {
        titleBarStyle: 'hiddenInset',
        vibrancy: 'under-window',
        visualEffectState: 'active',
        backgroundColor: '#00000000',
      };
    default:
      return { backgroundColor: backgroundFor(dark) };
  }
}

export function createMainWindow(opts: MainWindowOptions): BrowserWindow {
  const dark = nativeTheme.shouldUseDarkColors;
  const win = new BrowserWindow({
    width: 380,
    height: 600,
    minWidth: 360,
    minHeight: 520,
    show: false,
    title: 'GP Connect',
    icon: opts.icon,
    autoHideMenuBar: true,
    fullscreenable: false,
    maximizable: false,
    ...platformOptions(dark),
    webPreferences: {
      preload: opts.preload,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      devTools: opts.isDev,
    },
  });
  win.removeMenu();

  if (opts.show) win.once('ready-to-show', () => win.show());

  // The app UI never navigates; external links open in the system browser.
  win.webContents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url, opts.renderer)) event.preventDefault();
  });
  win.webContents.on('will-redirect', (event, url) => {
    if (!isAppUrl(url, opts.renderer)) event.preventDefault();
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url);
    return { action: 'deny' };
  });

  if (opts.renderer.devUrl) void win.loadURL(opts.renderer.devUrl);
  else void win.loadFile(opts.renderer.indexHtml);
  return win;
}

/** Keeps native window chrome in sync with the theme. */
export function applyThemeToWindow(win: BrowserWindow, dark: boolean): void {
  if (win.isDestroyed()) return;
  if (process.platform === 'win32') {
    win.setTitleBarOverlay(titleBarOverlayFor(dark));
  } else if (process.platform === 'linux') {
    win.setBackgroundColor(backgroundFor(dark));
  }
}

export function showWindow(win: BrowserWindow | null): void {
  if (!win || win.isDestroyed()) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}
