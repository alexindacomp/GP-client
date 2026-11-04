import { app } from 'electron';
import path from 'node:path';

/** `resources/` in development, `process.resourcesPath` when packaged. */
export function resourcesDir(): string {
  return app.isPackaged ? process.resourcesPath : path.join(app.getAppPath(), 'resources');
}

export function trayIconDir(): string {
  return path.join(resourcesDir(), 'tray');
}

/** Bundled binaries live in `<resources>/bin/<platform>/`. */
export function bundledBinDir(): string {
  return path.join(resourcesDir(), 'bin');
}

export function appIconPath(): string {
  return path.join(resourcesDir(), 'icon.png');
}

export function userDataFile(name: string): string {
  return path.join(app.getPath('userData'), name);
}

export function logsDir(): string {
  return path.join(app.getPath('userData'), 'logs');
}
