import { app } from 'electron';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HIDDEN_ARG = '--hidden';

/** Desktop Entry `Exec` quoting. */
function desktopQuote(s: string): string {
  return `"${s.replace(/(["`$\\])/g, '\\$1')}"`;
}

function linuxAutostartFile(): string {
  const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(configHome, 'autostart', 'gp-connect.desktop');
}

/** Enables/disables start at login. Linux uses an XDG autostart entry. */
export function setLaunchAtLogin(enabled: boolean): void {
  if (process.platform === 'linux') {
    const file = linuxAutostartFile();
    if (!enabled) {
      fs.rmSync(file, { force: true });
      return;
    }
    // AppImage: the stable path is the .AppImage file, not the temporary mount.
    const exec = process.env.APPIMAGE || process.execPath;
    const entry = [
      '[Desktop Entry]',
      'Type=Application',
      'Name=GP Connect',
      `Exec=${desktopQuote(exec)} ${HIDDEN_ARG}`,
      'X-GNOME-Autostart-enabled=true',
      'Terminal=false',
      '',
    ].join('\n');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, entry, { mode: 0o644 });
    return;
  }
  app.setLoginItemSettings({ openAtLogin: enabled, args: [HIDDEN_ARG] });
}

export function startedHidden(): boolean {
  if (process.argv.includes(HIDDEN_ARG)) return true;
  return process.platform === 'darwin' && app.getLoginItemSettings().wasOpenedAtLogin === true;
}
