import { Menu, Tray, nativeImage, type MenuItemConstructorOptions } from 'electron';
import path from 'node:path';
import type { Language, Profile, VpnState, VpnStatus } from '../shared/ipc';
import { TRAY_LABELS, trayTooltip } from './tray-labels';

type IconState = 'disconnected' | 'connecting' | 'connected';

export function iconStateFor(status: VpnStatus): IconState {
  if (status === 'connected') return 'connected';
  if (status === 'disconnected' || status === 'error') return 'disconnected';
  return 'connecting';
}

export interface TrayModel {
  state: VpnState;
  profiles: Profile[];
  selectedProfileId?: string;
  language: Language;
}

export interface TrayActions {
  connect(profileId: string): void;
  disconnect(): void;
  selectProfile(profileId: string): void;
  show(): void;
  quit(): void;
}

export class AppTray {
  private readonly tray: Tray;
  private iconState: IconState | null = null;

  constructor(
    private readonly iconDir: string,
    private readonly actions: TrayActions,
  ) {
    this.tray = new Tray(this.icon('disconnected'));
    this.tray.setToolTip('GP Connect');
    if (process.platform !== 'darwin') this.tray.on('click', () => actions.show());
  }

  update(model: TrayModel): void {
    const iconState = iconStateFor(model.state.status);
    if (iconState !== this.iconState) {
      this.iconState = iconState;
      this.tray.setImage(this.icon(iconState));
    }
    this.tray.setToolTip(trayTooltip(model.language, model.state.status, model.state.assignedIp));
    this.tray.setContextMenu(Menu.buildFromTemplate(this.menu(model)));
  }

  destroy(): void {
    this.tray.destroy();
  }

  private menu(m: TrayModel): MenuItemConstructorOptions[] {
    const l = TRAY_LABELS[m.language];
    const busy = m.state.status !== 'disconnected' && m.state.status !== 'error';
    const selected = m.selectedProfileId ?? m.profiles[0]?.id;
    const profileItems: MenuItemConstructorOptions[] = m.profiles.length
      ? m.profiles.map((p) => ({
          label: p.name,
          type: 'radio',
          checked: p.id === selected,
          enabled: !busy,
          click: () => this.actions.selectProfile(p.id),
        }))
      : [{ label: l.noProfiles, enabled: false }];

    return [
      { label: `${l[m.state.status] ?? m.state.status}`, enabled: false },
      { type: 'separator' },
      busy
        ? {
            label: l.disconnect,
            // A stop is already in flight; another click would only add admin dialogs.
            enabled: m.state.status !== 'disconnecting',
            click: () => this.actions.disconnect(),
          }
        : {
            label: l.connect,
            enabled: selected !== undefined,
            click: () => selected && this.actions.connect(selected),
          },
      { label: l.profiles, submenu: profileItems },
      { type: 'separator' },
      { label: l.show, click: () => this.actions.show() },
      { label: l.quit, click: () => this.actions.quit() },
    ];
  }

  private icon(state: IconState): Electron.NativeImage {
    // macOS menubar: monochrome template images adapt to light/dark menubar.
    const name = process.platform === 'darwin' ? `tray-${state}Template.png` : `tray-${state}.png`;
    const img = nativeImage.createFromPath(path.join(this.iconDir, name));
    if (process.platform === 'darwin') img.setTemplateImage(true);
    return img;
  }
}
