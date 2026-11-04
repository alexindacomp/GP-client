import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';
import {
  IPC,
  type AuthPrompt,
  type ConnectOptions,
  type GpApi,
  type ProfileInput,
  type Settings,
  type Unsubscribe,
  type VpnState,
} from '../shared/ipc';

function subscribe<T>(channel: string, cb: (payload: T) => void): Unsubscribe {
  const listener = (_event: IpcRendererEvent, payload: T): void => cb(payload);
  ipcRenderer.on(channel, listener);
  return () => {
    ipcRenderer.removeListener(channel, listener);
  };
}

const api: GpApi = {
  profiles: {
    list: () => ipcRenderer.invoke(IPC.profiles.list),
    save: (p: ProfileInput, password?: string) => ipcRenderer.invoke(IPC.profiles.save, p, password),
    remove: (id: string) => ipcRenderer.invoke(IPC.profiles.remove, id),
  },
  vpn: {
    connect: (profileId: string, opts?: ConnectOptions) => ipcRenderer.invoke(IPC.vpn.connect, profileId, opts),
    disconnect: () => ipcRenderer.invoke(IPC.vpn.disconnect),
    getState: () => ipcRenderer.invoke(IPC.vpn.getState),
    answerPrompt: (id: string, value: string | null) => ipcRenderer.invoke(IPC.vpn.answerPrompt, id, value),
    getPendingPrompts: () => ipcRenderer.invoke(IPC.vpn.getPendingPrompts),
    onState: (cb: (s: VpnState) => void) => subscribe(IPC.vpn.state, cb),
    onPrompt: (cb: (p: AuthPrompt) => void) => subscribe(IPC.vpn.prompt, cb),
  },
  logs: {
    get: () => ipcRenderer.invoke(IPC.logs.get),
    onLine: (cb: (line: string) => void) => subscribe(IPC.logs.line, cb),
    openFolder: () => ipcRenderer.invoke(IPC.logs.openFolder),
  },
  settings: {
    get: () => ipcRenderer.invoke(IPC.settings.get),
    set: (patch: Partial<Settings>) => ipcRenderer.invoke(IPC.settings.set, patch),
  },
  system: {
    info: () => ipcRenderer.invoke(IPC.system.info),
    onThemeChange: (cb: (dark: boolean) => void) => subscribe(IPC.system.themeChanged, cb),
    openExternal: (url: string) => ipcRenderer.invoke(IPC.system.openExternal, url),
  },
  window: {
    minimize: () => ipcRenderer.send(IPC.window.minimize),
    close: () => ipcRenderer.send(IPC.window.close),
  },
};

contextBridge.exposeInMainWorld('gp', api);
