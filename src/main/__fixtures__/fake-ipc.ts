/**
 * In-memory stand-in for Electron's ipcMain plus fake senders, so the real
 * handlers in src/main/ipc/handlers.ts (incl. sender validation) can be invoked.
 * Use with: vi.mock('electron', () => fakeElectronModule()).
 */
import { pathToFileURL } from 'node:url';
import type { RendererLocation } from '../security';

type InvokeHandler = (event: unknown, ...args: unknown[]) => unknown;
type OnHandler = (event: unknown, ...args: unknown[]) => void;

export const ipcRegistry = {
  handlers: new Map<string, InvokeHandler>(),
  listeners: new Map<string, OnHandler>(),
  reset(): void {
    this.handlers.clear();
    this.listeners.clear();
  },
};

export function fakeElectronModule(): Record<string, unknown> {
  return {
    ipcMain: {
      handle: (channel: string, fn: InvokeHandler) => ipcRegistry.handlers.set(channel, fn),
      on: (channel: string, fn: OnHandler) => ipcRegistry.listeners.set(channel, fn),
    },
    app: { on: () => undefined },
    session: {},
  };
}

export const RENDERER: RendererLocation = { indexHtml: '/opt/gp-connect/resources/app/out/renderer/index.html' };
export const APP_URL = `${pathToFileURL(RENDERER.indexHtml).toString()}#/connect`;

export interface FakeFrame {
  url: string;
}
export interface FakeWebContents {
  id: number;
  mainFrame: FakeFrame;
}

let nextId = 1;
export function fakeWebContents(url = APP_URL): FakeWebContents {
  return { id: nextId++, mainFrame: { url } };
}

export interface FakeEvent {
  sender: FakeWebContents;
  senderFrame: FakeFrame | null;
}

/** Event as sent from the main frame of `wc` (or from `frame` when given, e.g. an iframe). */
export function eventFrom(wc: FakeWebContents, frame: FakeFrame | null = wc.mainFrame): FakeEvent {
  return { sender: wc, senderFrame: frame };
}

/** Calls a registered `ipcMain.handle` handler like `ipcRenderer.invoke` would. */
export async function invoke(event: FakeEvent, channel: string, ...args: unknown[]): Promise<unknown> {
  const h = ipcRegistry.handlers.get(channel);
  if (!h) throw new Error(`no handler for ${channel}`);
  return h(event, ...args);
}

/** Emits a fire-and-forget `ipcRenderer.send` message. */
export function send(event: FakeEvent, channel: string): void {
  const l = ipcRegistry.listeners.get(channel);
  if (!l) throw new Error(`no listener for ${channel}`);
  l(event);
}
