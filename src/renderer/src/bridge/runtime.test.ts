import { afterEach, describe, expect, it, vi } from 'vitest';

const isTauri = vi.fn(() => false);
vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => isTauri(), invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

const { installBridge, currentShell, hasBridge } = await import('./runtime');

const root = document.documentElement;
const original = (window as Partial<Window>).gp;

afterEach(() => {
  delete root.dataset.shell;
  (window as Partial<Window>).gp = original;
  isTauri.mockReturnValue(false);
});

describe('installBridge', () => {
  it('installs the Tauri bridge inside Tauri', () => {
    isTauri.mockReturnValue(true);
    delete (window as Partial<Window>).gp;
    expect(installBridge()).toBe('tauri');
    expect(window.gp.vpn.connect).toBeTypeOf('function');
    expect(currentShell()).toBe('tauri');
    expect(root.dataset.shell).toBe('tauri');
  });

  it('keeps the preview mock', () => {
    const mock = {} as Window['gp'];
    window.gp = mock;
    root.dataset.shell = 'preview';
    expect(installBridge()).toBe('preview');
    expect(window.gp).toBe(mock);
  });

  it('is "browser" without any bridge', () => {
    delete (window as Partial<Window>).gp;
    expect(installBridge()).toBe('browser');
    expect(hasBridge()).toBe(false);
  });
});
