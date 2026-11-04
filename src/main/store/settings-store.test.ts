import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, type Settings } from '../../shared/ipc';
import { SettingsStore } from './settings-store';

let dir: string;
let file: string;
let warnings: string[];

const open = (): SettingsStore => new SettingsStore(file, (m) => warnings.push(m));
const write = (data: unknown): void => fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data));

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gp-settings-'));
  file = path.join(dir, 'settings.json');
  warnings = [];
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('SettingsStore', () => {
  it('uses the defaults without a file and persists changes across restarts', () => {
    const store = open();
    expect(store.get()).toEqual(DEFAULT_SETTINGS);
    store.set({ theme: 'dark', language: 'en', extraArgs: ['-v'] });
    expect(open().get()).toEqual({ ...DEFAULT_SETTINGS, theme: 'dark', language: 'en', extraArgs: ['-v'] });
    expect(warnings).toEqual([]);
  });

  it('a key patched to undefined is removed (cleared optional setting)', () => {
    const store = open();
    store.set({ openconnectPath: '/usr/sbin/openconnect' });
    store.set({ openconnectPath: undefined });
    expect(open().get()).not.toHaveProperty('openconnectPath');
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).not.toHaveProperty('openconnectPath');
  });

  it('notifies listeners with next and previous values; unsubscribe stops notifications', () => {
    const store = open();
    const l = vi.fn<(next: Settings, prev: Settings) => void>();
    const off = store.onChange(l);
    store.set({ theme: 'light' });
    expect(l).toHaveBeenCalledWith(
      expect.objectContaining({ theme: 'light' }),
      expect.objectContaining({ theme: 'system' }),
    );
    off();
    store.set({ theme: 'dark' });
    expect(l).toHaveBeenCalledOnce();
  });

  it('get() returns a copy: mutating it does not change the stored settings', () => {
    const store = open();
    const s = store.get();
    s.extraArgs.push('--script=/tmp/evil');
    s.theme = 'dark';
    expect(store.get()).toEqual(DEFAULT_SETTINGS);
  });

  it('does not change in-memory settings when writing the file fails', () => {
    const store = open();
    fs.mkdirSync(file); // a directory where the file should be → rename fails
    expect(() => store.set({ theme: 'dark' })).toThrow();
    expect(store.get().theme).toBe('system');
  });

  describe('corrupted or tampered settings.json', () => {
    it('unparseable JSON: defaults, the file is moved aside, a warning is logged', () => {
      write('{"theme": "dark",');
      expect(open().get()).toEqual(DEFAULT_SETTINGS);
      const files = fs.readdirSync(dir);
      expect(files).toEqual([expect.stringMatching(/^settings\.json\.corrupt-\d+$/)]);
      expect(warnings[0]).toMatch(/settings\.json is unreadable .*using defaults, old file kept at .*corrupt-\d+/);
    });

    it.each([['[]'], ['null'], ['"dark"']])('a non-object JSON value (%s) yields the defaults', (raw) => {
      write(raw);
      expect(open().get()).toEqual(DEFAULT_SETTINGS);
    });

    it('drops each invalid field (incl. disk-edited elevation settings), keeping the valid ones', () => {
      write({
        theme: 'dark',
        language: 'de',
        autoReconnect: 'yes',
        openconnectPath: '/bin/sh',
        hipScriptPath: 'relative/hip.sh',
        extraArgs: ['-v', '--script=/tmp/evil.sh'],
        lastProfileId: 'not-a-uuid',
        connectOnStartup: true,
        injected: 'x',
      });
      expect(open().get()).toEqual({ ...DEFAULT_SETTINGS, theme: 'dark', connectOnStartup: true });
      expect(warnings).toHaveLength(7);
      expect(warnings.join('\n')).toMatch(/Ignoring invalid setting "openconnectPath"/);
      expect(warnings.join('\n')).toMatch(/Ignoring invalid setting "extraArgs"/);
      expect(warnings.join('\n')).toMatch(/Ignoring invalid setting "injected"/);
    });

    it('keeps valid disk values for elevation settings (their confirmation is enforced elsewhere)', () => {
      write({ openconnectPath: '/opt/oc/bin/openconnect', extraArgs: ['--no-dtls'], hipScriptPath: '/opt/hip.sh' });
      expect(open().get()).toMatchObject({
        openconnectPath: '/opt/oc/bin/openconnect',
        extraArgs: ['--no-dtls'],
        hipScriptPath: '/opt/hip.sh',
      });
    });

    it('a "__proto__" key on disk does not pollute the settings object', () => {
      write('{"__proto__": {"autoReconnect": false, "polluted": true}, "theme": "light"}');
      const s = open().get();
      expect(s.theme).toBe('light');
      expect(s.autoReconnect).toBe(true);
      expect((s as unknown as Record<string, unknown>).polluted).toBeUndefined();
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });
});
