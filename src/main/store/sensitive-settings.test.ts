import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, type Settings } from '../../shared/ipc';
import { sensitiveChanges } from './sensitive-settings';

const current: Settings = { ...DEFAULT_SETTINGS, openconnectPath: '/usr/sbin/openconnect', extraArgs: ['-v'] };

describe('sensitiveChanges', () => {
  it('lists changed security-relevant settings with their new values', () => {
    expect(
      sensitiveChanges(current, {
        openconnectPath: '/usr/local/sbin/openconnect',
        hipScriptPath: '/usr/libexec/hipreport.sh',
        extraArgs: ['-v', '--no-dtls'],
        theme: 'dark',
      }),
    ).toEqual([
      { key: 'openconnectPath', value: '/usr/local/sbin/openconnect' },
      { key: 'hipScriptPath', value: '/usr/libexec/hipreport.sh' },
      { key: 'extraArgs', value: '-v --no-dtls' },
    ]);
  });

  it('shows cleared values', () => {
    expect(sensitiveChanges(current, { openconnectPath: undefined, extraArgs: [] })).toEqual([
      { key: 'openconnectPath', value: '(default)' },
      { key: 'extraArgs', value: '(none)' },
    ]);
  });

  it('ignores unchanged and non-sensitive settings', () => {
    expect(sensitiveChanges(current, { openconnectPath: '/usr/sbin/openconnect', extraArgs: ['-v'] })).toEqual([]);
    expect(sensitiveChanges(current, { theme: 'light', autoReconnect: false })).toEqual([]);
  });
});
