import { describe, expect, it } from 'vitest';
import {
  appleScriptString,
  chooseElevation,
  privilegedKillCommand,
  quoteWindowsArg,
  shQuote,
  wrapCommand,
} from './elevation';

describe('chooseElevation', () => {
  it.each([
    [{ platform: 'linux', isRoot: false }, 'pkexec'],
    [{ platform: 'linux', isRoot: true }, 'none'],
    [{ platform: 'darwin', isRoot: false }, 'osascript'],
    [{ platform: 'win32', isRoot: false }, 'uac'],
  ] as const)('%j → %s', (ctx, method) => {
    expect(chooseElevation(ctx)).toBe(method);
  });
});

describe('wrapCommand', () => {
  it('prefixes pkexec without the textual agent', () => {
    expect(wrapCommand('pkexec', '/usr/sbin/openconnect', ['-v'])).toEqual({
      command: 'pkexec',
      args: ['--disable-internal-agent', '/usr/sbin/openconnect', '-v'],
    });
    expect(wrapCommand('none', '/x', ['a'])).toEqual({ command: '/x', args: ['a'] });
  });

  it('builds a privileged kill and validates the pid', () => {
    expect(privilegedKillCommand(4242, 'INT')).toEqual({
      command: 'pkexec',
      args: ['--disable-internal-agent', '/bin/kill', '-s', 'INT', '4242'],
    });
    expect(() => privilegedKillCommand(1, 'KILL')).toThrow(RangeError);
    expect(() => privilegedKillCommand(-5, 'KILL')).toThrow(RangeError);
  });
});

describe('quoting', () => {
  it('shQuote escapes single quotes', () => {
    expect(shQuote("it's")).toBe(`'it'\\''s'`);
  });

  it.each([
    ['simple', 'simple'],
    ['with space', '"with space"'],
    ['', '""'],
    ['say "hi"', '"say \\"hi\\""'],
    ['C:\\Program Files\\', '"C:\\Program Files\\\\"'],
  ])('quoteWindowsArg(%j) = %s', (input, expected) => {
    expect(quoteWindowsArg(input)).toBe(expected);
  });

  it('appleScriptString escapes backslashes and quotes', () => {
    expect(appleScriptString('a "b" \\c')).toBe('"a \\"b\\" \\\\c"');
  });
});
