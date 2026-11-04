import { describe, expect, it } from 'vitest';
import {
  validateConnectOptions,
  validateExternalUrl,
  validateProfileInput,
  validateSettingsPatch,
  ValidationError,
  notConfirmedError,
} from './validation';

const ID = '3f2b8c1e-4a5d-4e6f-8a9b-0c1d2e3f4a5b';

describe('validateProfileInput', () => {
  it('normalises the portal URL and trims fields', () => {
    expect(
      validateProfileInput({
        name: ' Work ',
        portalUrl: 'vpn.example.com',
        authMode: 'auto',
        savePassword: false,
        username: '  ',
      }),
    ).toEqual({ name: 'Work', portalUrl: 'https://vpn.example.com', authMode: 'auto', savePassword: false });
  });

  it.each([
    [{ name: 'x', portalUrl: 'http://vpn.example.com', authMode: 'auto', savePassword: false }],
    [{ name: '', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false }],
    [{ name: 'x', portalUrl: 'vpn.example.com', authMode: 'kerberos', savePassword: false }],
    [{ name: 'x', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: 'yes' }],
    [{ name: 'x', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false, id: '../etc' }],
    [{ name: 'x', portalUrl: 'vpn.example.com', authMode: 'auto', savePassword: false, admin: true }],
    [null],
  ])('rejects %j', (input) => {
    expect(() => validateProfileInput(input)).toThrow(ValidationError);
  });

  it('accepts a valid id', () => {
    expect(
      validateProfileInput({ id: ID, name: 'x', portalUrl: 'vpn.example.com', authMode: 'saml', savePassword: false })
        .id,
    ).toBe(ID);
  });
});

describe('validateSettingsPatch', () => {
  it('accepts openconnect binary paths only', () => {
    expect(validateSettingsPatch({ openconnectPath: '/usr/sbin/openconnect' }).openconnectPath).toBe(
      '/usr/sbin/openconnect',
    );
    expect(validateSettingsPatch({ openconnectPath: 'C:\\Program Files\\OC\\OpenConnect.exe' }).openconnectPath).toBe(
      'C:\\Program Files\\OC\\OpenConnect.exe',
    );
  });

  it('accepts a partial patch and clears optional strings', () => {
    expect(validateSettingsPatch({ theme: 'dark', openconnectPath: '', extraArgs: ['--no-dtls'] })).toEqual({
      theme: 'dark',
      openconnectPath: undefined,
      extraArgs: ['--no-dtls'],
    });
  });

  it.each([
    [{ theme: 'blue' }],
    [{ language: 'de' }],
    [{ autoReconnect: 1 }],
    [{ openconnectPath: 'openconnect' }],
    [{ openconnectPath: '/usr/bin/python3' }],
    [{ openconnectPath: 'C:\\Windows\\System32\\cmd.exe' }],
    [{ extraArgs: ['--user=root'] }],
    [{ extraArgs: ['--script=/tmp/x'] }],
    [{ unknown: true }],
    [[]],
  ])('rejects %j', (patch) => {
    expect(() => validateSettingsPatch(patch)).toThrow(ValidationError);
  });
});

describe('validateConnectOptions', () => {
  it('accepts undefined and valid options', () => {
    expect(validateConnectOptions(undefined)).toEqual({});
    expect(validateConnectOptions({ gateway: 'Europe', password: 'pw' })).toEqual({
      gateway: 'Europe',
      password: 'pw',
    });
  });

  it('rejects multi-line passwords (stdin injection)', () => {
    expect(() => validateConnectOptions({ password: 'a\nb' })).toThrow(ValidationError);
  });
});

describe('validateExternalUrl', () => {
  it('allows https only', () => {
    expect(validateExternalUrl('https://example.com/docs')).toBe('https://example.com/docs');
    expect(() => validateExternalUrl('file:///etc/passwd')).toThrow(ValidationError);
    expect(() => validateExternalUrl('javascript:alert(1)')).toThrow(ValidationError);
  });
});

describe('machine-readable error markers (CR-8)', () => {
  it.each([
    [() => validateSettingsPatch({ extraArgs: ['--script=/x'] }), '[field:extraArgs][code:not_allowed] '],
    [() => validateSettingsPatch({ extraArgs: ['--mtu=1'] }), '[field:extraArgs][code:bad_value] '],
    [
      () => validateSettingsPatch({ openconnectPath: '/usr/bin/python3' }),
      '[field:openconnectPath][code:not_openconnect] ',
    ],
    [() => validateSettingsPatch({ hipScriptPath: 'hip.sh' }), '[field:hipScriptPath][code:not_absolute] '],
    [
      () =>
        validateProfileInput({ name: 'x', portalUrl: 'http://v.example.com', authMode: 'auto', savePassword: false }),
      '[field:portalUrl][code:not_https] ',
    ],
    [
      () => validateProfileInput({ name: '', portalUrl: 'v.example.com', authMode: 'auto', savePassword: false }),
      '[field:name][code:required] ',
    ],
    [() => validateSettingsPatch({ bogus: 1 }), '[field:bogus][code:unknown_field] '],
  ])('%#', (fn, prefix) => {
    expect(fn).toThrow(ValidationError);
    try {
      fn();
    } catch (e) {
      expect((e as Error).message.startsWith(prefix)).toBe(true);
    }
  });

  it('marks the not-confirmed rejection', () => {
    expect(notConfirmedError().message).toBe('[code:not_confirmed] The change was not confirmed');
  });
});

describe('language (A1)', () => {
  it.each(['ru', 'en', 'uk'])('accepts %s', (language) => {
    expect(validateSettingsPatch({ language })).toEqual({ language });
  });
  it('rejects others', () => {
    expect(() => validateSettingsPatch({ language: 'de' })).toThrow(ValidationError);
  });
});
