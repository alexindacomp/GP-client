import { describe, expect, it } from 'vitest';
import { isPermissionAllowed } from './permissions';

const main = { id: 'main' };
const other = { id: 'other' };
const APP = 'file:///opt/gp/resources/app.asar/out/renderer/index.html';
const isAppUrl = (u: string): boolean => u === APP;

describe('isPermissionAllowed', () => {
  it('allows sanitized clipboard writes from the app page in the main window', () => {
    expect(
      isPermissionAllowed({
        permission: 'clipboard-sanitized-write',
        requester: main,
        trusted: main,
        requestingUrl: APP,
        isAppUrl,
      }),
    ).toBe(true);
  });

  it.each([
    ['other permission', { permission: 'clipboard-read' }],
    ['notifications', { permission: 'notifications' }],
    ['another webContents', { requester: other }],
    ['no webContents', { requester: null }],
    ['foreign page', { requestingUrl: 'https://evil.example.com/' }],
    ['unknown URL', { requestingUrl: undefined }],
    ['no trusted window', { trusted: null }],
  ])('denies %s', (_n, over) => {
    expect(
      isPermissionAllowed({
        permission: 'clipboard-sanitized-write',
        requester: main,
        trusted: main,
        requestingUrl: APP,
        isAppUrl,
        ...over,
      }),
    ).toBe(false);
  });
});
