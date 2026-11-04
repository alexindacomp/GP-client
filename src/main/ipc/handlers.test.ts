import { describe, expect, it, vi } from 'vitest';
import { parseIpcError } from '../../shared/validation';
import { ValidationError } from '../store/validation';

vi.mock('electron', () => ({ ipcMain: { handle: vi.fn(), on: vi.fn() } }));
const { publicError } = await import('./handlers');

describe('publicError', () => {
  it('passes validation errors with their markers', () => {
    const e = publicError(new ValidationError('Bad', { field: 'extraArgs', code: 'not_allowed' }));
    expect(parseIpcError(e)).toEqual({ field: 'extraArgs', code: 'not_allowed', message: 'Bad' });
  });

  it.each([
    ['Profile not found', 'profileId', 'not_found'],
    ['Cannot connect while connected', undefined, 'busy'],
    ['Unknown or expired prompt', 'promptId', 'prompt_expired'],
    ['Answer must be a single line', 'answer', 'invalid'],
  ])('marks engine error %j', (msg, field, code) => {
    const info = parseIpcError(publicError(new Error(msg)));
    expect(info).toEqual({ ...(field ? { field } : {}), code, message: msg });
  });

  it('hides internal errors', () => {
    expect(parseIpcError(publicError(new Error('EACCES /home/alice/.config')))).toEqual({
      code: 'internal',
      message: 'Internal error, see the log for details',
    });
  });
});
