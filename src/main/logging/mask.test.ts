import { describe, expect, it } from 'vitest';
import { LogBuffer } from './log-buffer';
import { Logger } from './logger';
import { MASK, maskSecrets, SecretRegistry } from './mask';

describe('maskSecrets', () => {
  it.each([
    ['prelogin-cookie=abc123&user=x', `prelogin-cookie=${MASK}&user=x`],
    ['portal-userauthcookie: QWERTY', `portal-userauthcookie: ${MASK}`],
    ['POST body: user=bob&passwd=hunter2&ok=1', `POST body: user=bob&passwd=${MASK}&ok=1`],
    ['<prelogin-cookie>XYZ</prelogin-cookie>', `<prelogin-cookie>${MASK}</prelogin-cookie>`],
    ['Cookie: SESSION=1; other=2', `Cookie: ${MASK}`],
    ['Set-Cookie: a=b; HttpOnly', `Set-Cookie: ${MASK}`],
    ['Authorization: Bearer abc.def', `Authorization: ${MASK}`],
    ["COOKIE='authcookie=1&portal=2'", `COOKIE=${MASK}`],
    ['openconnect --cookie=secretvalue https://x', `openconnect --cookie=${MASK} https://x`],
  ])('%s', (input, expected) => {
    expect(maskSecrets(input)).toBe(expected);
  });

  it('keeps prompts and labels intact', () => {
    expect(maskSecrets('Password:')).toBe('Password:');
    expect(maskSecrets('<password-label>Password</password-label>')).toBe('<password-label>Password</password-label>');
    expect(maskSecrets('Connected as 10.0.0.1, using SSL')).toBe('Connected as 10.0.0.1, using SSL');
  });

  it('masks known secret values anywhere, including URL-encoded', () => {
    const secrets = ['s3cr3t+pass/word', 'COOKIEVALUE'];
    expect(maskSecrets('echo s3cr3t+pass/word and COOKIEVALUE', secrets)).toBe(`echo ${MASK} and ${MASK}`);
    expect(maskSecrets('q=s3cr3t%2Bpass%2Fword', secrets)).toBe(`q=${MASK}`);
  });

  it('does not mask very short values (false positives)', () => {
    expect(maskSecrets('abc', ['ab'])).toBe('abc');
  });
});

describe('SecretRegistry', () => {
  it('adds and removes secrets', () => {
    const r = new SecretRegistry();
    r.add('topsecret');
    expect(r.mask('x topsecret y')).toBe(`x ${MASK} y`);
    r.delete('topsecret');
    expect(r.mask('x topsecret y')).toBe('x topsecret y');
  });
});

describe('LogBuffer', () => {
  it('keeps only the last N lines', () => {
    const b = new LogBuffer(3);
    for (let i = 1; i <= 5; i++) b.push(`l${i}`);
    expect(b.snapshot()).toEqual(['l3', 'l4', 'l5']);
    expect(b.size).toBe(3);
  });

  it('rejects an invalid capacity', () => {
    expect(() => new LogBuffer(0)).toThrow(RangeError);
  });
});

describe('Logger', () => {
  it('masks registered secrets before buffering and notifying listeners', () => {
    const logger = new Logger(null, 10);
    const seen: string[] = [];
    logger.onLine((l) => seen.push(l));
    logger.secrets.add('MyP@ssw0rd');
    logger.info('test', 'sending MyP@ssw0rd\nprelogin-cookie=zzz');
    expect(logger.lines()).toHaveLength(2);
    expect(logger.lines().join('\n')).not.toContain('MyP@ssw0rd');
    expect(logger.lines().join('\n')).not.toContain('zzz');
    expect(seen).toEqual(logger.lines());
  });

  it('caps the buffer at the configured capacity (2000 by default)', () => {
    const logger = new Logger(null);
    for (let i = 0; i < 2100; i++) logger.info('t', `line ${i}`);
    expect(logger.lines()).toHaveLength(2000);
    expect(logger.lines()[0]).toContain('line 100');
  });
});

describe('short secrets (< 4 chars) are masked as whole tokens only (QA-3)', () => {
  it.each([
    ['Login failed for abc', 'Login failed for ***'],
    ['Login failed for abc.', 'Login failed for ***.'],
    ['user=bob&pin=12&x', 'user=bob&pin=***&x'],
    ['"abc" rejected', '"***" rejected'],
    ['abc abc', '*** ***'],
    ['(abc)', '(***)'],
  ])('%j → %j', (line, expected) => {
    const secrets = /12/.test(line) ? ['12'] : ['abc'];
    expect(maskSecrets(line, secrets)).toBe(expected);
  });

  it.each([
    ['abcdef', ['abc']],
    ['Connected as 10.0.12.1', ['12']],
    ['xabc', ['abc']],
    ['abc-def', ['abc']],
    ['Login failed', ['a']],
    ['https://abc.example.com/x', ['abc']],
  ])('does not mask inside other tokens: %j', (line, secrets) => {
    expect(maskSecrets(line, secrets)).toBe(line);
  });

  it('SecretRegistry accepts short secrets', () => {
    const r = new SecretRegistry();
    r.add('42');
    expect(r.mask('PIN 42 rejected')).toBe(`PIN ${MASK} rejected`);
  });
});
