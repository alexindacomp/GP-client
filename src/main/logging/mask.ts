/**
 * Secret masking for log lines. Everything that reaches the log buffer, the log
 * file or the renderer goes through {@link maskSecrets}.
 */

export const MASK = '***';

/**
 * Secrets at least this long are masked wherever they occur (substring match).
 * Shorter secrets (1–3 chars, e.g. a PIN or a short password) are masked only as
 * whole tokens, otherwise every "a" or "12" inside other words/IPs would vanish.
 */
const MIN_SECRET_LENGTH = 4;

/**
 * Whole-token rule for short secrets: the value must be
 * - preceded by start of line, whitespace, a quote, `=`, `,`, `;`, `(`, `[` or `<`, and
 * - followed by end of line, whitespace, a quote, `,`, `;`, `)`, `]`, `>`, `&`, or sentence
 *   punctuation (`.`, `:`, `!`, `?`) that is itself followed by whitespace/end.
 * So "Login failed for abc." and "passwd=abc&x" are masked, but "abc" inside "abcdef",
 * "12" inside "10.0.12.1" or "a" inside "Login" are not.
 */
const TOKEN_BEFORE = String.raw`(^|[\s"'=,;(\[<])`;
const TOKEN_AFTER = String.raw`(?=$|[\s"',;)\]>&]|[.:!?](?:\s|$))`;

function maskShortToken(line: string, secret: string): string {
  const re = new RegExp(`${TOKEN_BEFORE}${escapeRegExp(secret)}${TOKEN_AFTER}`, 'g');
  return line.replace(re, (_m, pre: string) => `${pre}${MASK}`);
}

const SECRET_KEYS =
  'prelogin-cookie|portal-userauthcookie|portal-prelogonuserauthcookie|authcookie|' +
  'passwd|password|passcode|cookie|token|secret|samlresponse|saml-request|otp';

/** `<prelogin-cookie>value</prelogin-cookie>` */
const XML_TAG_RE = new RegExp(`<(${SECRET_KEYS})>([^<]*)</\\1>`, 'gi');
/** `Cookie: a=b; c=d`, `Set-Cookie: ...`, `Authorization: Bearer x` — mask the whole header value. */
const HEADER_RE = /\b(set-cookie|cookie|authorization|proxy-authorization)(\s*:\s*)(\S.*)$/gi;
/** `key=value`, `key: value`, `--cookie=value`, `COOKIE='value'` */
const KV_RE = new RegExp(`(^|[\\s&?;,"'(<-])(${SECRET_KEYS})(\\s*[=:]\\s*)('[^']*'|"[^"]*"|[^\\s&;,"'<>)]+)`, 'gi');

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function maskSecrets(line: string, knownSecrets: Iterable<string> = []): string {
  let out = line;

  const all = [...knownSecrets].filter((s) => typeof s === 'string' && s.length > 0);
  const secrets = all.filter((s) => s.length >= MIN_SECRET_LENGTH).sort((a, b) => b.length - a.length);
  for (const secret of secrets) {
    out = out.replace(new RegExp(escapeRegExp(secret), 'g'), MASK);
    // Cookies are often URL-encoded in HTTP traces.
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) out = out.replace(new RegExp(escapeRegExp(encoded), 'g'), MASK);
  }

  for (const secret of all.filter((s) => s.length < MIN_SECRET_LENGTH).sort((a, b) => b.length - a.length)) {
    out = maskShortToken(out, secret);
  }

  out = out.replace(XML_TAG_RE, (_m, tag: string) => `<${tag}>${MASK}</${tag}>`);
  out = out.replace(HEADER_RE, (_m, name: string, sep: string) => `${name}${sep}${MASK}`);
  out = out.replace(KV_RE, (m, pre: string, key: string, sep: string, value: string) => {
    // "Password:" prompt without a value, or a value that is already masked.
    if (value === MASK || value.length === 0) return m;
    return `${pre}${key}${sep}${MASK}`;
  });
  return out;
}

/** Registry of runtime secrets (passwords, cookies) to be masked by value. */
export class SecretRegistry {
  private readonly secrets = new Set<string>();

  add(secret: string | undefined | null): void {
    // Short secrets are kept too; maskSecrets masks them as whole tokens only.
    if (secret && secret.length > 0) this.secrets.add(secret);
  }

  delete(secret: string | undefined | null): void {
    if (secret) this.secrets.delete(secret);
  }

  values(): Iterable<string> {
    return this.secrets.values();
  }

  mask(line: string): string {
    return maskSecrets(line, this.secrets);
  }
}
