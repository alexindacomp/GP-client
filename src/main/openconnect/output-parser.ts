/**
 * Parsing of openconnect stdout/stderr. Pure and stateful only where the output
 * format requires it (gateway list), so it can be unit-tested on fixtures.
 */
import type { Gateway, VpnErrorCode } from '../../shared/ipc';

export type OcEvent =
  | { type: 'connected'; ip: string }
  | { type: 'esp' }
  | { type: 'authenticated' }
  | { type: 'gateway-list'; count: number }
  | { type: 'gateway'; gateway: Gateway }
  | { type: 'auth-failed'; message: string }
  | { type: 'error'; code: VpnErrorCode; message: string }
  | { type: 'session-lost'; message: string };

export type OcPrompt =
  | { kind: 'select'; label: string; options: string[] }
  | { kind: 'secret'; label: string }
  | { kind: 'text'; label: string }
  | { kind: 'cert-confirm' };

const CONNECTED_RE = /^(?:Connected|Configured) as ([0-9a-fA-F.:]+?)(?:,|\s|$)/;
const ESP_RE = /ESP session established with server/i;
const AUTHENTICATED_RE =
  /GlobalProtect login returned|Tunnel timeout \(rekey interval\)|Gateway address in config XML|Got CONNECT response: HTTP\/1\.[01] 200/i;
const GATEWAY_HEADER_RE = /^(\d+) gateway servers? available:?\s*$/i;
const GATEWAY_ENTRY_RE = /^\s+(.+?)\s+\(([^()\s]+)\)(?:\s*\[(\d+(?:\.\d+)?)\])?\s*$/;

const AUTH_FAILED_RE =
  /Login failed|Invalid username or password|Authentication failed|Unexpected 512 result|auth(?:entication)? error|Invalid (?:user ?name|password|credentials)|password (?:is )?(?:incorrect|expired)/i;
const SESSION_LOST_RE =
  /Session terminated by server|Server terminated connection|Unrecoverable I\/O error; exiting|Reconnect failed|Session (?:has )?expired|Cookie was rejected by server/i;
const PRIVILEGES_RE =
  /Operation not permitted|Permission denied|Access is denied|Not authorized|Request dismissed|a password is required|must be run as root|administrator privileges|User canceled|\(-128\)/i;
const TUNNEL_RE =
  /Failed to (?:bind|open|set up|create|configure)[^.]*\b(?:tun|tap|wintun|adapter|device)\b|Set up tun(?: device)? failed|Script '.*' returned error|vpnc-script.*(?:error|failed)|(?:Could not|Cannot|Unable to) (?:open|create|load) (?:the )?Wintun|No tun device/i;
const TLS_RE =
  /certificate verify failed|failed verification|SSL connection failure|handshake failed|GnuTLS error|TLS (?:connection|handshake) (?:failed|error)|certificate (?:has )?expired|self[- ]signed certificate/i;
const DNS_RE =
  /getaddrinfo failed for host|Name or service not known|Temporary failure in name resolution|No such host is known|nodename nor servname/i;
const UNREACHABLE_RE =
  /Failed to connect to host|Failed to open HTTPS connection|Connection refused|No route to host|Network is unreachable|Connection timed out|Failed to connect to .*:\d+/i;
const BAD_OPTION_RE = /unrecognized option|invalid option|Unknown VPN protocol|option .* requires an argument/i;

export function parseLine(line: string): OcEvent | null {
  const text = line.trim();
  if (text === '') return null;

  const connected = CONNECTED_RE.exec(text);
  if (connected?.[1] && connected[1].length >= 2) return { type: 'connected', ip: connected[1] };
  if (ESP_RE.test(text)) return { type: 'esp' };
  if (AUTHENTICATED_RE.test(text)) return { type: 'authenticated' };
  // Order matters: a tun "Operation not permitted" is a privilege problem.
  if (
    PRIVILEGES_RE.test(text) &&
    /tun|tap|wintun|adapter|device|route|pkexec|sudo|executing command|privilege|administrator|cancel|-128|authoriz|password is required|root/i.test(
      text,
    )
  ) {
    return { type: 'error', code: 'PRIVILEGES_DENIED', message: text };
  }
  if (TUNNEL_RE.test(text)) return { type: 'error', code: 'TUNNEL_FAILED', message: text };
  if (TLS_RE.test(text)) return { type: 'error', code: 'TLS_ERROR', message: text };
  if (AUTH_FAILED_RE.test(text)) return { type: 'auth-failed', message: text };
  if (SESSION_LOST_RE.test(text)) return { type: 'session-lost', message: text };
  if (DNS_RE.test(text) || UNREACHABLE_RE.test(text)) {
    return { type: 'error', code: 'PORTAL_UNREACHABLE', message: text };
  }
  if (BAD_OPTION_RE.test(text)) return { type: 'error', code: 'UNKNOWN', message: text };
  return null;
}

/** Stateful wrapper: understands the multi-line gateway list. */
export class OutputParser {
  private gatewaysExpected = 0;

  parse(line: string): OcEvent | null {
    if (this.gatewaysExpected > 0) {
      const entry = GATEWAY_ENTRY_RE.exec(line);
      if (entry?.[1] && entry[2]) {
        this.gatewaysExpected--;
        const gateway: Gateway = { name: entry[1].trim(), address: entry[2] };
        if (entry[3] !== undefined) gateway.priority = Number(entry[3]);
        return { type: 'gateway', gateway };
      }
      this.gatewaysExpected = 0;
    }
    const header = GATEWAY_HEADER_RE.exec(line.trim());
    if (header?.[1]) {
      const count = Number(header[1]);
      this.gatewaysExpected = count;
      return { type: 'gateway-list', count };
    }
    return parseLine(line);
  }
}

const CERT_PROMPT_RE = /Enter 'yes' to accept, 'no' to abort; anything else to view:\s*$/i;
const SELECT_PROMPT_RE = /^(.*?)\s*\[([^\]]+)\]:\s*$/;
const SECRET_LABEL_RE =
  /pass(?:word|code|wd)?|challenge|token|otp|one[- ]time|\bpin\b|\bcode\b|response|verification|secret/i;
const GENERIC_PROMPT_RE = /^([^\n]{1,200}?):\s*$/;

/**
 * Recognises an interactive prompt in a trailing, newline-less fragment of
 * openconnect output (openconnect prints `Label:` without a newline and waits
 * for stdin).
 */
export function parsePrompt(fragment: string): OcPrompt | null {
  const text = fragment.replace(/\r/g, '').split('\n').pop()?.trim() ?? '';
  if (text === '') return null;
  if (CERT_PROMPT_RE.test(text)) return { kind: 'cert-confirm' };

  const select = SELECT_PROMPT_RE.exec(text);
  if (select && select[2] !== undefined) {
    const options = select[2]
      .split('|')
      .map((o) => o.trim())
      .filter((o) => o !== '');
    if (options.length > 0) {
      return { kind: 'select', label: (select[1] ?? '').replace(/:\s*$/, '').trim(), options };
    }
  }
  const generic = GENERIC_PROMPT_RE.exec(text);
  if (!generic?.[1]) return null;
  const label = generic[1].trim();
  // Timestamps/addresses like "10:20" are not prompts; require a word-ish label.
  if (!/[A-Za-zЀ-ӿ]/.test(label)) return null;
  return SECRET_LABEL_RE.test(label) ? { kind: 'secret', label } : { kind: 'text', label };
}

/** Splits a byte stream into lines while remembering the trailing fragment. */
export class LineSplitter {
  private pending = '';

  push(chunk: string): string[] {
    const data = this.pending + chunk;
    const parts = data.split(/\r\n|\n|\r/);
    this.pending = parts.pop() ?? '';
    return parts;
  }

  /** The current newline-less tail (e.g. an interactive prompt). */
  get partial(): string {
    return this.pending;
  }

  /** Returns and clears the tail. */
  takePartial(): string {
    const p = this.pending;
    this.pending = '';
    return p;
  }

  /** Remaining text at end of stream. */
  flush(): string[] {
    const p = this.takePartial();
    return p === '' ? [] : [p];
  }
}
