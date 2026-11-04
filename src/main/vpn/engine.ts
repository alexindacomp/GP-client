import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type {
  AuthPrompt,
  ConnectOptions,
  Gateway,
  Profile,
  Settings,
  VpnErrorCode,
  VpnState,
  VpnStatus,
} from '../../shared/ipc';
import type { PreloginResult } from '../auth/prelogin';
import type { SamlSuccess } from '../auth/saml-extract';
import { buildOpenconnectArgs, type OpenconnectAuth } from '../openconnect/args';
import { LineSplitter, OutputParser, parsePrompt, type OcPrompt } from '../openconnect/output-parser';
import type { ExitInfo, ProcessSpawner, VpnProcess } from '../process/types';
import { backoffDelay, DEFAULT_BACKOFF_MS } from './backoff';
import { errorCodeOf, VpnError } from './errors';
import { errorDetail, errorMessage, promptLabel, stopFailedMessage, type ErrorHint } from './messages';

export interface EngineLogger {
  info(source: string, msg: string): void;
  warn(source: string, msg: string): void;
  error(source: string, msg: string, err?: unknown): void;
  readonly secrets: {
    add(secret: string | undefined | null): void;
    delete(secret: string | undefined | null): void;
    mask(line: string): string;
  };
}

export interface EngineDeps {
  platform: NodeJS.Platform;
  getProfile(id: string): Profile | undefined;
  getSavedPassword(profileId: string): string | undefined;
  getSettings(): Settings;
  prelogin(portalUrl: string, signal: AbortSignal): Promise<PreloginResult>;
  samlLogin(profile: Profile, prelogin: PreloginResult, signal: AbortSignal): Promise<SamlSuccess>;
  /** Absolute path of the openconnect binary, or `null` when not installed. */
  locateOpenconnect(): Promise<string | null>;
  /**
   * Verifies that the files that will run elevated (binary, HIP wrapper) are
   * admin-controlled and returns their real paths. Must throw a VpnError
   * (PRIVILEGES_DENIED) otherwise. Called right before every spawn.
   */
  verifyElevatedFiles(files: { binary: string; hipScriptPath?: string }): Promise<{
    binary: string;
    hipScriptPath?: string;
  }>;
  spawner: ProcessSpawner;
  logger: EngineLogger;
  now?: () => number;
  newId?: () => string;
  /** Time to wait for a graceful stop before killing. */
  stopTimeoutMs?: number;
  /** How long a newline-less fragment must be stable before it is treated as a prompt. */
  promptDebounceMs?: number;
  backoffMs?: readonly number[];
  maxReconnectAttempts?: number;
}

interface VpnErrorInfo {
  code: VpnErrorCode;
  /** Technical cause → `VpnState.error.detail`. */
  detail?: string;
  /** Cause-specific next step overriding the per-code message. */
  hint?: ErrorHint;
}

interface Attempt {
  readonly profile: Profile;
  readonly opts: ConnectOptions;
  readonly isReconnect: boolean;
  readonly abort: AbortController;
  readonly parser: OutputParser;
  readonly splitters: { stdout: LineSplitter; stderr: LineSplitter };
  readonly promptTimers: { stdout?: NodeJS.Timeout; stderr?: NodeJS.Timeout };
  readonly secrets: string[];
  readonly promptIds: Set<string>;
  proc?: VpnProcess;
  username?: string;
  requestedGateway?: string;
  selectedGateway?: string;
  gateways: Gateway[];
  pendingError?: VpnErrorInfo;
  authFailed: boolean;
  everConnected: boolean;
  userStopping: boolean;
  /** Error to report when the attempt ends because of a local decision (cancel, auth loop, cert). */
  forcedError?: VpnErrorInfo;
  lastMessage?: string;
  exitPromise?: Promise<void>;
  /** In-flight stop (graceful → kill); shared by repeated Disconnect clicks. */
  stopPromise?: Promise<void>;
  /** Status to restore if openconnect cannot be stopped. */
  statusBeforeStop?: VpnStatus;
  /** `spawner.spawn()` is in flight (e.g. the UAC/admin dialog is open). */
  spawning?: boolean;
  /** Counted in {@link VpnEngine.pendingDisposals} until the late process is gone. */
  disposalCounted?: boolean;
}

/**
 * Maps a select answer (as shown to the renderer, possibly masked) back to the raw
 * option. If several raw options were shown identically, the answer is ambiguous
 * and an empty string is returned, which no option equals → the caller rejects it.
 */
export function unmaskOption(answer: string, rawByShown: ReadonlyMap<string, string[]>): string {
  const raws = rawByShown.get(answer);
  if (!raws) return answer;
  const unique = [...new Set(raws)];
  return unique.length === 1 ? unique[0]! : '';
}

type StateError = NonNullable<VpnState['error']>;

/** Thrown inside an attempt that was superseded or cancelled; never surfaces. */
class StaleAttempt extends Error {}

/** Error codes that make retrying pointless. */
const NON_RETRYABLE: ReadonlySet<VpnErrorCode> = new Set<VpnErrorCode>([
  'OPENCONNECT_NOT_FOUND',
  'AUTH_FAILED',
  'AUTH_CANCELLED',
  'PRIVILEGES_DENIED',
  'TLS_ERROR',
]);

/** When several errors are seen in the output, the most specific wins. */
const ERROR_PRIORITY: readonly VpnErrorCode[] = [
  'PRIVILEGES_DENIED',
  'AUTH_FAILED',
  'TLS_ERROR',
  'TUNNEL_FAILED',
  'PORTAL_UNREACHABLE',
  'UNKNOWN',
];

const MAX_ANSWER_LENGTH = 4096;
const GATEWAY_LABEL_RE = /gateway/i;
const OTP_RE = /otp|one[- ]time|token|passcode|\bcode\b|challenge|verification|mfa|2fa|authenticator|\bpin\b/i;

type EngineEvents = {
  state: [VpnState];
  prompt: [AuthPrompt];
};

/**
 * VPN connection state machine. Owns at most one openconnect process.
 *
 * disconnected → prelogin → authenticating → connecting → connected → disconnecting → disconnected
 * plus `error` (terminal until the next connect) and `reconnecting` (auto-reconnect with backoff).
 */
export class VpnEngine {
  private readonly emitter = new EventEmitter<EngineEvents>();
  private state: VpnState = { status: 'disconnected' };
  private attempt: Attempt | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  /**
   * Attempts abandoned by Disconnect while their process was still starting. Until
   * the late process is disposed (or re-adopted), a new connect is refused so it
   * can never become an untracked second openconnect.
   */
  private pendingDisposals = 0;
  private reconnectCount = 0;
  /** Password entered for the current session; kept in memory only so auto-reconnect does not re-ask. */
  private sessionPassword: { profileId: string; value: string } | null = null;
  private readonly prompts = new Map<string, (value: string | null) => void>();
  private readonly pendingPrompts = new Map<string, AuthPrompt>();
  private readonly knownGateways = new Map<string, Gateway[]>();
  /**
   * profileId → (value as shown to the renderer → raw gateway names/addresses).
   * Recorded when masked gateways are emitted, so a masked value sent back by the
   * renderer (e.g. "***-GW") can be translated even after the secret that caused
   * the masking has left the registry.
   */
  private readonly gatewayAliases = new Map<string, Map<string, Set<string>>>();

  private readonly now: () => number;
  private readonly newId: () => string;
  private readonly stopTimeoutMs: number;
  private readonly promptDebounceMs: number;
  private readonly backoffMs: readonly number[];
  private readonly maxReconnectAttempts: number;

  constructor(private readonly deps: EngineDeps) {
    this.now = deps.now ?? Date.now;
    this.newId = deps.newId ?? randomUUID;
    this.stopTimeoutMs = deps.stopTimeoutMs ?? 10_000;
    this.promptDebounceMs = deps.promptDebounceMs ?? 150;
    this.backoffMs = deps.backoffMs ?? DEFAULT_BACKOFF_MS;
    this.maxReconnectAttempts = deps.maxReconnectAttempts ?? 10;
  }

  getState(): VpnState {
    return structuredClone(this.state);
  }

  /**
   * Re-renders `state.error.message` in the current settings language (after a
   * language change) and re-emits the state. Code, hint and detail are kept.
   */
  relocalize(): void {
    // Only the error is re-rendered: prompts already shown keep their language until the next prompt.
    const err = this.state.error;
    if (!err) return;
    const message = errorMessage(err.code, this.deps.getSettings().language, err.hint, this.deps.platform);
    if (message === err.message) return;
    this.setState({ ...this.state, error: { ...err, message } });
  }

  /** Prompts that are waiting for an answer (re-sent to a reloaded renderer). */
  getPendingPrompts(): AuthPrompt[] {
    return [...this.pendingPrompts.values()].map((p) => structuredClone(p));
  }

  onState(cb: (s: VpnState) => void): () => void {
    this.emitter.on('state', cb);
    return () => this.emitter.off('state', cb);
  }

  onPrompt(cb: (p: AuthPrompt) => void): () => void {
    this.emitter.on('prompt', cb);
    return () => this.emitter.off('prompt', cb);
  }

  /**
   * Starts a connection attempt and returns once it has been started. Progress and
   * failures are reported through state changes. Rejects only for invalid requests.
   */
  connect(profileId: string, opts: ConnectOptions = {}): Promise<void> {
    const profile = this.deps.getProfile(profileId);
    if (!profile) return Promise.reject(new Error('Profile not found'));
    if (this.state.status !== 'disconnected' && this.state.status !== 'error') {
      return Promise.reject(new Error(`Cannot connect while ${this.state.status}`));
    }
    if (this.attempt || this.pendingDisposals > 0) {
      // An openconnect that could not be stopped is still owned by the engine, or
      // one that was starting during Disconnect has not been disposed yet.
      return Promise.reject(new Error('Cannot connect while openconnect is still running'));
    }
    this.reconnectCount = 0;
    if (this.sessionPassword?.profileId !== profileId) this.clearSessionPassword();
    this.startAttempt(profile, opts, false);
    return Promise.resolve();
  }

  /**
   * Stops the current connection/attempt and resolves when the engine is
   * `disconnected` (or when stopping failed, see {@link stopProcess}).
   * Idempotent: repeated calls while a stop is in flight share it.
   */
  async disconnect(): Promise<void> {
    this.cancelReconnectTimer();
    const att = this.attempt;
    if (!att) {
      this.clearSessionPassword();
      if (this.state.status !== 'disconnected') this.setIdle('disconnected');
      return;
    }
    // Mark the stop as user-initiated before joining an in-flight (forced) stop,
    // so the process exit ends in `disconnected` instead of an auto-reconnect.
    att.userStopping = true;
    att.abort.abort();
    this.cancelPrompts(att);
    this.clearSessionPassword();
    if (att.stopPromise) {
      if (this.state.status !== 'disconnecting') {
        const { error: _err, ...current } = this.state;
        this.setState({ ...current, status: 'disconnecting' });
      }
      return att.stopPromise;
    }

    const proc = att.proc;
    if (!proc) {
      // Still in prelogin/SAML/spawn: the attempt will notice it is stale.
      if (att.spawning && !att.disposalCounted) {
        att.disposalCounted = true;
        this.pendingDisposals++;
      }
      this.finishAttempt(att);
      this.setIdle('disconnected', att.profile.id);
      return;
    }
    att.statusBeforeStop = this.state.status;
    const { error: _previousError, ...rest } = this.state;
    this.setState({ ...rest, status: 'disconnecting' });
    this.deps.logger.info('vpn', 'Disconnecting…');
    await this.runStop(att, proc);
  }

  private runStop(att: Attempt, proc: VpnProcess): Promise<void> {
    if (!att.stopPromise) {
      att.stopPromise = this.stopProcess(att, proc).finally(() => {
        att.stopPromise = undefined;
      });
    }
    return att.stopPromise;
  }

  answerPrompt(id: string, value: string | null): Promise<void> {
    const resolve = this.prompts.get(id);
    if (!resolve) return Promise.reject(new Error('Unknown or expired prompt'));
    if (value !== null) {
      if (typeof value !== 'string' || value.length > MAX_ANSWER_LENGTH) {
        return Promise.reject(new Error('Invalid answer'));
      }
      if (/[\r\n\0]/.test(value)) return Promise.reject(new Error('Answer must be a single line'));
    }
    resolve(value);
    return Promise.resolve();
  }

  /** Called on app quit: stop openconnect without waiting for state updates. */
  async shutdown(): Promise<void> {
    await this.disconnect().catch(() => undefined);
  }

  // ---------------------------------------------------------------- attempts

  private startAttempt(profile: Profile, opts: ConnectOptions, isReconnect: boolean): void {
    const att: Attempt = {
      profile,
      opts,
      isReconnect,
      abort: new AbortController(),
      parser: new OutputParser(),
      splitters: { stdout: new LineSplitter(), stderr: new LineSplitter() },
      promptTimers: {},
      secrets: [],
      promptIds: new Set(),
      gateways: this.knownGateways.get(profile.id) ?? [],
      authFailed: false,
      everConnected: false,
      userStopping: false,
    };
    this.attempt = att;
    this.runAttempt(att).catch((err: unknown) => this.onAttemptError(att, err));
  }

  private assertCurrent(att: Attempt): void {
    if (this.attempt !== att || att.abort.signal.aborted) throw new StaleAttempt();
  }

  private phase(att: Attempt, status: VpnStatus): void {
    this.setState({
      status: att.isReconnect ? 'reconnecting' : status,
      profileId: att.profile.id,
      gateways: att.gateways.length ? att.gateways : undefined,
    });
  }

  private async runAttempt(att: Attempt): Promise<void> {
    const { profile } = att;
    const settings = this.deps.getSettings();
    const log = this.deps.logger;
    this.phase(att, 'prelogin');
    log.info('vpn', `${att.isReconnect ? 'Reconnecting' : 'Connecting'} to "${profile.name}" (${profile.portalUrl})`);

    const binary = await this.deps.locateOpenconnect();
    this.assertCurrent(att);
    if (!binary) throw new VpnError('OPENCONNECT_NOT_FOUND', 'openconnect binary not found');
    // Fail fast (before prelogin/SAML) on an untrusted binary or HIP script;
    // the check is repeated right before spawning.
    await this.deps.verifyElevatedFiles({ binary, hipScriptPath: settings.hipScriptPath });
    this.assertCurrent(att);

    let prelogin: PreloginResult | undefined;
    if (profile.authMode !== 'password') {
      prelogin = await this.deps.prelogin(profile.portalUrl, att.abort.signal);
      this.assertCurrent(att);
      log.info('vpn', `Prelogin: ${prelogin.authType === 'saml' ? `SAML (${prelogin.samlMethod})` : 'password'}`);
      if (profile.authMode === 'saml' && prelogin.authType !== 'saml') {
        throw new VpnError('AUTH_FAILED', 'The portal does not offer SAML authentication');
      }
    }

    let auth: OpenconnectAuth;
    let secret: string;
    let username = profile.username;
    this.phase(att, 'authenticating');
    if (prelogin?.authType === 'saml') {
      const saml = await this.deps.samlLogin(profile, prelogin, att.abort.signal);
      this.assertCurrent(att);
      auth = { kind: 'saml', cookieName: saml.cookieName };
      secret = saml.cookie;
      username = saml.username;
    } else {
      auth = { kind: 'password' };
      if (!username) {
        const answer = await this.ask(att, {
          kind: 'text',
          message: prelogin?.usernameLabel ?? promptLabel('username', settings.language),
        });
        if (answer === null || answer.trim() === '') throw new VpnError('AUTH_CANCELLED', 'Username not provided');
        username = answer.trim();
      }
      let password =
        att.opts.password ??
        this.deps.getSavedPassword(profile.id) ??
        (this.sessionPassword?.profileId === profile.id ? this.sessionPassword.value : undefined);
      if (!password) {
        const message = [prelogin?.authMessage, prelogin?.passwordLabel ?? promptLabel('password', settings.language)]
          .filter(Boolean)
          .join('\n');
        const answer = await this.ask(att, { kind: 'password', message });
        if (answer === null) throw new VpnError('AUTH_CANCELLED', 'Password not provided');
        password = answer;
      }
      secret = password;
      this.sessionPassword = { profileId: profile.id, value: password };
    }
    this.addSecret(att, secret);
    att.username = username;
    att.requestedGateway = this.unmaskGateway(profile.id, att.opts.gateway) ?? profile.preferredGateway;

    // Settings are re-read and re-validated right before the elevated spawn.
    const current = this.deps.getSettings();
    const trusted = await this.deps.verifyElevatedFiles({ binary, hipScriptPath: current.hipScriptPath });
    this.assertCurrent(att);
    const args = buildOpenconnectArgs({
      portalUrl: profile.portalUrl,
      platform: this.deps.platform,
      username,
      auth,
      gateway: att.requestedGateway,
      hipScriptPath: trusted.hipScriptPath,
      extraArgs: current.extraArgs,
    });
    log.info('vpn', `Running ${trusted.binary} ${args.join(' ')}`);

    let proc: VpnProcess;
    att.spawning = true;
    try {
      proc = await this.deps.spawner.spawn({ binary: trusted.binary, args });
    } catch (err) {
      this.releaseDisposal(att);
      throw err;
    } finally {
      att.spawning = false;
    }
    if (this.attempt !== att || att.abort.signal.aborted) {
      // Disconnected while the process was starting (e.g. during the UAC prompt).
      try {
        await this.disposeLateProcess(att, proc);
      } finally {
        this.releaseDisposal(att);
      }
      throw new StaleAttempt();
    }
    this.attachProcess(att, proc);
    proc.write(`${secret}\n`);
  }

  private releaseDisposal(att: Attempt): void {
    if (!att.disposalCounted) return;
    att.disposalCounted = false;
    this.pendingDisposals--;
  }

  private attachProcess(att: Attempt, proc: VpnProcess): void {
    att.proc = proc;
    att.exitPromise = new Promise<void>((resolve) => {
      proc.onExit((info) => {
        this.onProcessExit(att, info);
        resolve();
      });
    });
    proc.onStdout((chunk) => this.onOutput(att, 'stdout', chunk));
    proc.onStderr((chunk) => this.onOutput(att, 'stderr', chunk));
  }

  /**
   * A process that finished starting after the user disconnected must go away.
   * If it cannot be killed (e.g. the admin dialog for `pkexec kill` was
   * dismissed), the engine re-adopts it so the user sees it and can retry.
   */
  private async disposeLateProcess(att: Attempt, proc: VpnProcess): Promise<void> {
    const log = this.deps.logger;
    const exited = new Promise<void>((resolve) => proc.onExit(() => resolve()));
    try {
      await proc.kill();
    } catch (err) {
      log.error('vpn', 'Failed to kill openconnect that started after disconnect', err);
    }
    if (await this.waitFor(exited, 3_000)) return;
    log.error('vpn', 'openconnect that started after disconnect is still running');
    // connect() is refused while this disposal is pending, so normally nobody else
    // owns the engine now; keep ownership of the process so Disconnect can retry.
    if (this.attempt !== null) {
      log.error('vpn', 'Cannot track the late openconnect: another attempt is active');
      return;
    }
    att.userStopping = true;
    att.statusBeforeStop = 'authenticating';
    this.attempt = att;
    this.attachProcess(att, proc);
    this.setState({
      status: 'authenticating',
      profileId: att.profile.id,
      gateways: att.gateways.length ? att.gateways : undefined,
      error: this.stopFailedError(),
    });
  }

  private onAttemptError(att: Attempt, err: unknown): void {
    if (err instanceof StaleAttempt || this.attempt !== att || att.userStopping) return;
    const code = errorCodeOf(err);
    const detail = err instanceof Error ? err.message : String(err);
    const hint = err instanceof VpnError ? err.hint : undefined;
    this.deps.logger.error('vpn', `Connection attempt failed [${code}]`, detail);
    if (att.proc) {
      // The process is running but we gave up on it: make sure it goes away.
      att.forcedError = { code, detail, hint };
      att.statusBeforeStop = this.state.status;
      void this.runStop(att, att.proc);
      return;
    }
    this.finishAttempt(att);
    const error: VpnErrorInfo = { code, detail, hint };
    // A reconnect attempt that fails before spawning (network still down,
    // prelogin unreachable, …) keeps backing off like a failed process would.
    if (att.isReconnect && this.shouldReconnect(att, error)) this.scheduleReconnect(att, error);
    else this.endWithError(att, error);
  }

  // ---------------------------------------------------------------- process output

  private onOutput(att: Attempt, stream: 'stdout' | 'stderr', chunk: string): void {
    const splitter = att.splitters[stream];
    for (const line of splitter.push(chunk)) this.onLine(att, line);

    const timer = att.promptTimers[stream];
    if (timer) clearTimeout(timer);
    att.promptTimers[stream] = undefined;
    if (splitter.partial.trim() !== '') {
      att.promptTimers[stream] = setTimeout(() => {
        att.promptTimers[stream] = undefined;
        this.checkPartial(att, stream);
      }, this.promptDebounceMs);
    }
  }

  private onLine(att: Attempt, rawLine: string): void {
    if (rawLine.trim() === '') return;
    // Classification runs on the RAW line (masking a short secret such as "a" must
    // not change "sudo: a password is required"). Everything that leaves the parser
    // — log, lastMessage, error details, state — is masked.
    const mask = (t: string): string => this.deps.logger.secrets.mask(t);
    const line = mask(rawLine);
    this.deps.logger.info('openconnect', line);
    if (this.attempt !== att) return;
    const ev = att.parser.parse(rawLine);
    if (!ev) {
      att.lastMessage = line.trim();
      return;
    }
    switch (ev.type) {
      case 'authenticated':
        if (this.state.status === 'authenticating') this.phase(att, 'connecting');
        break;
      case 'gateway-list':
        att.gateways = [];
        break;
      case 'gateway':
        att.gateways = [...att.gateways, ev.gateway];
        this.knownGateways.set(att.profile.id, att.gateways);
        this.setState({ ...this.state, gateways: att.gateways });
        break;
      case 'connected':
        att.everConnected = true;
        att.pendingError = undefined;
        this.reconnectCount = 0;
        this.setState({
          status: 'connected',
          profileId: att.profile.id,
          assignedIp: ev.ip,
          connectedAt: this.now(),
          gateway: this.currentGateway(att),
          gateways: att.gateways.length ? att.gateways : undefined,
        });
        this.deps.logger.info('vpn', `Connected, assigned IP ${mask(ev.ip)}`);
        break;
      case 'esp':
        att.pendingError = undefined;
        break;
      case 'auth-failed':
        att.authFailed = true;
        this.recordError(att, { code: 'AUTH_FAILED', detail: mask(ev.message) });
        break;
      case 'error':
        this.recordError(att, { code: ev.code, detail: mask(ev.message) });
        break;
      case 'session-lost':
        att.lastMessage = mask(ev.message);
        break;
    }
  }

  private recordError(att: Attempt, err: VpnErrorInfo): void {
    const cur = att.pendingError;
    // Replace only on a strictly more specific code: within one code the first line
    // is the root cause ("getaddrinfo failed …", "Invalid username or password");
    // later lines of the same code are generic follow-ups ("Failed to open HTTPS
    // connection", "Login failed.").
    if (!cur || ERROR_PRIORITY.indexOf(err.code) < ERROR_PRIORITY.indexOf(cur.code)) att.pendingError = err;
  }

  private checkPartial(att: Attempt, stream: 'stdout' | 'stderr'): void {
    if (this.attempt !== att || !att.proc) return;
    const splitter = att.splitters[stream];
    const prompt = parsePrompt(splitter.partial);
    if (!prompt) return;
    const fragment = splitter.takePartial().trim();
    this.deps.logger.info('openconnect', this.deps.logger.secrets.mask(fragment));
    void this.handlePrompt(att, prompt).catch((err: unknown) => this.onAttemptError(att, err));
  }

  private async handlePrompt(att: Attempt, prompt: OcPrompt): Promise<void> {
    const proc = att.proc;
    if (!proc) return;
    const log = this.deps.logger;
    switch (prompt.kind) {
      case 'cert-confirm':
        log.warn('vpn', 'Server certificate is not trusted; refusing.');
        att.forcedError = { code: 'TLS_ERROR', detail: att.lastMessage };
        proc.write('no\n');
        return;

      case 'select': {
        if (GATEWAY_LABEL_RE.test(prompt.label)) {
          const choice = this.pickGateway(att, prompt.options);
          att.selectedGateway = choice;
          log.info('vpn', `Selecting gateway "${choice}"`);
          proc.write(`${choice}\n`);
          return;
        }
        const answer = await this.ask(att, {
          kind: 'select',
          message: att.lastMessage ?? prompt.label,
          options: prompt.options,
        });
        if (answer === null) throw new VpnError('AUTH_CANCELLED', 'Selection cancelled');
        if (!prompt.options.includes(answer)) throw new VpnError('AUTH_CANCELLED', 'Invalid selection');
        proc.write(`${answer}\n`);
        return;
      }

      case 'secret': {
        if (att.authFailed) {
          // openconnect asks again after a failed login: do not loop, report the failure.
          throw new VpnError('AUTH_FAILED', att.pendingError?.detail ?? 'Login failed');
        }
        const context = att.lastMessage && att.lastMessage !== prompt.label ? att.lastMessage : undefined;
        const isOtp = OTP_RE.test(prompt.label) || (context !== undefined && OTP_RE.test(context));
        const answer = await this.ask(att, {
          kind: isOtp ? 'otp' : 'password',
          message: [context, prompt.label].filter(Boolean).join('\n'),
        });
        if (answer === null) throw new VpnError('AUTH_CANCELLED', 'Prompt cancelled');
        this.addSecret(att, answer);
        proc.write(`${answer}\n`);
        return;
      }

      case 'text': {
        if (/user/i.test(prompt.label) && att.username) {
          proc.write(`${att.username}\n`);
          return;
        }
        const answer = await this.ask(att, {
          kind: 'text',
          message: [att.lastMessage, prompt.label].filter(Boolean).join('\n'),
        });
        if (answer === null) throw new VpnError('AUTH_CANCELLED', 'Prompt cancelled');
        proc.write(`${answer}\n`);
        return;
      }
    }
  }

  private pickGateway(att: Attempt, options: string[]): string {
    const wanted = att.requestedGateway?.toLowerCase();
    if (wanted) {
      const byLabel = options.find((o) => o.toLowerCase() === wanted);
      if (byLabel) return byLabel;
      const gw = att.gateways.find((g) => g.address.toLowerCase() === wanted || g.name.toLowerCase() === wanted);
      const byGw = gw && options.find((o) => o === gw.name || o === gw.address);
      if (byGw) return byGw;
      this.deps.logger.warn(
        'vpn',
        `Gateway "${att.requestedGateway}" is not offered by the portal; using the first one`,
      );
    }
    return options[0]!;
  }

  private currentGateway(att: Attempt): Gateway | undefined {
    const key = (att.selectedGateway ?? att.requestedGateway)?.toLowerCase();
    if (key) {
      const found = att.gateways.find((g) => g.name.toLowerCase() === key || g.address.toLowerCase() === key);
      if (found) return found;
      const name = att.selectedGateway ?? att.requestedGateway!;
      return { name, address: name };
    }
    if (att.gateways.length === 1) return att.gateways[0];
    if (att.gateways.length === 0) {
      const host = new URL(att.profile.portalUrl).host;
      return { name: host, address: host };
    }
    return undefined;
  }

  // ---------------------------------------------------------------- process lifecycle

  private async stopProcess(att: Attempt, proc: VpnProcess): Promise<void> {
    const log = this.deps.logger;
    const exited = att.exitPromise ?? Promise.resolve();
    try {
      await proc.stop();
    } catch (err) {
      log.warn('vpn', `Graceful stop failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (await this.waitFor(exited, this.stopTimeoutMs)) return;
    log.warn('vpn', 'openconnect did not stop in time; killing it');
    try {
      await proc.kill();
    } catch (err) {
      log.error('vpn', 'Failed to kill openconnect', err);
    }
    if (await this.waitFor(exited, 3_000)) return;
    // The (root) process is still alive, typically because both admin dialogs
    // (stop and kill) were dismissed. Do NOT pretend we are disconnected: keep
    // owning the process so Disconnect can be retried and a late exit is handled.
    log.error('vpn', 'openconnect is still running after kill');
    if (this.attempt === att) {
      const status = att.statusBeforeStop ?? (att.everConnected ? 'connected' : 'authenticating');
      this.setState({ ...this.state, status, error: this.stopFailedError() });
    }
  }

  private stopFailedError(): StateError {
    return {
      code: 'PRIVILEGES_DENIED',
      message: stopFailedMessage(this.deps.getSettings().language),
      hint: 'stop_failed',
    };
  }

  private waitFor(p: Promise<void>, ms: number): Promise<boolean> {
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), ms);
      void p.then(() => {
        clearTimeout(t);
        resolve(true);
      });
    });
  }

  private onProcessExit(att: Attempt, info: ExitInfo): void {
    for (const stream of ['stdout', 'stderr'] as const) {
      for (const line of att.splitters[stream].flush()) this.onLine(att, line);
    }
    this.deps.logger.info(
      'vpn',
      `openconnect exited (code ${info.code ?? 'none'}${info.signal ? `, ${info.signal}` : ''})`,
    );
    if (this.attempt !== att) return;
    this.finishAttempt(att);

    if (att.userStopping) {
      this.setIdle('disconnected', att.profile.id);
      return;
    }
    const err = att.forcedError ?? att.pendingError ?? this.classifyExit(att, info);
    if (this.shouldReconnect(att, err)) {
      this.scheduleReconnect(att, err);
    } else {
      this.endWithError(att, err);
    }
  }

  private classifyExit(att: Attempt, info: ExitInfo): VpnErrorInfo {
    // pkexec: 126 = dialog dismissed, 127 = not authorized.
    if (info.code === 126 || info.code === 127) {
      return { code: 'PRIVILEGES_DENIED', detail: att.lastMessage };
    }
    if (att.everConnected || att.isReconnect) {
      return { code: 'TUNNEL_FAILED', detail: att.lastMessage ?? 'Connection lost' };
    }
    return {
      code: 'UNKNOWN',
      detail: att.lastMessage ?? `openconnect exited with code ${info.code ?? info.signal ?? 'unknown'}`,
    };
  }

  private shouldReconnect(att: Attempt, err: VpnErrorInfo): boolean {
    if (!this.deps.getSettings().autoReconnect) return false;
    if (!att.everConnected && !att.isReconnect) return false;
    if (NON_RETRYABLE.has(err.code)) return false;
    return this.reconnectCount < this.maxReconnectAttempts;
  }

  private scheduleReconnect(att: Attempt, err: VpnErrorInfo): void {
    const delay = backoffDelay(this.reconnectCount, this.backoffMs);
    this.reconnectCount++;
    this.deps.logger.warn(
      'vpn',
      `Connection lost [${err.code}]; reconnect ${this.reconnectCount}/${this.maxReconnectAttempts} in ${delay / 1000}s`,
    );
    this.setState({
      status: 'reconnecting',
      profileId: att.profile.id,
      gateways: att.gateways.length ? att.gateways : undefined,
      error: this.errorFor(err),
    });
    this.cancelReconnectTimer();
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      const profile = this.deps.getProfile(att.profile.id);
      if (!profile) {
        this.setIdle('disconnected');
        return;
      }
      this.startAttempt(profile, att.opts, true);
    }, delay);
  }

  /** Common cleanup when an attempt is over (process gone or never started). */
  private finishAttempt(att: Attempt): void {
    for (const t of Object.values(att.promptTimers)) if (t) clearTimeout(t);
    this.cancelPrompts(att);
    for (const s of att.secrets) {
      if (s !== this.sessionPassword?.value) this.deps.logger.secrets.delete(s);
    }
    if (this.attempt === att) this.attempt = null;
  }

  private endWithError(att: Attempt, err: VpnErrorInfo): void {
    this.cancelReconnectTimer();
    this.clearSessionPassword();
    this.setState({
      status: 'error',
      profileId: att.profile.id,
      gateways: att.gateways.length ? att.gateways : undefined,
      error: this.errorFor(err),
    });
  }

  private setIdle(status: 'disconnected', profileId?: string): void {
    const gateways = profileId ? this.knownGateways.get(profileId) : undefined;
    this.setState({ status, profileId, gateways: gateways?.length ? gateways : undefined });
  }

  private errorFor(err: VpnErrorInfo): StateError {
    const detail = errorDetail(err.detail ? this.deps.logger.secrets.mask(err.detail) : undefined);
    const out: StateError = {
      code: err.code,
      message: errorMessage(err.code, this.deps.getSettings().language, err.hint, this.deps.platform),
    };
    if (detail) out.detail = detail;
    if (err.hint) out.hint = err.hint;
    return out;
  }

  private cancelReconnectTimer(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private clearSessionPassword(): void {
    if (this.sessionPassword) this.deps.logger.secrets.delete(this.sessionPassword.value);
    this.sessionPassword = null;
  }

  private addSecret(att: Attempt, secret: string): void {
    att.secrets.push(secret);
    this.deps.logger.secrets.add(secret);
  }

  // ---------------------------------------------------------------- prompts

  private ask(att: Attempt, p: Omit<AuthPrompt, 'id'>): Promise<string | null> {
    this.assertCurrent(att);
    // Prompt text may come straight from openconnect output (newline-less fragment):
    // mask it like the log does before it reaches the renderer.
    const mask = (t: string): string => this.deps.logger.secrets.mask(t);
    const prompt: AuthPrompt = { id: this.newId(), ...p, message: mask(p.message) };
    // Select answers come back as the masked option: map them back to the raw one.
    const rawByShown = new Map<string, string[]>();
    if (p.options) {
      prompt.options = p.options.map((raw) => {
        const shown = mask(raw);
        rawByShown.set(shown, [...(rawByShown.get(shown) ?? []), raw]);
        return shown;
      });
    }
    return new Promise<string | null>((resolve) => {
      att.promptIds.add(prompt.id);
      this.pendingPrompts.set(prompt.id, prompt);
      this.prompts.set(prompt.id, (value) => {
        this.prompts.delete(prompt.id);
        this.pendingPrompts.delete(prompt.id);
        att.promptIds.delete(prompt.id);
        resolve(value);
      });
      this.emitter.emit('prompt', structuredClone(prompt));
    }).then((value) => {
      this.assertCurrent(att);
      if (value === null || !p.options) return value;
      return unmaskOption(value, rawByShown);
    });
  }

  private aliasesFor(profileId: string): Map<string, Set<string>> {
    let m = this.gatewayAliases.get(profileId);
    if (!m) {
      m = new Map();
      this.gatewayAliases.set(profileId, m);
    }
    return m;
  }

  private cancelPrompts(att: Attempt): void {
    for (const id of [...att.promptIds]) this.prompts.get(id)?.(null);
  }

  // ---------------------------------------------------------------- state

  /**
   * Translates a gateway value received from the renderer (possibly masked) back to
   * the raw name/address. Unknown values pass through unchanged; a masked value that
   * matches several raw gateways is ambiguous → warning and no explicit selection.
   */
  private unmaskGateway(profileId: string, value: string | undefined): string | undefined {
    if (value === undefined) return undefined;
    const raws = this.gatewayAliases.get(profileId)?.get(value);
    if (!raws || raws.size === 0 || raws.has(value)) return value;
    if (raws.size === 1) return [...raws][0];
    this.deps.logger.warn(
      'vpn',
      `Gateway "${value}" is ambiguous (several gateways look the same after hiding secrets); selecting automatically`,
    );
    return undefined;
  }

  private setState(next: VpnState): void {
    // Gateway names/addresses and the IP come from raw openconnect output.
    const mask = (t: string): string => this.deps.logger.secrets.mask(t);
    const aliases = next.profileId ? this.aliasesFor(next.profileId) : null;
    const maskValue = (raw: string): string => {
      const shown = mask(raw);
      // Only real maskings are recorded (state values re-emitted from this.state are
      // already masked and must not alias to themselves).
      if (aliases && shown !== raw) aliases.set(shown, (aliases.get(shown) ?? new Set<string>()).add(raw));
      return shown;
    };
    const maskGw = (g: Gateway): Gateway => ({ ...g, name: maskValue(g.name), address: maskValue(g.address) });
    next = {
      ...next,
      gateway: next.gateway ? maskGw(next.gateway) : undefined,
      gateways: next.gateways?.map(maskGw),
      assignedIp: next.assignedIp === undefined ? undefined : mask(next.assignedIp),
    };
    const clean: VpnState = { status: next.status };
    for (const [k, v] of Object.entries(next)) {
      if (v !== undefined) (clean as unknown as Record<string, unknown>)[k] = v;
    }
    this.state = clean;
    this.emitter.emit('state', structuredClone(clean));
  }
}
