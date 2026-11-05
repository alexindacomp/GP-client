//! VPN connection state machine. Owns at most one openconnect
//! process.
//!
//! `disconnected → prelogin → authenticating → connecting → connected → disconnecting →
//! disconnected`, plus `error` (terminal until the next connect) and `reconnecting`
//! (auto-reconnect with backoff 2/5/10/30 s).
//!
//! Concurrency: all state lives behind one mutex (`Core`); per-attempt data behind a second one
//! that is only ever locked *after* `Core` (never the other way round) and never across an
//! `.await`. Each process gets one pump task that reads its output/exit in order and owns the
//! line splitters, the output parser and the prompt debounce timers.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::backoff::{DEFAULT_BACKOFF, backoff_delay};
use super::errors::VpnError;
use super::messages::{PromptLabel, error_detail, error_message, prompt_label, stop_failed_message};
use crate::clock::{Clock, SystemClock};
use crate::logging::Logger;
use crate::openconnect::args::{OpenconnectArgsInput, OpenconnectAuth, build_openconnect_args};
use crate::openconnect::output_parser::{LineSplitter, OcEvent, OcPrompt, OutputParser, parse_prompt};
use crate::platform::Platform;
use crate::prelogin::{AuthType, PreloginClient, PreloginResult};
use crate::process::{
    Elevation, ExitStatusInfo, OutputChunk, OutputStream, ProcessSpawner, SpawnRequest, VpnProcess,
};
use crate::saml::SamlAuthenticator;
use crate::types::{
    AuthMode, AuthPrompt, ConnectOptions, Gateway, Profile, PromptKind, Settings, VpnErrorCode, VpnErrorHint,
    VpnState, VpnStateError, VpnStatus,
};
use crate::util::js_len;
use crate::validation::format_ipc_error;

// ------------------------------------------------------------------ dependencies

/// Profiles as seen by the engine (implemented by the app on top of `ProfilesStore`).
pub trait ProfileProvider: Send + Sync {
    fn get_profile(&self, id: &str) -> Option<Profile>;
    /// Saved password of a profile; `None` when not saved.
    fn get_saved_password(&self, profile_id: &str) -> Option<String>;
}

/// Current settings (re-read before every spawn).
pub trait SettingsProvider: Send + Sync {
    fn get_settings(&self) -> Settings;
}

/// Files that will run with administrator rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedFiles {
    pub binary: String,
    pub hip_script_path: Option<String>,
}

#[async_trait]
pub trait OpenconnectProvider: Send + Sync {
    /// Absolute path of the openconnect binary, or `None` when not installed.
    async fn locate_openconnect(&self) -> Option<String>;
    /// Verifies that the files that will run elevated are admin-controlled (and that changed
    /// settings were confirmed) and returns their real paths. Must fail with a
    /// `PRIVILEGES_DENIED` [`VpnError`] otherwise. Called before prelogin and again right before
    /// every spawn.
    async fn verify_elevated_files(&self, files: &ElevatedFiles) -> Result<ElevatedFiles, VpnError>;
}

/// Timings and limits.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Wait for a graceful stop before killing.
    pub stop_timeout: Duration,
    /// Wait for the exit after a kill.
    pub kill_timeout: Duration,
    /// How long a newline-less fragment must be stable before it is treated as a prompt.
    pub prompt_debounce: Duration,
    pub backoff: Vec<Duration>,
    pub max_reconnect_attempts: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            stop_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(3),
            prompt_debounce: Duration::from_millis(150),
            backoff: DEFAULT_BACKOFF.to_vec(),
            max_reconnect_attempts: 10,
        }
    }
}

pub type IdGenerator = Arc<dyn Fn() -> String + Send + Sync>;

pub struct EngineDeps {
    pub platform: Platform,
    /// Elevation method put into every [`SpawnRequest`] (see `process::choose_elevation`).
    pub elevation: Elevation,
    pub profiles: Arc<dyn ProfileProvider>,
    pub settings: Arc<dyn SettingsProvider>,
    pub prelogin: Arc<dyn PreloginClient>,
    pub saml: Arc<dyn SamlAuthenticator>,
    pub openconnect: Arc<dyn OpenconnectProvider>,
    pub spawner: Arc<dyn ProcessSpawner>,
    pub logger: Arc<Logger>,
    pub clock: Arc<dyn Clock>,
    /// Prompt ids (UUID v4 by default).
    pub new_id: IdGenerator,
    pub config: EngineConfig,
}

impl EngineDeps {
    /// Deps with the system clock, UUID prompt ids and the default config.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        platform: Platform,
        elevation: Elevation,
        profiles: Arc<dyn ProfileProvider>,
        settings: Arc<dyn SettingsProvider>,
        prelogin: Arc<dyn PreloginClient>,
        saml: Arc<dyn SamlAuthenticator>,
        openconnect: Arc<dyn OpenconnectProvider>,
        spawner: Arc<dyn ProcessSpawner>,
        logger: Arc<Logger>,
    ) -> Self {
        EngineDeps {
            platform,
            elevation,
            profiles,
            settings,
            prelogin,
            saml,
            openconnect,
            spawner,
            logger,
            clock: Arc::new(SystemClock),
            new_id: Arc::new(|| uuid::Uuid::new_v4().to_string()),
            config: EngineConfig::default(),
        }
    }
}

// ------------------------------------------------------------------ public API types

/// Pushed to subscribers (`gp:vpn:state`, `gp:vpn:prompt`).
#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    State(VpnState),
    Prompt(AuthPrompt),
}

/// Rejections of invalid requests (everything else is reported through the state).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("Profile not found")]
    ProfileNotFound,
    #[error("Cannot connect while {0}")]
    Busy(VpnStatus),
    #[error("Cannot connect while openconnect is still running")]
    StillRunning,
    #[error("Unknown or expired prompt")]
    UnknownPrompt,
    #[error("Invalid answer")]
    InvalidAnswer,
    #[error("Answer must be a single line")]
    MultiLineAnswer,
}

impl EngineError {
    /// Message with `[field:..][code:..]` markers for the UI (`publicError` in the TS handlers).
    pub fn to_ipc_error(&self) -> String {
        let (field, code) = match self {
            EngineError::ProfileNotFound => (Some("profileId"), "not_found"),
            EngineError::Busy(_) | EngineError::StillRunning => (None, "busy"),
            EngineError::UnknownPrompt => (Some("promptId"), "prompt_expired"),
            EngineError::InvalidAnswer | EngineError::MultiLineAnswer => (Some("answer"), "invalid"),
        };
        format_ipc_error(field, Some(code), &self.to_string())
    }
}

/// Maps a select answer (as shown to the UI, possibly masked) back to the raw option. If several
/// raw options were shown identically, the answer is ambiguous and an empty string is returned,
/// which no option equals → the caller rejects it.
pub fn unmask_option<S: std::hash::BuildHasher>(
    answer: &str,
    raw_by_shown: &HashMap<String, Vec<String>, S>,
) -> String {
    let Some(raws) = raw_by_shown.get(answer) else {
        return answer.to_string();
    };
    let unique: BTreeSet<&String> = raws.iter().collect();
    if unique.len() == 1 {
        (*unique.first().expect("one element")).clone()
    } else {
        String::new()
    }
}

// ------------------------------------------------------------------ internals

#[derive(Debug, Clone)]
struct ErrInfo {
    code: VpnErrorCode,
    /// Technical cause → `VpnState.error.detail`.
    detail: Option<String>,
    hint: Option<VpnErrorHint>,
}

impl ErrInfo {
    fn code(code: VpnErrorCode, detail: Option<String>) -> Self {
        ErrInfo {
            code,
            detail,
            hint: None,
        }
    }
}

enum AttemptError {
    /// The attempt was superseded or cancelled; never surfaces.
    Stale,
    Failed(VpnError),
}

impl From<VpnError> for AttemptError {
    fn from(e: VpnError) -> Self {
        AttemptError::Failed(e)
    }
}

type AResult<T> = Result<T, AttemptError>;

/// Error codes that make retrying pointless.
const NON_RETRYABLE: [VpnErrorCode; 5] = [
    VpnErrorCode::OpenconnectNotFound,
    VpnErrorCode::AuthFailed,
    VpnErrorCode::AuthCancelled,
    VpnErrorCode::PrivilegesDenied,
    VpnErrorCode::TlsError,
];

/// When several errors are seen in the output, the most specific wins.
const ERROR_PRIORITY: [VpnErrorCode; 6] = [
    VpnErrorCode::PrivilegesDenied,
    VpnErrorCode::AuthFailed,
    VpnErrorCode::TlsError,
    VpnErrorCode::TunnelFailed,
    VpnErrorCode::PortalUnreachable,
    VpnErrorCode::Unknown,
];

fn priority(code: VpnErrorCode) -> usize {
    ERROR_PRIORITY
        .iter()
        .position(|c| *c == code)
        .unwrap_or(ERROR_PRIORITY.len())
}

const MAX_ANSWER_LENGTH: usize = 4096;

static GATEWAY_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new("(?i)gateway").expect("valid regex"));
static USER_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new("(?i)user").expect("valid regex"));
static OTP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)otp|one[- ]time|token|passcode|\bcode\b|challenge|verification|mfa|2fa|authenticator|\bpin\b",
    )
    .expect("valid regex")
});

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running process as owned by the engine.
struct ProcHandle {
    proc: tokio::sync::Mutex<Box<dyn VpnProcess>>,
    /// Becomes `true` once the pump has handled the exit.
    exited: watch::Receiver<bool>,
}

impl ProcHandle {
    async fn write(&self, data: &str) -> AResult<()> {
        self.proc.lock().await.write(data.as_bytes()).await.map_err(|e| {
            AttemptError::Failed(VpnError::new(
                VpnErrorCode::Unknown,
                format!("write to openconnect failed: {e}"),
            ))
        })
    }

    async fn wait_exit(&self, within: Duration) -> bool {
        let mut rx = self.exited.clone();
        matches!(tokio::time::timeout(within, rx.wait_for(|v| *v)).await, Ok(Ok(_)))
    }
}

struct Attempt {
    id: u64,
    profile: Profile,
    opts: ConnectOptions,
    is_reconnect: bool,
    cancel: CancellationToken,
    data: Mutex<AttemptData>,
}

impl Attempt {
    fn d(&self) -> MutexGuard<'_, AttemptData> {
        lock(&self.data)
    }
}

#[derive(Default)]
struct AttemptData {
    proc: Option<Arc<ProcHandle>>,
    username: Option<String>,
    requested_gateway: Option<String>,
    selected_gateway: Option<String>,
    gateways: Vec<Gateway>,
    pending_error: Option<ErrInfo>,
    auth_failed: bool,
    ever_connected: bool,
    user_stopping: bool,
    /// Error to report when the attempt ends because of a local decision (cancel, auth loop, cert).
    forced_error: Option<ErrInfo>,
    last_message: Option<String>,
    /// In-flight stop (graceful → kill); shared by repeated Disconnect clicks.
    stop_done: Option<watch::Receiver<bool>>,
    /// Status to restore if openconnect cannot be stopped.
    status_before_stop: Option<VpnStatus>,
    /// `spawn()` is in flight (e.g. the UAC/admin dialog is open).
    spawning: bool,
    /// Counted in `pending_disposals` until the late process is gone.
    disposal_counted: bool,
    secrets: Vec<String>,
}

struct PendingPrompt {
    attempt_id: u64,
    tx: oneshot::Sender<Option<String>>,
}

struct Core {
    state: VpnState,
    attempt: Option<Arc<Attempt>>,
    next_attempt_id: u64,
    /// (generation, task) of the scheduled reconnect.
    reconnect_timer: Option<(u64, JoinHandle<()>)>,
    timer_gen: u64,
    /// Attempts abandoned by Disconnect while their process was still starting. Until the late
    /// process is disposed (or re-adopted), a new connect is refused so it can never become an
    /// untracked second openconnect.
    pending_disposals: u32,
    reconnect_count: u32,
    /// Password entered for the current session; in memory only so auto-reconnect does not re-ask.
    session_password: Option<(String, String)>,
    prompts: HashMap<String, PendingPrompt>,
    pending_prompts: Vec<AuthPrompt>,
    known_gateways: HashMap<String, Vec<Gateway>>,
    /// profileId → (value as shown to the UI → raw gateway names/addresses), recorded when masked
    /// gateways are emitted, so a masked value sent back (e.g. "***-GW") can be translated even
    /// after the secret that caused the masking has left the registry.
    gateway_aliases: HashMap<String, HashMap<String, BTreeSet<String>>>,
    subscribers: Vec<mpsc::UnboundedSender<EngineEvent>>,
}

fn is_current(core: &Core, att: &Arc<Attempt>) -> bool {
    core.attempt.as_ref().is_some_and(|a| Arc::ptr_eq(a, att))
}

fn assert_current(core: &Core, att: &Arc<Attempt>) -> AResult<()> {
    if is_current(core, att) && !att.cancel.is_cancelled() {
        Ok(())
    } else {
        Err(AttemptError::Stale)
    }
}

fn non_empty_gateways(g: &[Gateway]) -> Option<Vec<Gateway>> {
    (!g.is_empty()).then(|| g.to_vec())
}

/// Incremental UTF-8 decoding of pipe chunks (a character may be split across reads).
#[derive(Default)]
struct Utf8Decoder {
    pending: Vec<u8>,
}

impl Utf8Decoder {
    fn push(&mut self, data: &[u8]) -> String {
        self.pending.extend_from_slice(data);
        let mut out = String::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(s) => {
                    out.push_str(s);
                    self.pending.clear();
                    return out;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    out.push_str(std::str::from_utf8(&self.pending[..valid]).expect("validated prefix"));
                    match e.error_len() {
                        // incomplete sequence at the end: wait for more data
                        None => {
                            self.pending.drain(..valid);
                            return out;
                        }
                        Some(n) => {
                            out.push(char::REPLACEMENT_CHARACTER);
                            self.pending.drain(..valid + n);
                        }
                    }
                }
            }
        }
    }

    fn finish(&mut self) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        let s = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        s
    }
}

/// Pump-local per-stream state.
#[derive(Default)]
struct StreamState {
    decoder: Utf8Decoder,
    splitter: LineSplitter,
    prompt_deadline: Option<Instant>,
}

struct PumpState {
    streams: [StreamState; 2],
    parser: OutputParser,
}

fn stream_index(s: OutputStream) -> usize {
    match s {
        OutputStream::Stdout => 0,
        OutputStream::Stderr => 1,
    }
}

struct Inner {
    deps: EngineDeps,
    core: Mutex<Core>,
}

// ------------------------------------------------------------------ engine

/// The VPN engine. Cheap to clone (shared handle). Must be used inside a tokio runtime.
#[derive(Clone)]
pub struct VpnEngine {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for VpnEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnEngine")
            .field("state", &self.get_state())
            .finish_non_exhaustive()
    }
}

impl VpnEngine {
    pub fn new(deps: EngineDeps) -> Self {
        let core = Core {
            state: VpnState::new(VpnStatus::Disconnected),
            attempt: None,
            next_attempt_id: 0,
            reconnect_timer: None,
            timer_gen: 0,
            pending_disposals: 0,
            reconnect_count: 0,
            session_password: None,
            prompts: HashMap::new(),
            pending_prompts: Vec::new(),
            known_gateways: HashMap::new(),
            gateway_aliases: HashMap::new(),
            subscribers: Vec::new(),
        };
        VpnEngine {
            inner: Arc::new(Inner {
                deps,
                core: Mutex::new(core),
            }),
        }
    }

    pub fn get_state(&self) -> VpnState {
        lock(&self.inner.core).state.clone()
    }

    /// Prompts that are waiting for an answer (re-sent to a reloaded UI).
    pub fn get_pending_prompts(&self) -> Vec<AuthPrompt> {
        lock(&self.inner.core).pending_prompts.clone()
    }

    /// State and prompt events from now on. Dropping the receiver unsubscribes.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<EngineEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        lock(&self.inner.core).subscribers.push(tx);
        rx
    }

    /// Re-renders `state.error.message` in the current settings language (after a language
    /// change) and re-emits the state. Code, hint and detail are kept.
    pub fn relocalize(&self) {
        let inner = &self.inner;
        let mut core = lock(&inner.core);
        let Some(err) = core.state.error.clone() else {
            return;
        };
        let lang = inner.deps.settings.get_settings().language;
        let message = error_message(err.code, lang, err.hint, inner.deps.platform);
        if message == err.message {
            return;
        }
        let mut next = core.state.clone();
        next.error = Some(VpnStateError {
            message: message.to_string(),
            ..err
        });
        inner.set_state(&mut core, next);
    }

    /// Starts a connection attempt and returns once it has been started. Progress and failures
    /// are reported through state changes; only invalid requests are rejected.
    pub fn connect(&self, profile_id: &str, opts: ConnectOptions) -> Result<(), EngineError> {
        let inner = &self.inner;
        let profile = inner
            .deps
            .profiles
            .get_profile(profile_id)
            .ok_or(EngineError::ProfileNotFound)?;
        let mut core = lock(&inner.core);
        let status = core.state.status;
        if status != VpnStatus::Disconnected && status != VpnStatus::Error {
            return Err(EngineError::Busy(status));
        }
        if core.attempt.is_some() || core.pending_disposals > 0 {
            // An openconnect that could not be stopped is still owned by the engine, or one that
            // was starting during Disconnect has not been disposed yet.
            return Err(EngineError::StillRunning);
        }
        core.reconnect_count = 0;
        if core
            .session_password
            .as_ref()
            .is_some_and(|(id, _)| id != profile_id)
        {
            inner.clear_session_password(&mut core);
        }
        inner.start_attempt(&mut core, profile, opts, false);
        Ok(())
    }

    /// Stops the current connection/attempt and resolves when the engine is `disconnected` (or
    /// when stopping failed: the process is then still owned and Disconnect can be retried).
    /// Idempotent: repeated calls while a stop is in flight share it.
    pub async fn disconnect(&self) {
        let inner = &self.inner;
        let wait = {
            let mut core = lock(&inner.core);
            cancel_reconnect_timer(&mut core);
            let Some(att) = core.attempt.clone() else {
                inner.clear_session_password(&mut core);
                if core.state.status != VpnStatus::Disconnected {
                    inner.set_idle(&mut core, None);
                }
                return;
            };
            // Mark the stop as user-initiated before joining an in-flight (forced) stop, so the
            // process exit ends in `disconnected` instead of an auto-reconnect.
            att.d().user_stopping = true;
            att.cancel.cancel();
            cancel_prompts(&mut core, att.id);
            inner.clear_session_password(&mut core);

            let mut d = att.d();
            if let Some(rx) = d.stop_done.clone() {
                drop(d);
                if core.state.status != VpnStatus::Disconnecting {
                    let mut next = core.state.clone();
                    next.status = VpnStatus::Disconnecting;
                    next.error = None;
                    inner.set_state(&mut core, next);
                }
                rx
            } else if let Some(proc) = d.proc.clone() {
                d.status_before_stop = Some(core.state.status);
                drop(d);
                let mut next = core.state.clone();
                next.status = VpnStatus::Disconnecting;
                next.error = None;
                inner.set_state(&mut core, next);
                inner.deps.logger.info("vpn", "Disconnecting…");
                Inner::run_stop(inner, &att, proc)
            } else {
                // Still in prelogin/SAML/spawn: the attempt will notice it is stale.
                if d.spawning && !d.disposal_counted {
                    d.disposal_counted = true;
                    core.pending_disposals += 1;
                }
                inner.finish_attempt(&mut core, &att, &mut d);
                drop(d);
                inner.set_idle(&mut core, Some(att.profile.id.clone()));
                return;
            }
        };
        let mut wait = wait;
        let _ = wait.wait_for(|done| *done).await;
    }

    /// Answers a prompt; `None` cancels it (and the connection attempt).
    pub fn answer_prompt(&self, id: &str, value: Option<String>) -> Result<(), EngineError> {
        let mut core = lock(&self.inner.core);
        if !core.prompts.contains_key(id) {
            return Err(EngineError::UnknownPrompt);
        }
        if let Some(v) = &value {
            if js_len(v) > MAX_ANSWER_LENGTH {
                return Err(EngineError::InvalidAnswer);
            }
            if v.contains(['\r', '\n', '\0']) {
                return Err(EngineError::MultiLineAnswer);
            }
        }
        resolve_prompt(&mut core, id, value);
        Ok(())
    }

    /// Called on app quit: stop openconnect.
    pub async fn shutdown(&self) {
        self.disconnect().await;
    }
}

fn resolve_prompt(core: &mut Core, id: &str, value: Option<String>) {
    if let Some(p) = core.prompts.remove(id) {
        core.pending_prompts.retain(|x| x.id != id);
        let _ = p.tx.send(value);
    }
}

impl Inner {
    fn mask(&self, t: &str) -> String {
        self.deps.logger.secrets().mask(t)
    }

    fn settings(&self) -> Settings {
        self.deps.settings.get_settings()
    }

    // ---------------------------------------------------------------- attempts

    fn start_attempt(
        self: &Arc<Self>,
        core: &mut Core,
        profile: Profile,
        opts: ConnectOptions,
        is_reconnect: bool,
    ) {
        core.next_attempt_id += 1;
        let gateways = core.known_gateways.get(&profile.id).cloned().unwrap_or_default();
        let att = Arc::new(Attempt {
            id: core.next_attempt_id,
            profile,
            opts,
            is_reconnect,
            cancel: CancellationToken::new(),
            data: Mutex::new(AttemptData {
                gateways,
                ..AttemptData::default()
            }),
        });
        core.attempt = Some(att.clone());
        {
            let d = att.d();
            self.phase(core, &att, &d, VpnStatus::Prelogin);
        }
        let verb = if is_reconnect {
            "Reconnecting"
        } else {
            "Connecting"
        };
        self.deps.logger.info(
            "vpn",
            &format!("{verb} to \"{}\" ({})", att.profile.name, att.profile.portal_url),
        );
        let inner = self.clone();
        tokio::spawn(async move {
            if let Err(e) = inner.run_attempt(&att).await {
                inner.on_attempt_error(&att, e);
            }
        });
    }

    fn phase(&self, core: &mut Core, att: &Attempt, d: &AttemptData, status: VpnStatus) {
        let mut s = VpnState::new(if att.is_reconnect {
            VpnStatus::Reconnecting
        } else {
            status
        });
        s.profile_id = Some(att.profile.id.clone());
        s.gateways = non_empty_gateways(&d.gateways);
        self.set_state(core, s);
    }

    fn check(&self, att: &Arc<Attempt>) -> AResult<()> {
        assert_current(&lock(&self.core), att)
    }

    async fn run_attempt(self: &Arc<Self>, att: &Arc<Attempt>) -> AResult<()> {
        let deps = &self.deps;
        let log = &deps.logger;
        let profile = &att.profile;
        let settings = self.settings();

        let binary = deps.openconnect.locate_openconnect().await;
        self.check(att)?;
        let binary = binary.ok_or_else(|| {
            VpnError::new(VpnErrorCode::OpenconnectNotFound, "openconnect binary not found")
        })?;
        // Fail fast (before prelogin/SAML) on an untrusted binary or HIP script; the check is
        // repeated right before spawning.
        let files = ElevatedFiles {
            binary: binary.clone(),
            hip_script_path: settings.hip_script_path.clone(),
        };
        deps.openconnect.verify_elevated_files(&files).await?;
        self.check(att)?;

        let mut prelogin: Option<PreloginResult> = None;
        if profile.auth_mode != AuthMode::Password {
            let p = deps
                .prelogin
                .prelogin(&profile.portal_url, att.cancel.clone())
                .await?;
            self.check(att)?;
            let kind = match (p.auth_type, p.saml_method) {
                (AuthType::Saml, Some(m)) => format!("SAML ({})", m.as_str()),
                (AuthType::Saml, None) => "SAML".into(),
                (AuthType::Password, _) => "password".into(),
            };
            log.info("vpn", &format!("Prelogin: {kind}"));
            if profile.auth_mode == AuthMode::Saml && p.auth_type != AuthType::Saml {
                return Err(VpnError::new(
                    VpnErrorCode::AuthFailed,
                    "The portal does not offer SAML authentication",
                )
                .into());
            }
            prelogin = Some(p);
        }

        {
            let mut core = lock(&self.core);
            assert_current(&core, att)?;
            let d = att.d();
            self.phase(&mut core, att, &d, VpnStatus::Authenticating);
        }

        let auth: OpenconnectAuth;
        let secret: String;
        let mut username = profile.username.clone();
        if let Some(p) = prelogin.as_ref().filter(|p| p.auth_type == AuthType::Saml) {
            let saml = deps.saml.saml_login(profile, p, att.cancel.clone()).await?;
            self.check(att)?;
            auth = OpenconnectAuth::Saml {
                cookie_name: saml.cookie_name,
            };
            secret = saml.cookie;
            username = Some(saml.username);
        } else {
            auth = OpenconnectAuth::Password;
            if username.is_none() {
                let label = prelogin
                    .as_ref()
                    .and_then(|p| p.username_label.clone())
                    .unwrap_or_else(|| prompt_label(PromptLabel::Username, settings.language).to_string());
                let answer = self.ask(att, PromptKind::Text, &label, None).await?;
                let answer = answer.map(|a| a.trim().to_string()).filter(|a| !a.is_empty());
                let Some(a) = answer else {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Username not provided").into());
                };
                username = Some(a);
            }
            let session = {
                let core = lock(&self.core);
                core.session_password
                    .as_ref()
                    .filter(|(id, _)| *id == profile.id)
                    .map(|(_, v)| v.clone())
            };
            let mut password = att
                .opts
                .password
                .clone()
                .or_else(|| deps.profiles.get_saved_password(&profile.id))
                .or(session);
            if password.as_deref().is_none_or(str::is_empty) {
                let label = prelogin
                    .as_ref()
                    .and_then(|p| p.password_label.clone())
                    .unwrap_or_else(|| prompt_label(PromptLabel::Password, settings.language).to_string());
                let message = [
                    prelogin.as_ref().and_then(|p| p.auth_message.clone()),
                    Some(label),
                ]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
                let Some(answer) = self.ask(att, PromptKind::Password, &message, None).await? else {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Password not provided").into());
                };
                password = Some(answer);
            }
            secret = password.unwrap_or_default();
            lock(&self.core).session_password = Some((profile.id.clone(), secret.clone()));
        }

        {
            let core = lock(&self.core);
            let requested = self.unmask_gateway(&core, &profile.id, att.opts.gateway.as_deref());
            let mut d = att.d();
            add_secret(&self.deps.logger, &mut d, &secret);
            d.username.clone_from(&username);
            d.requested_gateway = requested.or_else(|| profile.preferred_gateway.clone());
        }

        // Settings are re-read and re-validated right before the elevated spawn.
        let current = self.settings();
        let files = ElevatedFiles {
            binary,
            hip_script_path: current.hip_script_path.clone(),
        };
        let trusted = deps.openconnect.verify_elevated_files(&files).await?;
        self.check(att)?;
        let requested_gateway = att.d().requested_gateway.clone();
        let args = build_openconnect_args(&OpenconnectArgsInput {
            portal_url: &profile.portal_url,
            platform: deps.platform,
            username: username.as_deref(),
            auth,
            gateway: requested_gateway.as_deref(),
            hip_script_path: trusted.hip_script_path.as_deref(),
            extra_args: &current.extra_args,
        })
        .map_err(|e| VpnError::new(VpnErrorCode::Unknown, e.message))?;
        log.info("vpn", &format!("Running {} {}", trusted.binary, args.join(" ")));

        {
            // No await between this check and `spawning = true`: Disconnect must either see the
            // attempt as stale before the spawn or count the in-flight spawn as pending disposal.
            let core = lock(&self.core);
            assert_current(&core, att)?;
            att.d().spawning = true;
        }
        let spawned = deps
            .spawner
            .spawn(SpawnRequest {
                binary: PathBuf::from(&trusted.binary),
                args,
                elevation: deps.elevation,
                env: Vec::new(),
            })
            .await;
        let proc = match spawned {
            Ok(p) => p,
            Err(e) => {
                let mut core = lock(&self.core);
                let mut d = att.d();
                d.spawning = false;
                release_disposal(&mut core, &mut d);
                return Err(VpnError::from(e).into());
            }
        };
        let handle = self.start_pump(att, proc);
        let stale = {
            // Atomically: either the attempt is still current and owns the process from now on,
            // or Disconnect already happened and the process must be disposed.
            let core = lock(&self.core);
            let mut d = att.d();
            d.spawning = false;
            let current = assert_current(&core, att).is_ok();
            if current {
                d.proc = Some(handle.clone());
            }
            !current
        };
        if stale {
            // Disconnected while the process was starting (e.g. during the UAC prompt).
            self.dispose_late_process(att, handle).await;
            let mut core = lock(&self.core);
            release_disposal(&mut core, &mut att.d());
            return Err(AttemptError::Stale);
        }
        handle.write(&format!("{secret}\n")).await
    }

    /// Takes the output/exit receivers and starts the pump task.
    fn start_pump(self: &Arc<Self>, att: &Arc<Attempt>, mut proc: Box<dyn VpnProcess>) -> Arc<ProcHandle> {
        let out_rx = proc.output();
        let exit_rx = proc.exited();
        let (exited_tx, exited_rx) = watch::channel(false);
        let handle = Arc::new(ProcHandle {
            proc: tokio::sync::Mutex::new(proc),
            exited: exited_rx,
        });
        let inner = self.clone();
        let att = att.clone();
        tokio::spawn(async move { inner.pump(&att, out_rx, exit_rx, exited_tx).await });
        handle
    }

    async fn pump(
        self: &Arc<Self>,
        att: &Arc<Attempt>,
        mut out_rx: mpsc::Receiver<OutputChunk>,
        mut exit_rx: oneshot::Receiver<ExitStatusInfo>,
        exited_tx: watch::Sender<bool>,
    ) {
        let mut st = PumpState {
            streams: [StreamState::default(), StreamState::default()],
            parser: OutputParser::new(),
        };
        let mut out_open = true;
        loop {
            let deadline = st.streams.iter().filter_map(|s| s.prompt_deadline).min();
            tokio::select! {
                biased;
                chunk = out_rx.recv(), if out_open => match chunk {
                    Some(c) => self.on_output(att, &mut st, &c),
                    None => out_open = false,
                },
                status = &mut exit_rx => {
                    while let Ok(c) = out_rx.try_recv() {
                        self.on_output(att, &mut st, &c);
                    }
                    self.on_process_exit(att, &mut st, &status.unwrap_or_default());
                    let _ = exited_tx.send(true);
                    return;
                }
                () = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                    let now = Instant::now();
                    for i in 0..st.streams.len() {
                        if st.streams[i].prompt_deadline.is_some_and(|d| d <= now) {
                            st.streams[i].prompt_deadline = None;
                            self.check_partial(att, &mut st, i);
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- process output

    fn on_output(self: &Arc<Self>, att: &Arc<Attempt>, st: &mut PumpState, chunk: &OutputChunk) {
        let i = stream_index(chunk.stream);
        let text = st.streams[i].decoder.push(&chunk.data);
        if text.is_empty() {
            return;
        }
        for line in st.streams[i].splitter.push(&text) {
            self.on_line(att, &mut st.parser, &line);
        }
        let s = &mut st.streams[i];
        s.prompt_deadline = (!s.splitter.partial().trim().is_empty())
            .then(|| Instant::now() + self.deps.config.prompt_debounce);
    }

    fn on_line(&self, att: &Arc<Attempt>, parser: &mut OutputParser, raw: &str) {
        if raw.trim().is_empty() {
            return;
        }
        // Classification runs on the RAW line (masking a short secret such as "a" must not
        // change "sudo: a password is required"). Everything that leaves the parser — log,
        // last message, error details, state — is masked.
        let line = self.mask(raw);
        self.deps.logger.info("openconnect", &line);
        let mut core = lock(&self.core);
        if !is_current(&core, att) {
            return;
        }
        let ev = parser.parse(raw);
        let mut d = att.d();
        let Some(ev) = ev else {
            d.last_message = Some(line.trim().to_string());
            return;
        };
        match ev {
            OcEvent::Authenticated => {
                if core.state.status == VpnStatus::Authenticating {
                    self.phase(&mut core, att, &d, VpnStatus::Connecting);
                }
            }
            OcEvent::GatewayList { .. } => d.gateways.clear(),
            OcEvent::Gateway(g) => {
                d.gateways.push(g);
                core.known_gateways
                    .insert(att.profile.id.clone(), d.gateways.clone());
                let mut next = core.state.clone();
                next.gateways = Some(d.gateways.clone());
                self.set_state(&mut core, next);
            }
            OcEvent::Connected { ip } => {
                d.ever_connected = true;
                d.pending_error = None;
                core.reconnect_count = 0;
                let mut next = VpnState::new(VpnStatus::Connected);
                next.profile_id = Some(att.profile.id.clone());
                next.assigned_ip = Some(ip.clone());
                next.connected_at = Some(self.deps.clock.now_ms());
                next.gateway = current_gateway(att, &d);
                next.gateways = non_empty_gateways(&d.gateways);
                self.set_state(&mut core, next);
                self.deps
                    .logger
                    .info("vpn", &format!("Connected, assigned IP {}", self.mask(&ip)));
            }
            OcEvent::Esp => d.pending_error = None,
            OcEvent::AuthFailed { message } => {
                d.auth_failed = true;
                record_error(
                    &mut d,
                    ErrInfo::code(VpnErrorCode::AuthFailed, Some(self.mask(&message))),
                );
            }
            OcEvent::Error { code, message } => {
                record_error(&mut d, ErrInfo::code(code, Some(self.mask(&message))));
            }
            OcEvent::SessionLost { message } => d.last_message = Some(self.mask(&message)),
        }
    }

    fn check_partial(self: &Arc<Self>, att: &Arc<Attempt>, st: &mut PumpState, i: usize) {
        {
            let core = lock(&self.core);
            if !is_current(&core, att) || att.d().proc.is_none() {
                return;
            }
        }
        let splitter = &mut st.streams[i].splitter;
        let Some(prompt) = parse_prompt(splitter.partial()) else {
            return;
        };
        let fragment = splitter.take_partial();
        self.deps.logger.info("openconnect", &self.mask(fragment.trim()));
        let inner = self.clone();
        let att = att.clone();
        tokio::spawn(async move {
            if let Err(e) = inner.handle_prompt(&att, prompt).await {
                inner.on_attempt_error(&att, e);
            }
        });
    }

    async fn handle_prompt(self: &Arc<Self>, att: &Arc<Attempt>, prompt: OcPrompt) -> AResult<()> {
        let Some(proc) = att.d().proc.clone() else {
            return Ok(());
        };
        let log = &self.deps.logger;
        match prompt {
            OcPrompt::CertConfirm => {
                log.warn("vpn", "Server certificate is not trusted; refusing.");
                {
                    let mut d = att.d();
                    d.forced_error = Some(ErrInfo::code(VpnErrorCode::TlsError, d.last_message.clone()));
                }
                proc.write("no\n").await
            }
            OcPrompt::Select { label, options } => {
                if GATEWAY_LABEL_RE.is_match(&label) {
                    let choice = self.pick_gateway(att, &options);
                    att.d().selected_gateway = Some(choice.clone());
                    log.info("vpn", &format!("Selecting gateway \"{choice}\""));
                    return proc.write(&format!("{choice}\n")).await;
                }
                let message = att.d().last_message.clone().unwrap_or(label);
                let Some(answer) = self
                    .ask(att, PromptKind::Select, &message, Some(&options))
                    .await?
                else {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Selection cancelled").into());
                };
                if !options.contains(&answer) {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Invalid selection").into());
                }
                proc.write(&format!("{answer}\n")).await
            }
            OcPrompt::Secret { label } => {
                let (auth_failed, pending_detail, last) = {
                    let d = att.d();
                    (
                        d.auth_failed,
                        d.pending_error.as_ref().and_then(|e| e.detail.clone()),
                        d.last_message.clone(),
                    )
                };
                if auth_failed {
                    // openconnect asks again after a failed login: do not loop, report the failure.
                    let detail = pending_detail.unwrap_or_else(|| "Login failed".into());
                    return Err(VpnError::new(VpnErrorCode::AuthFailed, detail).into());
                }
                let context = last.filter(|m| *m != label && !m.is_empty());
                let is_otp =
                    OTP_RE.is_match(&label) || context.as_deref().is_some_and(|c| OTP_RE.is_match(c));
                let message = [context, Some(label)]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("\n");
                let kind = if is_otp {
                    PromptKind::Otp
                } else {
                    PromptKind::Password
                };
                let Some(answer) = self.ask(att, kind, &message, None).await? else {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Prompt cancelled").into());
                };
                add_secret(&self.deps.logger, &mut att.d(), &answer);
                proc.write(&format!("{answer}\n")).await
            }
            OcPrompt::Text { label } => {
                let (username, last) = {
                    let d = att.d();
                    (d.username.clone(), d.last_message.clone())
                };
                if let Some(u) = username.filter(|u| !u.is_empty() && USER_LABEL_RE.is_match(&label)) {
                    return proc.write(&format!("{u}\n")).await;
                }
                let message = [last, Some(label)]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                let Some(answer) = self.ask(att, PromptKind::Text, &message, None).await? else {
                    return Err(VpnError::new(VpnErrorCode::AuthCancelled, "Prompt cancelled").into());
                };
                proc.write(&format!("{answer}\n")).await
            }
        }
    }

    fn pick_gateway(&self, att: &Attempt, options: &[String]) -> String {
        let d = att.d();
        if let Some(requested) = &d.requested_gateway {
            let wanted = requested.to_lowercase();
            if let Some(o) = options.iter().find(|o| o.to_lowercase() == wanted) {
                return o.clone();
            }
            let gw = d
                .gateways
                .iter()
                .find(|g| g.address.to_lowercase() == wanted || g.name.to_lowercase() == wanted);
            if let Some(o) = gw.and_then(|g| options.iter().find(|o| **o == g.name || **o == g.address)) {
                return o.clone();
            }
            self.deps.logger.warn(
                "vpn",
                &format!("Gateway \"{requested}\" is not offered by the portal; using the first one"),
            );
        }
        options[0].clone()
    }

    // ---------------------------------------------------------------- process lifecycle

    /// Joins or starts the stop (graceful → kill) of `proc`; the receiver flips to `true` when
    /// the stop sequence is over (exited, or given up).
    fn run_stop(self: &Arc<Self>, att: &Arc<Attempt>, proc: Arc<ProcHandle>) -> watch::Receiver<bool> {
        let mut d = att.d();
        if let Some(rx) = &d.stop_done {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(false);
        d.stop_done = Some(rx.clone());
        drop(d);
        let inner = self.clone();
        let att = att.clone();
        tokio::spawn(async move {
            inner.stop_process(&att, &proc).await;
            att.d().stop_done = None;
            let _ = tx.send(true);
        });
        rx
    }

    async fn stop_process(&self, att: &Arc<Attempt>, proc: &ProcHandle) {
        let log = &self.deps.logger;
        let stopped = proc.proc.lock().await.stop().await;
        if let Err(e) = stopped {
            log.warn("vpn", &format!("Graceful stop failed: {e}"));
        }
        if proc.wait_exit(self.deps.config.stop_timeout).await {
            return;
        }
        log.warn("vpn", "openconnect did not stop in time; killing it");
        let killed = proc.proc.lock().await.kill().await;
        if let Err(e) = killed {
            log.error("vpn", &format!("Failed to kill openconnect: {e}"));
        }
        if proc.wait_exit(self.deps.config.kill_timeout).await {
            return;
        }
        // The (root) process is still alive, typically because both admin dialogs (stop and
        // kill) were dismissed. Do NOT pretend we are disconnected: keep owning the process so
        // Disconnect can be retried and a late exit is handled.
        log.error("vpn", "openconnect is still running after kill");
        let mut core = lock(&self.core);
        if is_current(&core, att) {
            let status = {
                let d = att.d();
                d.status_before_stop.unwrap_or(if d.ever_connected {
                    VpnStatus::Connected
                } else {
                    VpnStatus::Authenticating
                })
            };
            let mut next = core.state.clone();
            next.status = status;
            next.error = Some(self.stop_failed_error());
            self.set_state(&mut core, next);
        }
    }

    /// A process that finished starting after the user disconnected must go away. If it cannot
    /// be killed (e.g. the admin dialog for `pkexec kill` was dismissed), the engine re-adopts it
    /// so the user sees it and can retry.
    async fn dispose_late_process(&self, att: &Arc<Attempt>, handle: Arc<ProcHandle>) {
        let log = &self.deps.logger;
        let killed = handle.proc.lock().await.kill().await;
        if let Err(e) = killed {
            log.error(
                "vpn",
                &format!("Failed to kill openconnect that started after disconnect: {e}"),
            );
        }
        if handle.wait_exit(self.deps.config.kill_timeout).await {
            return;
        }
        log.error(
            "vpn",
            "openconnect that started after disconnect is still running",
        );
        let mut core = lock(&self.core);
        // connect() is refused while this disposal is pending, so normally nobody else owns the
        // engine now; keep ownership of the process so Disconnect can retry.
        if core.attempt.is_some() {
            log.error(
                "vpn",
                "Cannot track the late openconnect: another attempt is active",
            );
            return;
        }
        let mut d = att.d();
        d.user_stopping = true;
        d.status_before_stop = Some(VpnStatus::Authenticating);
        d.proc = Some(handle);
        core.attempt = Some(att.clone());
        let mut next = VpnState::new(VpnStatus::Authenticating);
        next.profile_id = Some(att.profile.id.clone());
        next.gateways = non_empty_gateways(&d.gateways);
        next.error = Some(self.stop_failed_error());
        drop(d);
        self.set_state(&mut core, next);
    }

    fn on_attempt_error(self: &Arc<Self>, att: &Arc<Attempt>, err: AttemptError) {
        let AttemptError::Failed(err) = err else { return };
        let mut core = lock(&self.core);
        if !is_current(&core, att) {
            return;
        }
        let mut d = att.d();
        if d.user_stopping {
            return;
        }
        let info = ErrInfo {
            code: err.code,
            detail: Some(err.message.clone()),
            hint: err.hint,
        };
        self.deps.logger.error(
            "vpn",
            &format!("Connection attempt failed [{}]: {}", err.code, err.message),
        );
        if let Some(proc) = d.proc.clone() {
            // The process is running but we gave up on it: make sure it goes away.
            d.forced_error = Some(info);
            d.status_before_stop = Some(core.state.status);
            drop(d);
            drop(core);
            let _ = self.run_stop(att, proc);
            return;
        }
        self.finish_attempt(&mut core, att, &mut d);
        // A reconnect attempt that fails before spawning (network still down, prelogin
        // unreachable, …) keeps backing off like a failed process would.
        if att.is_reconnect && self.should_reconnect(&core, att, &d, &info) {
            self.schedule_reconnect(&mut core, att, &d, &info);
        } else {
            self.end_with_error(&mut core, att, &d, &info);
        }
    }

    fn on_process_exit(self: &Arc<Self>, att: &Arc<Attempt>, st: &mut PumpState, info: &ExitStatusInfo) {
        for s in &mut st.streams {
            let rest = s.decoder.finish();
            let mut lines = s.splitter.push(&rest);
            lines.extend(s.splitter.flush());
            for line in lines {
                self.on_line(att, &mut st.parser, &line);
            }
        }
        let code = info.code.map_or_else(|| "none".to_string(), |c| c.to_string());
        let signal = info
            .signal
            .as_deref()
            .map(|s| format!(", {s}"))
            .unwrap_or_default();
        self.deps
            .logger
            .info("vpn", &format!("openconnect exited (code {code}{signal})"));

        let mut core = lock(&self.core);
        if !is_current(&core, att) {
            return;
        }
        let mut d = att.d();
        self.finish_attempt(&mut core, att, &mut d);
        if d.user_stopping {
            drop(d);
            self.set_idle(&mut core, Some(att.profile.id.clone()));
            return;
        }
        let err = d
            .forced_error
            .clone()
            .or_else(|| d.pending_error.clone())
            .unwrap_or_else(|| classify_exit(att, &d, info));
        if self.should_reconnect(&core, att, &d, &err) {
            self.schedule_reconnect(&mut core, att, &d, &err);
        } else {
            self.end_with_error(&mut core, att, &d, &err);
        }
    }

    fn should_reconnect(&self, core: &Core, att: &Attempt, d: &AttemptData, err: &ErrInfo) -> bool {
        if !self.settings().auto_reconnect {
            return false;
        }
        if !d.ever_connected && !att.is_reconnect {
            return false;
        }
        if NON_RETRYABLE.contains(&err.code) {
            return false;
        }
        core.reconnect_count < self.deps.config.max_reconnect_attempts
    }

    fn schedule_reconnect(
        self: &Arc<Self>,
        core: &mut Core,
        att: &Arc<Attempt>,
        d: &AttemptData,
        err: &ErrInfo,
    ) {
        let delay = backoff_delay(core.reconnect_count, &self.deps.config.backoff);
        core.reconnect_count += 1;
        let secs = delay.as_secs_f64();
        self.deps.logger.warn(
            "vpn",
            &format!(
                "Connection lost [{}]; reconnect {}/{} in {secs}s",
                err.code, core.reconnect_count, self.deps.config.max_reconnect_attempts
            ),
        );
        let mut next = VpnState::new(VpnStatus::Reconnecting);
        next.profile_id = Some(att.profile.id.clone());
        next.gateways = non_empty_gateways(&d.gateways);
        next.error = Some(self.error_for(err));
        self.set_state(core, next);
        cancel_reconnect_timer(core);
        core.timer_gen += 1;
        let generation = core.timer_gen;
        let inner = self.clone();
        let att = att.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            inner.on_reconnect_timer(&att, generation);
        });
        core.reconnect_timer = Some((generation, task));
    }

    fn on_reconnect_timer(self: &Arc<Self>, att: &Attempt, generation: u64) {
        let mut core = lock(&self.core);
        if core.reconnect_timer.as_ref().map(|(g, _)| *g) != Some(generation) {
            return; // cancelled meanwhile
        }
        core.reconnect_timer = None;
        match self.deps.profiles.get_profile(&att.profile.id) {
            None => self.set_idle(&mut core, None),
            Some(profile) => self.start_attempt(&mut core, profile, att.opts.clone(), true),
        }
    }

    /// Common cleanup when an attempt is over (process gone or never started).
    fn finish_attempt(&self, core: &mut Core, att: &Arc<Attempt>, d: &mut AttemptData) {
        cancel_prompts(core, att.id);
        let session = core.session_password.as_ref().map(|(_, v)| v.clone());
        for s in d.secrets.drain(..) {
            if Some(&s) != session.as_ref() {
                self.deps.logger.secrets().delete(&s);
            }
        }
        if is_current(core, att) {
            core.attempt = None;
        }
    }

    fn end_with_error(&self, core: &mut Core, att: &Attempt, d: &AttemptData, err: &ErrInfo) {
        cancel_reconnect_timer(core);
        self.clear_session_password(core);
        let mut next = VpnState::new(VpnStatus::Error);
        next.profile_id = Some(att.profile.id.clone());
        next.gateways = non_empty_gateways(&d.gateways);
        next.error = Some(self.error_for(err));
        self.set_state(core, next);
    }

    fn set_idle(&self, core: &mut Core, profile_id: Option<String>) {
        let gateways = profile_id
            .as_ref()
            .and_then(|p| core.known_gateways.get(p))
            .and_then(|g| non_empty_gateways(g));
        let mut next = VpnState::new(VpnStatus::Disconnected);
        next.profile_id = profile_id;
        next.gateways = gateways;
        self.set_state(core, next);
    }

    fn error_for(&self, err: &ErrInfo) -> VpnStateError {
        let detail = error_detail(err.detail.as_deref().map(|d| self.mask(d)).as_deref());
        VpnStateError {
            code: err.code,
            message: error_message(err.code, self.settings().language, err.hint, self.deps.platform)
                .to_string(),
            detail,
            hint: err.hint,
        }
    }

    fn stop_failed_error(&self) -> VpnStateError {
        VpnStateError {
            code: VpnErrorCode::PrivilegesDenied,
            message: stop_failed_message(self.settings().language).to_string(),
            detail: None,
            hint: Some(VpnErrorHint::StopFailed),
        }
    }

    fn clear_session_password(&self, core: &mut Core) {
        if let Some((_, v)) = core.session_password.take() {
            self.deps.logger.secrets().delete(&v);
        }
    }

    // ---------------------------------------------------------------- prompts

    async fn ask(
        &self,
        att: &Arc<Attempt>,
        kind: PromptKind,
        message: &str,
        options: Option<&[String]>,
    ) -> AResult<Option<String>> {
        let mut raw_by_shown: HashMap<String, Vec<String>> = HashMap::new();
        let rx = {
            let mut core = lock(&self.core);
            assert_current(&core, att)?;
            // Prompt text may come straight from openconnect output: mask it like the log does.
            let shown_options = options.map(|opts| {
                opts.iter()
                    .map(|raw| {
                        let shown = self.mask(raw);
                        raw_by_shown.entry(shown.clone()).or_default().push(raw.clone());
                        shown
                    })
                    .collect::<Vec<_>>()
            });
            let prompt = AuthPrompt {
                id: (self.deps.new_id)(),
                kind,
                message: self.mask(message),
                options: shown_options,
            };
            let (tx, rx) = oneshot::channel();
            core.prompts.insert(
                prompt.id.clone(),
                PendingPrompt {
                    attempt_id: att.id,
                    tx,
                },
            );
            core.pending_prompts.push(prompt.clone());
            emit(&mut core, &EngineEvent::Prompt(prompt));
            rx
        };
        let value = rx.await.unwrap_or(None);
        self.check(att)?;
        Ok(match (value, options) {
            (Some(v), Some(_)) => Some(unmask_option(&v, &raw_by_shown)),
            (v, _) => v,
        })
    }

    // ---------------------------------------------------------------- state

    /// Translates a gateway value received from the UI (possibly masked) back to the raw
    /// name/address. Unknown values pass through; a masked value that matches several raw
    /// gateways is ambiguous → warning and no explicit selection.
    fn unmask_gateway(&self, core: &Core, profile_id: &str, value: Option<&str>) -> Option<String> {
        let value = value?;
        let raws = core.gateway_aliases.get(profile_id).and_then(|m| m.get(value));
        match raws {
            None => Some(value.to_string()),
            Some(r) if r.is_empty() || r.contains(value) => Some(value.to_string()),
            Some(r) if r.len() == 1 => r.first().cloned(),
            Some(_) => {
                self.deps.logger.warn(
                    "vpn",
                    &format!(
                        "Gateway \"{value}\" is ambiguous (several gateways look the same after hiding secrets); selecting automatically"
                    ),
                );
                None
            }
        }
    }

    fn set_state(&self, core: &mut Core, mut next: VpnState) {
        // Gateway names/addresses and the IP come from raw openconnect output.
        let mut aliases: Vec<(String, String)> = Vec::new();
        let mut mask_value = |raw: &str| {
            let shown = self.mask(raw);
            // Only real maskings are recorded (values re-emitted from the current state are
            // already masked and must not alias to themselves).
            if shown != raw {
                aliases.push((shown.clone(), raw.to_string()));
            }
            shown
        };
        let mut mask_gw = |g: &mut Gateway| {
            g.name = mask_value(&g.name);
            g.address = mask_value(&g.address);
        };
        if let Some(g) = next.gateway.as_mut() {
            mask_gw(g);
        }
        if let Some(list) = next.gateways.as_mut() {
            list.iter_mut().for_each(&mut mask_gw);
        }
        if let Some(ip) = next.assigned_ip.as_mut() {
            *ip = self.mask(ip);
        }
        if let Some(pid) = &next.profile_id {
            let map = core.gateway_aliases.entry(pid.clone()).or_default();
            for (shown, raw) in aliases {
                map.entry(shown).or_default().insert(raw);
            }
        }
        core.state = next.clone();
        emit(core, &EngineEvent::State(next));
    }
}

fn cancel_reconnect_timer(core: &mut Core) {
    if let Some((_, task)) = core.reconnect_timer.take() {
        task.abort();
    }
}

fn cancel_prompts(core: &mut Core, attempt_id: u64) {
    let ids: Vec<String> = core
        .prompts
        .iter()
        .filter(|(_, p)| p.attempt_id == attempt_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in ids {
        resolve_prompt(core, &id, None);
    }
}

fn release_disposal(core: &mut Core, d: &mut AttemptData) {
    if d.disposal_counted {
        d.disposal_counted = false;
        core.pending_disposals -= 1;
    }
}

fn emit(core: &mut Core, ev: &EngineEvent) {
    core.subscribers.retain(|s| s.send(ev.clone()).is_ok());
}

fn add_secret(logger: &Logger, d: &mut AttemptData, secret: &str) {
    d.secrets.push(secret.to_string());
    logger.secrets().add(secret);
}

/// Replace only on a strictly more specific code: within one code the first line is the root
/// cause ("getaddrinfo failed …", "Invalid username or password"); later lines of the same code
/// are generic follow-ups ("Failed to open HTTPS connection", "Login failed.").
fn record_error(d: &mut AttemptData, err: ErrInfo) {
    if d.pending_error
        .as_ref()
        .is_none_or(|cur| priority(err.code) < priority(cur.code))
    {
        d.pending_error = Some(err);
    }
}

fn current_gateway(att: &Attempt, d: &AttemptData) -> Option<Gateway> {
    let chosen = d.selected_gateway.as_ref().or(d.requested_gateway.as_ref());
    if let Some(name) = chosen {
        let key = name.to_lowercase();
        if let Some(g) = d
            .gateways
            .iter()
            .find(|g| g.name.to_lowercase() == key || g.address.to_lowercase() == key)
        {
            return Some(g.clone());
        }
        return Some(Gateway {
            name: name.clone(),
            address: name.clone(),
            priority: None,
        });
    }
    match d.gateways.len() {
        1 => Some(d.gateways[0].clone()),
        0 => {
            let host = url::Url::parse(&att.profile.portal_url).map_or_else(
                |_| att.profile.portal_url.clone(),
                |u| crate::validation::url_host(&u),
            );
            Some(Gateway {
                name: host.clone(),
                address: host,
                priority: None,
            })
        }
        _ => None,
    }
}

fn classify_exit(att: &Attempt, d: &AttemptData, info: &ExitStatusInfo) -> ErrInfo {
    // pkexec: 126 = dialog dismissed, 127 = not authorized.
    if matches!(info.code, Some(126 | 127)) {
        return ErrInfo::code(VpnErrorCode::PrivilegesDenied, d.last_message.clone());
    }
    if d.ever_connected || att.is_reconnect {
        return ErrInfo::code(
            VpnErrorCode::TunnelFailed,
            Some(d.last_message.clone().unwrap_or_else(|| "Connection lost".into())),
        );
    }
    let how = info
        .code
        .map(|c| c.to_string())
        .or_else(|| info.signal.clone())
        .unwrap_or_else(|| "unknown".into());
    ErrInfo::code(
        VpnErrorCode::Unknown,
        Some(
            d.last_message
                .clone()
                .unwrap_or_else(|| format!("openconnect exited with code {how}")),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmask_option_maps_back_or_rejects_ambiguity() {
        let mut m = HashMap::new();
        m.insert("***-GW".to_string(), vec!["Berlin-GW".to_string()]);
        assert_eq!(unmask_option("***-GW", &m), "Berlin-GW");
        assert_eq!(unmask_option("Munich-GW", &m), "Munich-GW");
        m.insert("***".to_string(), vec!["a1".into(), "a2".into()]);
        assert_eq!(unmask_option("***", &m), "");
        m.insert("x".to_string(), vec!["y".into(), "y".into()]);
        assert_eq!(unmask_option("x", &m), "y");
    }

    #[test]
    fn utf8_decoder_handles_split_and_invalid_sequences() {
        let mut d = Utf8Decoder::default();
        let bytes = "Пароль".as_bytes();
        let mut out = String::new();
        for b in bytes {
            out.push_str(&d.push(std::slice::from_ref(b)));
        }
        assert_eq!(out, "Пароль");
        assert_eq!(d.push(&[b'a', 0xff, b'b']), "a\u{fffd}b");
        assert_eq!(d.push(&[0xd0]), "");
        assert_eq!(d.finish(), "\u{fffd}");
    }

    #[test]
    fn engine_errors_have_public_markers() {
        assert_eq!(
            EngineError::ProfileNotFound.to_ipc_error(),
            "[field:profileId][code:not_found] Profile not found"
        );
        assert_eq!(
            EngineError::Busy(VpnStatus::Connected).to_ipc_error(),
            "[code:busy] Cannot connect while connected"
        );
        assert_eq!(
            EngineError::StillRunning.to_ipc_error(),
            "[code:busy] Cannot connect while openconnect is still running"
        );
        assert_eq!(
            EngineError::UnknownPrompt.to_ipc_error(),
            "[field:promptId][code:prompt_expired] Unknown or expired prompt"
        );
        assert_eq!(
            EngineError::MultiLineAnswer.to_ipc_error(),
            "[field:answer][code:invalid] Answer must be a single line"
        );
    }

    #[test]
    fn error_priority_order() {
        let mut d = AttemptData::default();
        record_error(
            &mut d,
            ErrInfo::code(VpnErrorCode::PortalUnreachable, Some("first".into())),
        );
        record_error(
            &mut d,
            ErrInfo::code(VpnErrorCode::PortalUnreachable, Some("second".into())),
        );
        assert_eq!(d.pending_error.as_ref().unwrap().detail.as_deref(), Some("first"));
        record_error(&mut d, ErrInfo::code(VpnErrorCode::TlsError, Some("tls".into())));
        assert_eq!(d.pending_error.as_ref().unwrap().code, VpnErrorCode::TlsError);
        record_error(&mut d, ErrInfo::code(VpnErrorCode::Unknown, None));
        assert_eq!(d.pending_error.as_ref().unwrap().code, VpnErrorCode::TlsError);
    }
}
