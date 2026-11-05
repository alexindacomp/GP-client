//! Test harness for `VpnEngine`: a scriptable
//! fake openconnect process and spawner, fakes for the other deps, and a player for recorded
//! openconnect transcripts (fixtures/openconnect/*.txt). Only the process boundary and the
//! injected services are fake; parser, logger, masking and the state machine are real.
//!
//! Time: tests run with `#[tokio::test(start_paused = true)]`; [`advance`] sleeps on the paused
//! clock (tokio auto-advances it, firing every engine timer that falls inside the interval, like
//! `vi.advanceTimersByTimeAsync`) and [`flush`] lets all ready tasks run.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use gp_core::clock::FixedClock;
use gp_core::logging::Logger;
use gp_core::prelogin::{PreloginClient, PreloginResult};
use gp_core::process::{
    Elevation, ExitStatusInfo, OutputChunk, ProcessSpawner, SpawnError, SpawnRequest, VpnProcess,
};
use gp_core::saml::{SamlAuthenticator, SamlCookieName, SamlSuccess};
use gp_core::vpn::{
    ElevatedFiles, EngineConfig, EngineDeps, EngineEvent, OpenconnectProvider, ProfileProvider,
    SettingsProvider, VpnEngine, VpnError,
};
use gp_core::{AuthMode, AuthPrompt, Platform, Profile, Settings, VpnErrorCode, VpnState, VpnStatus};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

pub const PROFILE_ID: &str = "11111111-2222-4333-8444-555555555555";
/// Longer than the engine's prompt debounce (150 ms).
pub const PROMPT_SETTLE_MS: u64 = 200;
pub const NOW_MS: i64 = 1_700_000_000_000;

// ------------------------------------------------------------------ time

/// Lets every ready task run (no time passes).
pub async fn flush() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

/// Advances the paused clock by `ms`, firing the timers due meanwhile, then flushes.
pub async fn advance(ms: u64) {
    flush().await;
    tokio::time::sleep(Duration::from_millis(ms)).await;
    flush().await;
}

// ------------------------------------------------------------------ fixtures

pub fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures_dir().join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// LF (or mixed) → CRLF.
pub fn to_crlf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

// ------------------------------------------------------------------ fake process

pub struct FakeProcState {
    written: Mutex<Vec<String>>,
    stop_calls: AtomicUsize,
    kill_calls: AtomicUsize,
    /// When false, stop() is ignored (simulates a hung openconnect).
    exit_on_stop: AtomicBool,
    /// When false, kill() is ignored too (e.g. both pkexec dialogs dismissed).
    exit_on_kill: AtomicBool,
    kill_error: Mutex<Option<String>>,
    write_error: Mutex<Option<String>>,
    out_tx: mpsc::Sender<OutputChunk>,
    exit_tx: Mutex<Option<oneshot::Sender<ExitStatusInfo>>>,
}

/// Test-side handle of a fake openconnect process.
#[derive(Clone)]
pub struct FakeProc(pub Arc<FakeProcState>);

impl FakeProc {
    pub fn out(&self, text: &str) {
        self.0
            .out_tx
            .try_send(OutputChunk::stdout(text.as_bytes()))
            .expect("output channel");
    }
    pub fn err(&self, text: &str) {
        self.0
            .out_tx
            .try_send(OutputChunk::stderr(text.as_bytes()))
            .expect("output channel");
    }
    pub fn exit(&self, code: i32) {
        self.exit_with(Some(code), None);
    }
    pub fn exit_signal(&self, signal: &str) {
        self.exit_with(None, Some(signal));
    }
    fn exit_with(&self, code: Option<i32>, signal: Option<&str>) {
        if let Some(tx) = self.0.exit_tx.lock().unwrap().take() {
            let _ = tx.send(ExitStatusInfo {
                code,
                signal: signal.map(String::from),
            });
        }
    }
    /// Everything written to stdin, in order.
    pub fn written(&self) -> Vec<String> {
        self.0.written.lock().unwrap().clone()
    }
    pub fn last_written(&self) -> Option<String> {
        self.written().last().cloned()
    }
    pub fn stop_calls(&self) -> usize {
        self.0.stop_calls.load(Ordering::SeqCst)
    }
    pub fn kill_calls(&self) -> usize {
        self.0.kill_calls.load(Ordering::SeqCst)
    }
    pub fn set_exit_on_stop(&self, v: bool) {
        self.0.exit_on_stop.store(v, Ordering::SeqCst);
    }
    pub fn set_exit_on_kill(&self, v: bool) {
        self.0.exit_on_kill.store(v, Ordering::SeqCst);
    }
    pub fn set_kill_error(&self, e: Option<&str>) {
        *self.0.kill_error.lock().unwrap() = e.map(String::from);
    }
    pub fn set_write_error(&self, e: Option<&str>) {
        *self.0.write_error.lock().unwrap() = e.map(String::from);
    }
    pub fn same(&self, other: &FakeProc) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// What the engine owns.
struct FakeProcess {
    st: Arc<FakeProcState>,
    out_rx: Option<mpsc::Receiver<OutputChunk>>,
    exit_rx: Option<oneshot::Receiver<ExitStatusInfo>>,
}

fn new_fake_process() -> (FakeProc, FakeProcess) {
    let (out_tx, out_rx) = mpsc::channel(1 << 16);
    let (exit_tx, exit_rx) = oneshot::channel();
    let st = Arc::new(FakeProcState {
        written: Mutex::new(vec![]),
        stop_calls: AtomicUsize::new(0),
        kill_calls: AtomicUsize::new(0),
        exit_on_stop: AtomicBool::new(true),
        exit_on_kill: AtomicBool::new(true),
        kill_error: Mutex::new(None),
        write_error: Mutex::new(None),
        out_tx,
        exit_tx: Mutex::new(Some(exit_tx)),
    });
    (
        FakeProc(st.clone()),
        FakeProcess {
            st,
            out_rx: Some(out_rx),
            exit_rx: Some(exit_rx),
        },
    )
}

#[async_trait]
impl VpnProcess for FakeProcess {
    fn pid(&self) -> Option<u32> {
        Some(4242)
    }
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(e) = self.st.write_error.lock().unwrap().clone() {
            return Err(io::Error::other(e));
        }
        self.st
            .written
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(data).into_owned());
        Ok(())
    }
    fn output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.out_rx.take().expect("output() called once")
    }
    /// Like a real process, the exit is reported asynchronously after the signal was sent.
    async fn stop(&mut self) -> io::Result<()> {
        self.st.stop_calls.fetch_add(1, Ordering::SeqCst);
        if self.st.exit_on_stop.load(Ordering::SeqCst) {
            FakeProc(self.st.clone()).exit(0);
        }
        Ok(())
    }
    async fn kill(&mut self) -> io::Result<()> {
        self.st.kill_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = self.st.kill_error.lock().unwrap().clone() {
            return Err(io::Error::other(e));
        }
        if self.st.exit_on_kill.load(Ordering::SeqCst) {
            FakeProc(self.st.clone()).exit_signal("SIGKILL");
        }
        Ok(())
    }
    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.exit_rx.take().expect("exited() called once")
    }
}

// ------------------------------------------------------------------ fake spawner

#[derive(Clone)]
enum Gate {
    Closed,
    Open,
    Fail(SpawnError),
}

type ProcHook = Box<dyn Fn(&FakeProc) + Send + Sync>;

#[derive(Default)]
pub struct FakeSpawner {
    requests: Mutex<Vec<SpawnRequest>>,
    processes: Mutex<Vec<FakeProc>>,
    fail_with: Mutex<Option<SpawnError>>,
    gate: Mutex<Option<(watch::Sender<Gate>, watch::Receiver<Gate>)>>,
    on_proc: Mutex<Option<ProcHook>>,
}

impl FakeSpawner {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `spawn` waits until [`Self::release`] (like a pending UAC/admin dialog).
    pub fn gated(on_proc: impl Fn(&FakeProc) + Send + Sync + 'static) -> Arc<Self> {
        let s = Self::default();
        *s.gate.lock().unwrap() = Some(watch::channel(Gate::Closed));
        *s.on_proc.lock().unwrap() = Some(Box::new(on_proc));
        Arc::new(s)
    }

    pub fn release(&self) {
        if let Some((tx, _)) = &*self.gate.lock().unwrap() {
            tx.send_replace(Gate::Open);
        }
    }

    /// The pending spawn fails.
    pub fn fail_pending(&self, e: SpawnError) {
        if let Some((tx, _)) = &*self.gate.lock().unwrap() {
            tx.send_replace(Gate::Fail(e));
        }
    }

    pub fn fail_with(&self, e: Option<SpawnError>) {
        *self.fail_with.lock().unwrap() = e;
    }

    pub fn requests(&self) -> Vec<SpawnRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn processes(&self) -> Vec<FakeProc> {
        self.processes.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.processes.lock().unwrap().len()
    }

    pub fn last(&self) -> FakeProc {
        self.processes
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("no process spawned")
    }
}

#[async_trait]
impl ProcessSpawner for FakeSpawner {
    async fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let gate = self.gate.lock().unwrap().as_ref().map(|(_, rx)| rx.clone());
        if let Some(mut rx) = gate {
            let state = rx
                .wait_for(|g| !matches!(g, Gate::Closed))
                .await
                .expect("gate")
                .clone();
            if let Gate::Fail(e) = state {
                return Err(e);
            }
        }
        self.requests.lock().unwrap().push(req);
        if let Some(e) = self.fail_with.lock().unwrap().clone() {
            return Err(e);
        }
        let (handle, proc) = new_fake_process();
        if let Some(hook) = &*self.on_proc.lock().unwrap() {
            hook(&handle);
        }
        self.processes.lock().unwrap().push(handle);
        Ok(Box::new(proc))
    }
}

// ------------------------------------------------------------------ other fakes

type Scripted<T> = Mutex<(VecDeque<Result<T, VpnError>>, Result<T, VpnError>)>;

fn next_scripted<T: Clone>(s: &Scripted<T>) -> Result<T, VpnError> {
    let mut g = s.lock().unwrap();
    g.0.pop_front().unwrap_or_else(|| g.1.clone())
}

pub struct FakePrelogin {
    script: Scripted<PreloginResult>,
    calls: AtomicUsize,
}

impl FakePrelogin {
    pub fn resolve(&self, r: PreloginResult) {
        self.script.lock().unwrap().1 = Ok(r);
    }
    pub fn reject(&self, e: VpnError) {
        self.script.lock().unwrap().1 = Err(e);
    }
    pub fn reject_once(&self, e: VpnError) {
        self.script.lock().unwrap().0.push_back(Err(e));
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PreloginClient for FakePrelogin {
    async fn prelogin(
        &self,
        _portal_url: &str,
        _cancel: CancellationToken,
    ) -> Result<PreloginResult, VpnError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        next_scripted(&self.script)
    }
}

pub struct FakeSaml {
    script: Scripted<SamlSuccess>,
    /// (profile id, prelogin) of each call.
    pub calls: Mutex<Vec<(String, PreloginResult)>>,
}

impl FakeSaml {
    pub fn resolve(&self, r: SamlSuccess) {
        self.script.lock().unwrap().1 = Ok(r);
    }
    pub fn reject(&self, e: VpnError) {
        self.script.lock().unwrap().1 = Err(e);
    }
    pub fn calls(&self) -> Vec<(String, PreloginResult)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SamlAuthenticator for FakeSaml {
    async fn saml_login(
        &self,
        profile: &Profile,
        prelogin: &PreloginResult,
        _cancel: CancellationToken,
    ) -> Result<SamlSuccess, VpnError> {
        self.calls
            .lock()
            .unwrap()
            .push((profile.id.clone(), prelogin.clone()));
        next_scripted(&self.script)
    }
}

pub struct FakeOc {
    pub binary: Mutex<Option<String>>,
    verify_once: Mutex<VecDeque<Result<ElevatedFiles, VpnError>>>,
    /// `None`: echo the input.
    verify_default: Mutex<Option<Result<ElevatedFiles, VpnError>>>,
    verify_calls: Mutex<Vec<ElevatedFiles>>,
}

impl FakeOc {
    pub fn set_binary(&self, b: Option<&str>) {
        *self.binary.lock().unwrap() = b.map(String::from);
    }
    pub fn verify_result(&self, r: Result<ElevatedFiles, VpnError>) {
        *self.verify_default.lock().unwrap() = Some(r);
    }
    pub fn verify_reject_once(&self, e: VpnError) {
        self.verify_once.lock().unwrap().push_back(Err(e));
    }
    pub fn verify_calls(&self) -> Vec<ElevatedFiles> {
        self.verify_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl OpenconnectProvider for FakeOc {
    async fn locate_openconnect(&self) -> Option<String> {
        self.binary.lock().unwrap().clone()
    }
    async fn verify_elevated_files(&self, files: &ElevatedFiles) -> Result<ElevatedFiles, VpnError> {
        self.verify_calls.lock().unwrap().push(files.clone());
        if let Some(r) = self.verify_once.lock().unwrap().pop_front() {
            return r;
        }
        self.verify_default
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Ok(files.clone()))
    }
}

struct Host {
    profile: Mutex<Profile>,
    profile_exists: AtomicBool,
    saved_password: Mutex<Option<String>>,
    settings: Mutex<Settings>,
}

impl ProfileProvider for Host {
    fn get_profile(&self, id: &str) -> Option<Profile> {
        let p = self.profile.lock().unwrap();
        (self.profile_exists.load(Ordering::SeqCst) && p.id == id).then(|| p.clone())
    }
    fn get_saved_password(&self, _profile_id: &str) -> Option<String> {
        self.saved_password.lock().unwrap().clone()
    }
}

impl SettingsProvider for Host {
    fn get_settings(&self) -> Settings {
        self.settings.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------------ harness

#[derive(Default)]
struct Collected {
    events: Vec<EngineEvent>,
}

pub struct Harness {
    pub engine: VpnEngine,
    pub spawner: Arc<FakeSpawner>,
    pub logger: Arc<Logger>,
    pub prelogin: Arc<FakePrelogin>,
    pub saml: Arc<FakeSaml>,
    pub oc: Arc<FakeOc>,
    host: Arc<Host>,
    rx: Mutex<mpsc::UnboundedReceiver<EngineEvent>>,
    collected: Mutex<Collected>,
}

pub fn password_prelogin() -> PreloginResult {
    PreloginResult::password()
}

pub fn default_saml() -> SamlSuccess {
    SamlSuccess {
        username: "alice@example.com".into(),
        cookie_name: SamlCookieName::PreloginCookie,
        cookie: "SAML-COOKIE-VALUE".into(),
    }
}

pub struct Builder {
    profile: Profile,
    settings: Settings,
    saved_password: Option<String>,
    config: EngineConfig,
    platform: Platform,
    logger: Option<Arc<Logger>>,
    spawner: Option<Arc<FakeSpawner>>,
    prelogin: Result<PreloginResult, VpnError>,
    saml: Result<SamlSuccess, VpnError>,
    binary: Option<String>,
}

impl Builder {
    pub fn profile(mut self, f: impl FnOnce(&mut Profile)) -> Self {
        f(&mut self.profile);
        self
    }
    pub fn settings(mut self, f: impl FnOnce(&mut Settings)) -> Self {
        f(&mut self.settings);
        self
    }
    pub fn saved_password(mut self, pw: &str) -> Self {
        self.saved_password = Some(pw.into());
        self
    }
    pub fn config(mut self, f: impl FnOnce(&mut EngineConfig)) -> Self {
        f(&mut self.config);
        self
    }
    pub fn platform(mut self, p: Platform) -> Self {
        self.platform = p;
        self
    }
    pub fn logger(mut self, l: Arc<Logger>) -> Self {
        self.logger = Some(l);
        self
    }
    pub fn spawner(mut self, s: Arc<FakeSpawner>) -> Self {
        self.spawner = Some(s);
        self
    }
    pub fn prelogin(mut self, r: Result<PreloginResult, VpnError>) -> Self {
        self.prelogin = r;
        self
    }
    pub fn saml(mut self, r: Result<SamlSuccess, VpnError>) -> Self {
        self.saml = r;
        self
    }
    pub fn binary(mut self, b: Option<&str>) -> Self {
        self.binary = b.map(String::from);
        self
    }

    pub fn build(self) -> Harness {
        let spawner = self.spawner.unwrap_or_default();
        let logger = self.logger.unwrap_or_else(|| Arc::new(Logger::in_memory()));
        let host = Arc::new(Host {
            profile: Mutex::new(self.profile),
            profile_exists: AtomicBool::new(true),
            saved_password: Mutex::new(self.saved_password),
            settings: Mutex::new(self.settings),
        });
        let prelogin = Arc::new(FakePrelogin {
            script: Mutex::new((VecDeque::new(), self.prelogin)),
            calls: AtomicUsize::new(0),
        });
        let saml = Arc::new(FakeSaml {
            script: Mutex::new((VecDeque::new(), self.saml)),
            calls: Mutex::new(vec![]),
        });
        let oc = Arc::new(FakeOc {
            binary: Mutex::new(self.binary),
            verify_once: Mutex::new(VecDeque::new()),
            verify_default: Mutex::new(None),
            verify_calls: Mutex::new(vec![]),
        });
        let n = Arc::new(AtomicUsize::new(0));
        let deps = EngineDeps {
            platform: self.platform,
            elevation: Elevation::Pkexec,
            profiles: host.clone(),
            settings: host.clone(),
            prelogin: prelogin.clone(),
            saml: saml.clone(),
            openconnect: oc.clone(),
            spawner: spawner.clone(),
            logger: logger.clone(),
            clock: Arc::new(FixedClock(NOW_MS)),
            new_id: Arc::new(move || {
                format!(
                    "00000000-0000-4000-8000-{:012}",
                    n.fetch_add(1, Ordering::SeqCst) + 1
                )
            }),
            config: self.config,
        };
        let engine = VpnEngine::new(deps);
        let rx = engine.subscribe();
        Harness {
            engine,
            spawner,
            logger,
            prelogin,
            saml,
            oc,
            host,
            rx: Mutex::new(rx),
            collected: Mutex::new(Collected::default()),
        }
    }
}

pub fn harness() -> Builder {
    Builder {
        profile: Profile {
            id: PROFILE_ID.into(),
            name: "Work".into(),
            portal_url: "https://vpn.example.com".into(),
            username: Some("alice".into()),
            auth_mode: AuthMode::Password,
            preferred_gateway: None,
            save_password: false,
        },
        settings: Settings {
            auto_reconnect: true,
            ..Settings::default()
        },
        saved_password: None,
        config: EngineConfig::default(),
        platform: Platform::Linux,
        logger: None,
        spawner: None,
        prelogin: Ok(password_prelogin()),
        saml: Err(VpnError::new(VpnErrorCode::Unknown, "samlLogin not configured")),
        binary: Some("/usr/sbin/openconnect".into()),
    }
}

impl Harness {
    fn drain(&self) {
        let mut rx = self.rx.lock().unwrap();
        let mut c = self.collected.lock().unwrap();
        while let Ok(ev) = rx.try_recv() {
            c.events.push(ev);
        }
    }

    /// Every state emitted so far.
    pub fn states(&self) -> Vec<VpnState> {
        self.drain();
        self.collected
            .lock()
            .unwrap()
            .events
            .iter()
            .filter_map(|e| {
                if let EngineEvent::State(s) = e {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Every prompt emitted so far.
    pub fn prompts(&self) -> Vec<AuthPrompt> {
        self.drain();
        self.collected
            .lock()
            .unwrap()
            .events
            .iter()
            .filter_map(|e| {
                if let EngineEvent::Prompt(p) = e {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn statuses(&self) -> Vec<VpnStatus> {
        self.states().iter().map(|s| s.status).collect()
    }

    /// Consecutive duplicates removed: the status path the user sees.
    pub fn status_path(&self) -> Vec<VpnStatus> {
        let mut out = self.statuses();
        out.dedup();
        out
    }

    pub fn state(&self) -> VpnState {
        self.engine.get_state()
    }

    pub fn status(&self) -> VpnStatus {
        self.state().status
    }

    pub fn error_code(&self) -> Option<VpnErrorCode> {
        self.state().error.map(|e| e.code)
    }

    pub fn log_text(&self) -> String {
        self.logger.lines().join("\n")
    }

    pub fn set_language(&self, l: gp_core::Language) {
        self.host.settings.lock().unwrap().language = l;
    }

    pub fn set_saved_password(&self, pw: Option<&str>) {
        *self.host.saved_password.lock().unwrap() = pw.map(String::from);
    }

    pub fn set_profile_exists(&self, v: bool) {
        self.host.profile_exists.store(v, Ordering::SeqCst);
    }

    pub fn connect(&self) {
        self.engine
            .connect(PROFILE_ID, gp_core::ConnectOptions::default())
            .expect("connect accepted");
    }

    pub fn connect_with(&self, opts: gp_core::ConnectOptions) {
        self.engine.connect(PROFILE_ID, opts).expect("connect accepted");
    }

    pub fn answer(&self, id: &str, value: Option<&str>) {
        self.engine
            .answer_prompt(id, value.map(String::from))
            .expect("answer accepted");
    }

    /// Starts `disconnect()` in the background; await the handle to join it.
    pub fn disconnect_bg(&self) -> tokio::task::JoinHandle<()> {
        let e = self.engine.clone();
        tokio::spawn(async move { e.disconnect().await })
    }
}

// ------------------------------------------------------------------ transcripts

/// One step of a recorded openconnect session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Complete line(s) on stdout / stderr.
    Out { stderr: bool, text: String },
    /// A newline-less fragment on stderr; openconnect now waits for stdin.
    Prompt { text: String },
}

/// Parses a transcript fixture. Format, one entry per line:
/// `# …` comment, `! text` → stderr line, `? Label:` → prompt on stderr without newline,
/// anything else → stdout line. With `crlf` every line ends in CRLF and every prompt in a lone
/// CR, like output from openconnect.exe / the Windows helper.
pub fn load_transcript(name: &str, crlf: bool) -> Vec<Step> {
    let text = fixture(&format!("openconnect/{name}"));
    let source = if crlf { to_crlf(&text) } else { text };
    let mut steps = Vec::new();
    for raw in source.split('\n') {
        if raw.starts_with('#') || raw.is_empty() || raw == "\r" {
            continue;
        }
        if let Some(t) = raw.strip_prefix("? ") {
            steps.push(Step::Prompt { text: t.into() });
        } else if let Some(t) = raw.strip_prefix("! ") {
            steps.push(Step::Out {
                stderr: true,
                text: format!("{t}\n"),
            });
        } else {
            steps.push(Step::Out {
                stderr: false,
                text: format!("{raw}\n"),
            });
        }
    }
    steps
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlayOptions {
    /// Re-chunk the output at this many characters, ignoring line boundaries (consecutive
    /// steps on the same stream are merged first), like pipe reads do.
    pub chunk_size: Option<usize>,
    /// Deliver each prompt in two chunks this many ms apart (must stay below the 150 ms debounce).
    pub split_prompt_gap_ms: Option<u64>,
}

fn emit(proc: &FakeProc, stderr: bool, text: &str, chunk_size: Option<usize>) {
    let chars: Vec<char> = text.chars().collect();
    let size = chunk_size.unwrap_or(chars.len()).max(1);
    for chunk in chars.chunks(size) {
        let s: String = chunk.iter().collect();
        if stderr { proc.err(&s) } else { proc.out(&s) }
    }
}

/// Replays steps until (and including) the next prompt, then waits past the prompt debounce.
/// Returns the remaining steps.
pub async fn play_until_prompt(proc: &FakeProc, steps: &[Step], opts: PlayOptions) -> Vec<Step> {
    let mut pending: Option<(bool, String)> = None;
    let flush_pending = |pending: &mut Option<(bool, String)>| {
        if let Some((stderr, text)) = pending.take() {
            emit(proc, stderr, &text, opts.chunk_size);
        }
    };
    let mut i = 0;
    while i < steps.len() {
        match &steps[i] {
            Step::Prompt { text } => {
                flush_pending(&mut pending);
                if let Some(gap) = opts.split_prompt_gap_ms {
                    let chars: Vec<char> = text.chars().collect();
                    let mid = chars.len().div_ceil(2);
                    emit(
                        proc,
                        true,
                        &chars[..mid].iter().collect::<String>(),
                        opts.chunk_size,
                    );
                    advance(gap).await;
                    emit(
                        proc,
                        true,
                        &chars[mid..].iter().collect::<String>(),
                        opts.chunk_size,
                    );
                } else {
                    emit(proc, true, text, opts.chunk_size);
                }
                i += 1;
                break;
            }
            Step::Out { stderr, text } => {
                if opts.chunk_size.is_none() {
                    emit(proc, *stderr, text, None);
                } else if let Some((s, t)) = pending.as_mut().filter(|(s, _)| s == stderr) {
                    let _ = s;
                    t.push_str(text);
                } else {
                    flush_pending(&mut pending);
                    pending = Some((*stderr, text.clone()));
                }
            }
        }
        i += 1;
    }
    flush_pending(&mut pending);
    advance(PROMPT_SETTLE_MS).await;
    steps[i.min(steps.len())..].to_vec()
}

/// Replays all remaining steps (prompts included, each followed by the debounce).
pub async fn play_all(proc: &FakeProc, steps: &[Step], opts: PlayOptions) {
    let mut rest = steps.to_vec();
    while !rest.is_empty() {
        rest = play_until_prompt(proc, &rest, opts).await;
    }
}
