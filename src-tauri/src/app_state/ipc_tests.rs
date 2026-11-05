//! End-to-end tests of the Tauri command layer: every `GpApi` command is invoked through Tauri's real IPC entry point
//! (`Webview::on_message`: invoke key, origin/ACL check, argument deserialization, command
//! dispatch, response serialization) against a real `AppState` built from the real stores, logger
//! and `VpnEngine`.
//!
//! Fake: only the process boundary (openconnect spawner), the portal prelogin, the SAML window,
//! openconnect discovery for the engine and the OS keystore (`MemorySecretStore`). Data, logs and
//! SSO data live in a temp dir.
//!
//! Runs on every OS: the commands are generic over the Tauri runtime, so the app under test uses
//! `tauri::test::MockRuntime` (no webview, no display). The tests are serialized (one app at a
//! time) and pump the event loop while they wait.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use gp_core::logging::{DEFAULT_CAPACITY, LOG_FILE_NAME, Logger};
use gp_core::platform::Platform;
use gp_core::prelogin::{PreloginClient, PreloginResult, parse_prelogin};
use gp_core::process::{
    Elevation, ExitStatusInfo, OutputChunk, ProcessSpawner, SpawnError, SpawnRequest, VpnProcess,
};
use gp_core::saml::{SamlAuthenticator, SamlOutcome, SamlSuccess, extract_saml_from_html};
use gp_core::store::confirm_dialog::{ConfirmDialog, ConfirmDialogText};
use gp_core::store::confirmed_settings::ConfirmedSettingsGuard;
use gp_core::store::profiles::ProfilesStore;
use gp_core::store::secret_store::MemorySecretStore;
use gp_core::store::settings::{SettingsStore, WarningFn};
use gp_core::types::{AuthPrompt, Profile, PromptKind, VpnErrorCode, VpnState, VpnStatus};
use gp_core::validation::parse_ipc_error;
use gp_core::vpn::engine::EngineEvent;
use gp_core::vpn::{ElevatedFiles, EngineDeps, OpenconnectProvider, VpnEngine, VpnError};
use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody, InvokeResponse};
use tauri::test::MockRuntime;
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::{AppState, StoreProfiles, StoreSettings};
use crate::discovery::Discovery;
use crate::saml::SamlSessions;
use crate::window::MAIN;

/// A second webview of the app (the SAML window's role): must never be served.
const OTHER: &str = "saml";
/// Origin of the bundled UI (`is_app_url` in window.rs): Tauri's custom protocol URL.
#[cfg(any(windows, target_os = "android"))]
const APP_ORIGIN: &str = "http://tauri.localhost/";
#[cfg(not(any(windows, target_os = "android")))]
const APP_ORIGIN: &str = "tauri://localhost/";
const UNKNOWN_ID: &str = "3f2b8c4e-1d2a-4b5c-8d9e-0f1a2b3c4d5e";
const WAIT: Duration = Duration::from_secs(20);

const PASSWORD: &str = "Hunter2-Pa$$word!";
const OTP: &str = "918273";
/// A plausible openconnect location of the OS running the tests (the engine only passes it on to
/// the fake spawner; the settings validators accept it on every OS).
#[cfg(windows)]
const OC_PATH: &str = r"C:\Program Files\OpenConnect\openconnect.exe";
#[cfg(not(windows))]
const OC_PATH: &str = "/usr/sbin/openconnect";
/// `SystemInfo.platform` of the OS running the tests.
const PLATFORM: &str = if cfg!(windows) {
    "win32"
} else if cfg!(target_os = "macos") {
    "darwin"
} else {
    "linux"
};

/// `<prelogin-cookie>` of fixtures/saml-success.html.
const COOKIE: &str = "PRELOGIN-COOKIE-abc123XYZ";

/// Every registered command (same list as `generate_handler!` in main.rs; the vitest contract
/// test checks that list against the renderer bridge).
const COMMANDS: [&str; 14] = [
    "profiles_list",
    "profiles_save",
    "profiles_remove",
    "vpn_connect",
    "vpn_disconnect",
    "vpn_get_state",
    "vpn_answer_prompt",
    "vpn_get_pending_prompts",
    "logs_get",
    "logs_open_folder",
    "settings_get",
    "settings_set",
    "system_info",
    "system_open_external",
];

/// One app under test at a time (shared tracing/async runtime, global keyed state).
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

/// `encodeURIComponent`.
fn encode_uri_component(s: &str) -> String {
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

// ------------------------------------------------------------------ fakes (process boundary)

struct ProcShared {
    written: Mutex<Vec<String>>,
    out_tx: mpsc::Sender<OutputChunk>,
    exit_tx: Mutex<Option<oneshot::Sender<ExitStatusInfo>>>,
}

/// Test-side handle of a fake openconnect process.
#[derive(Clone)]
struct Proc(Arc<ProcShared>);

impl Proc {
    fn stdout(&self, text: &str) {
        self.0
            .out_tx
            .try_send(OutputChunk::stdout(text.as_bytes()))
            .unwrap();
    }
    fn stderr(&self, text: &str) {
        self.0
            .out_tx
            .try_send(OutputChunk::stderr(text.as_bytes()))
            .unwrap();
    }
    fn exit(&self, code: i32) {
        if let Some(tx) = self.0.exit_tx.lock().unwrap().take() {
            let _ = tx.send(ExitStatusInfo {
                code: Some(code),
                signal: None,
            });
        }
    }
    fn written(&self) -> Vec<String> {
        self.0.written.lock().unwrap().clone()
    }
}

struct FakeProcess {
    shared: Arc<ProcShared>,
    out_rx: Option<mpsc::Receiver<OutputChunk>>,
    exit_rx: Option<oneshot::Receiver<ExitStatusInfo>>,
}

#[async_trait]
impl VpnProcess for FakeProcess {
    fn pid(&self) -> Option<u32> {
        Some(4242)
    }
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.shared
            .written
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(data).into_owned());
        Ok(())
    }
    fn output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.out_rx.take().expect("output() called once")
    }
    async fn stop(&mut self) -> std::io::Result<()> {
        Proc(self.shared.clone()).exit(0);
        Ok(())
    }
    async fn kill(&mut self) -> std::io::Result<()> {
        Proc(self.shared.clone()).exit(137);
        Ok(())
    }
    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.exit_rx.take().expect("exited() called once")
    }
}

#[derive(Default)]
struct FakeSpawner {
    requests: Mutex<Vec<SpawnRequest>>,
    procs: Mutex<Vec<Proc>>,
}

impl FakeSpawner {
    fn procs(&self) -> Vec<Proc> {
        self.procs.lock().unwrap().clone()
    }
}

#[async_trait]
impl ProcessSpawner for FakeSpawner {
    async fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let (out_tx, out_rx) = mpsc::channel(1 << 12);
        let (exit_tx, exit_rx) = oneshot::channel();
        let shared = Arc::new(ProcShared {
            written: Mutex::new(vec![]),
            out_tx,
            exit_tx: Mutex::new(Some(exit_tx)),
        });
        self.requests.lock().unwrap().push(req);
        self.procs.lock().unwrap().push(Proc(shared.clone()));
        Ok(Box::new(FakeProcess {
            shared,
            out_rx: Some(out_rx),
            exit_rx: Some(exit_rx),
        }))
    }
}

struct FakePrelogin(PreloginResult);

#[async_trait]
impl PreloginClient for FakePrelogin {
    async fn prelogin(
        &self,
        _portal_url: &str,
        _cancel: CancellationToken,
    ) -> Result<PreloginResult, VpnError> {
        Ok(self.0.clone())
    }
}

struct FakeSaml(Option<SamlSuccess>);

#[async_trait]
impl SamlAuthenticator for FakeSaml {
    async fn saml_login(
        &self,
        _profile: &Profile,
        _prelogin: &PreloginResult,
        _cancel: CancellationToken,
    ) -> Result<SamlSuccess, VpnError> {
        self.0
            .clone()
            .ok_or_else(|| VpnError::new(VpnErrorCode::Unknown, "SAML not expected in this test"))
    }
}

/// The native confirmation dialog: answers as configured and records what was shown.
#[derive(Default)]
struct FakeDialog {
    accept: AtomicBool,
    shown: Mutex<Vec<ConfirmDialogText>>,
}

#[async_trait]
impl ConfirmDialog for FakeDialog {
    async fn confirm(&self, text: &ConfirmDialogText) -> bool {
        self.shown.lock().unwrap().push(text.clone());
        self.accept.load(Ordering::SeqCst)
    }
}

struct FakeOpenconnect;

#[async_trait]
impl OpenconnectProvider for FakeOpenconnect {
    async fn locate_openconnect(&self) -> Option<String> {
        Some(OC_PATH.into())
    }
    async fn verify_elevated_files(&self, files: &ElevatedFiles) -> Result<ElevatedFiles, VpnError> {
        Ok(files.clone())
    }
}

// ------------------------------------------------------------------ the app under test

struct Ctx {
    app: App<MockRuntime>,
    tmp: tempfile::TempDir,
    dialog: Arc<FakeDialog>,
    secrets: Arc<MemorySecretStore>,
    spawner: Arc<FakeSpawner>,
    /// What the app pushes to the UI: every log line (`gp:logs:line`) and every engine event
    /// (`gp:vpn:state` / `gp:vpn:prompt` payloads), serialized like `emit_to` does.
    pushed: Arc<Mutex<Vec<String>>>,
    events: mpsc::UnboundedReceiver<EngineEvent>,
    /// Every command result (value or error string) returned over IPC.
    responses: Vec<String>,
    _serial: MutexGuard<'static, ()>,
}

fn ctx() -> Ctx {
    ctx_with(PreloginResult::password(), None)
}

fn ctx_with(prelogin: PreloginResult, saml: Option<SamlSuccess>) -> Ctx {
    let serial = serial();
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let app = tauri::test::mock_builder()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            crate::commands::profiles_list,
            crate::commands::profiles_save,
            crate::commands::profiles_remove,
            crate::commands::vpn_connect,
            crate::commands::vpn_disconnect,
            crate::commands::vpn_get_state,
            crate::commands::vpn_answer_prompt,
            crate::commands::vpn_get_pending_prompts,
            crate::commands::logs_get,
            crate::commands::logs_open_folder,
            crate::commands::settings_get,
            crate::commands::settings_set,
            crate::commands::system_info,
            crate::commands::system_open_external,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("build the test app");

    let logger = Arc::new(Logger::new(Some(&tmp.path().join("logs")), DEFAULT_CAPACITY));
    let warn: WarningFn = {
        let logger = logger.clone();
        Arc::new(move |m: &str| logger.warn("test", m))
    };
    let secrets = Arc::new(MemorySecretStore::new());
    let settings = Arc::new(SettingsStore::open(data_dir.join("settings.json"), warn.as_ref()));
    let profiles = Arc::new(ProfilesStore::open(
        data_dir.join("profiles.json"),
        secrets.clone(),
        warn.clone(),
    ));
    let guard = Arc::new(ConfirmedSettingsGuard::open(
        data_dir.join("confirmed-settings.json"),
        secrets.clone(),
        warn,
    ));
    let spawner = Arc::new(FakeSpawner::default());
    let mut deps = EngineDeps::new(
        Platform::current(),
        Elevation::Uac,
        Arc::new(StoreProfiles(profiles.clone())),
        Arc::new(StoreSettings(settings.clone())),
        Arc::new(FakePrelogin(prelogin)),
        Arc::new(FakeSaml(saml)),
        Arc::new(FakeOpenconnect),
        spawner.clone(),
        logger.clone(),
    );
    // Real time drives the engine here (the Tauri runtime cannot be paused); keep the prompt
    // debounce short so the tests stay fast. Waits poll for a condition, never a fixed delay.
    deps.config.prompt_debounce = Duration::from_millis(30);
    let engine = VpnEngine::new(deps);
    let events = engine.subscribe();

    let pushed = Arc::new(Mutex::new(Vec::new()));
    {
        let pushed = pushed.clone();
        logger.on_line(move |line| pushed.lock().unwrap().push(json!(line).to_string()));
    }

    let dialog = Arc::new(FakeDialog::default());
    app.manage(AppState::new(
        logger.clone(),
        settings.clone(),
        profiles,
        guard,
        dialog.clone(),
        Arc::new(Discovery::new(Platform::current(), settings, None, logger)),
        engine,
        tmp.path().join("logs"),
        tmp.path().join("saml"),
        Arc::new(SamlSessions::default()),
    ));

    for label in [MAIN, OTHER] {
        WebviewWindowBuilder::new(&app, label, WebviewUrl::App("index.html".into()))
            .visible(false)
            .build()
            .unwrap_or_else(|e| panic!("create the {label} webview: {e}"));
    }

    Ctx {
        app,
        tmp,
        dialog,
        secrets,
        spawner,
        pushed,
        events,
        responses: Vec::new(),
        _serial: serial,
    }
}

impl Ctx {
    fn st(&self) -> tauri::State<'_, AppState> {
        self.app.state::<AppState>()
    }

    fn data(&self, name: &str) -> PathBuf {
        self.tmp.path().join("data").join(name)
    }

    /// Runs the event loop until `f` yields a value (commands run on the async runtime; window
    /// getters/setters they call need the event loop).
    fn pump_until<T>(&mut self, what: &str, mut f: impl FnMut(&Self) -> Option<T>) -> T {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(v) = f(self) {
                return v;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            // Deprecated for busy-looping; here the loop is bounded by a condition and a deadline,
            // and `run_return` would block until the app exits.
            #[allow(deprecated)]
            self.app.run_iteration(|_, _| {});
            std::thread::yield_now();
        }
    }

    /// Invokes `cmd` like `@tauri-apps/api` does from the webview `label` loaded from `origin`.
    fn invoke_at(&mut self, label: &str, origin: &str, cmd: &str, args: Value) -> Result<Value, String> {
        let webview = self
            .app
            .get_webview_window(label)
            .unwrap_or_else(|| panic!("no webview {label}"));
        let (tx, rx) = std::sync::mpsc::channel();
        webview.on_message(
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(1),
                error: CallbackFn(2),
                url: origin.parse().unwrap(),
                body: InvokeBody::Json(args),
                headers: tauri::http::HeaderMap::default(),
                invoke_key: self.app.invoke_key().to_string(),
            },
            Box::new(move |_webview, _cmd, response, _callback, _error| {
                let _ = tx.send(response);
            }),
        );
        let response = self.pump_until(cmd, |_| rx.try_recv().ok());
        let result = match response {
            InvokeResponse::Ok(body) => Ok(body.deserialize::<Value>().unwrap()),
            InvokeResponse::Err(e) => Err(match e.0 {
                Value::String(s) => s,
                other => other.to_string(),
            }),
        };
        self.responses.push(format!("{result:?}"));
        result
    }

    fn invoke(&mut self, cmd: &str, args: Value) -> Result<Value, String> {
        self.invoke_at(MAIN, APP_ORIGIN, cmd, args)
    }

    fn ok(&mut self, cmd: &str, args: Value) -> Value {
        self.invoke(cmd, args)
            .unwrap_or_else(|e| panic!("{cmd} failed: {e}"))
    }

    /// The `[field:..][code:..]` markers of a failed command.
    fn markers(&mut self, cmd: &str, args: Value) -> (Option<String>, Option<String>) {
        let err = match self.invoke(cmd, args) {
            Ok(v) => panic!("{cmd} unexpectedly succeeded: {v}"),
            Err(e) => e,
        };
        let info = parse_ipc_error(&err);
        assert!(
            !info.message.is_empty() && !info.message.starts_with('['),
            "{cmd}: malformed error {err:?}"
        );
        (info.field, info.code)
    }

    fn log_text(&self) -> String {
        self.st().logger.lines().join("\n")
    }

    /// Moves engine events into the UI sink (what the setup hook forwards with `emit_to(MAIN)`).
    fn drain_events(&mut self) {
        while let Ok(ev) = self.events.try_recv() {
            let payload = match ev {
                EngineEvent::State(s) => serde_json::to_string(&s).unwrap(),
                EngineEvent::Prompt(p) => serde_json::to_string(&p).unwrap(),
            };
            self.pushed.lock().unwrap().push(payload);
        }
    }

    fn status(&self) -> VpnStatus {
        self.st().engine.get_state().status
    }

    fn wait_status(&mut self, want: VpnStatus) {
        self.pump_until(&format!("status {want:?}"), |c| {
            (c.status() == want).then_some(())
        });
    }

    fn proc(&mut self) -> Proc {
        self.pump_until("openconnect spawn", |c| c.spawner.procs().last().cloned())
    }

    fn wait_written(&mut self, proc: &Proc, n: usize) -> Vec<String> {
        self.pump_until(&format!("{n} stdin writes"), |_| {
            let w = proc.written();
            (w.len() >= n).then_some(w)
        })
    }

    fn wait_log(&mut self, needle: &str) {
        self.pump_until(&format!("log line with {needle:?}"), |c| {
            c.log_text().contains(needle).then_some(())
        });
    }

    fn save_profile(&mut self, profile: &Value, password: Option<&str>) -> Value {
        let mut args = json!({ "profile": profile });
        if let Some(p) = password {
            args["password"] = json!(p);
        }
        self.ok("profiles_save", args)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // Stop a running fake openconnect so no engine task outlives the app.
        let engine = self.st().engine.clone();
        tauri::async_runtime::block_on(engine.shutdown());
    }
}

fn profile_input(name: &str) -> Value {
    json!({ "name": name, "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false })
}

fn field(f: &str, c: &str) -> (Option<String>, Option<String>) {
    (Some(f.into()), Some(c.into()))
}

fn code(c: &str) -> (Option<String>, Option<String>) {
    (None, Some(c.into()))
}

fn id_of(profile: &Value) -> String {
    profile["id"].as_str().expect("profile id").to_string()
}

/// Valid arguments for every command (used to prove the sender check runs before anything else).
fn valid_args(cmd: &str) -> Value {
    match cmd {
        "profiles_save" => json!({ "profile": profile_input("X"), "password": "pw" }),
        "profiles_remove" => json!({ "id": UNKNOWN_ID }),
        "vpn_connect" => json!({ "profileId": UNKNOWN_ID }),
        "vpn_answer_prompt" => json!({ "id": UNKNOWN_ID, "value": "1" }),
        "settings_set" => json!({ "patch": { "theme": "dark" } }),
        "system_open_external" => json!({ "url": "https://example.com/" }),
        _ => json!({}),
    }
}

// ------------------------------------------------------------------ sender validation

#[test]
fn every_command_rejects_a_webview_other_than_main_without_side_effects() {
    let mut c = ctx();

    for cmd in COMMANDS {
        let r = c.invoke_at(OTHER, APP_ORIGIN, cmd, valid_args(cmd));
        assert_eq!(r, Err("Untrusted sender".to_string()), "{cmd}");
    }

    let log = c.log_text();
    for cmd in COMMANDS {
        assert!(
            log.contains(&format!("Rejected {cmd} from untrusted sender")),
            "{cmd} rejection not logged"
        );
    }
    assert!(c.st().profiles.list().is_empty(), "profiles_save ran");
    assert_eq!(
        c.st().settings.get().theme,
        gp_core::types::Theme::System,
        "settings_set ran"
    );
    assert!(c.spawner.procs().is_empty(), "vpn_connect ran");
}

#[test]
fn the_main_webview_on_a_remote_origin_is_refused() {
    let mut c = ctx();
    for cmd in ["settings_set", "profiles_save", "logs_get"] {
        let r = c.invoke_at(MAIN, "https://evil.example.com/", cmd, valid_args(cmd));
        assert!(r.is_err(), "{cmd} served a remote origin: {r:?}");
    }
    assert!(c.st().profiles.list().is_empty());
    assert_eq!(c.st().settings.get().theme, gp_core::types::Theme::System);
}

// ------------------------------------------------------------------ profiles

#[test]
fn profiles_save_list_and_update_keep_the_password_in_the_keystore_only() {
    let mut c = ctx();
    assert_eq!(c.ok("profiles_list", json!({})), json!([]));

    let mut input = profile_input("Office");
    input["username"] = json!("alice");
    input["savePassword"] = json!(true);
    let saved = c.save_profile(&input, Some(PASSWORD));
    let id = id_of(&saved);
    assert_eq!(saved["portalUrl"], "https://vpn.example.com");
    assert_eq!(saved["name"], "Office");
    assert!(saved.get("password").is_none(), "{saved}");
    assert_eq!(c.ok("profiles_list", json!({})), json!([saved.clone()]));

    // Stored in the keystore, never in profiles.json or a response.
    assert!(c.secrets.snapshot().values().any(|v| v == PASSWORD));
    let on_disk = std::fs::read_to_string(c.data("profiles.json")).unwrap();
    assert!(on_disk.contains(&id) && !on_disk.contains(PASSWORD), "{on_disk}");
    assert_eq!(c.st().profiles.get_password(&id).as_deref(), Some(PASSWORD));

    // Update by id; an absent password keeps the stored one.
    input["id"] = json!(id.to_uppercase());
    input["name"] = json!("Office 2");
    let updated = c.save_profile(&input, None);
    assert_eq!(
        (id_of(&updated), updated["name"].clone()),
        (id.clone(), json!("Office 2"))
    );
    assert_eq!(c.ok("profiles_list", json!({})).as_array().unwrap().len(), 1);
    assert_eq!(c.st().profiles.get_password(&id).as_deref(), Some(PASSWORD));

    assert!(!c.responses.join("\n").contains(PASSWORD));
}

#[test]
fn profiles_save_reports_invalid_input_with_markers() {
    let mut c = ctx();
    let bad = |f: &str, v: Value| {
        let mut p = profile_input("X");
        p[f] = v;
        json!({ "profile": p })
    };
    let cases = [
        (json!({}), code("invalid_type")),
        (json!({ "profile": "x" }), code("invalid_type")),
        (
            bad("portalUrl", json!("http://vpn.example.com")),
            field("portalUrl", "not_https"),
        ),
        (bad("portalUrl", json!("")), field("portalUrl", "required")),
        (bad("name", json!("")), field("name", "required")),
        (bad("name", json!("a\u{7}b")), field("name", "invalid_chars")),
        (bad("authMode", json!("kerberos")), field("authMode", "invalid")),
        (
            bad("savePassword", json!("yes")),
            field("savePassword", "invalid_type"),
        ),
        (bad("id", json!("../etc")), field("id", "invalid")),
        (bad("admin", json!(true)), field("admin", "unknown_field")),
        (
            json!({ "profile": profile_input("X"), "password": "a\nb" }),
            field("password", "invalid_chars"),
        ),
        (
            json!({ "profile": profile_input("X"), "password": 42 }),
            field("password", "invalid_type"),
        ),
    ];
    for (args, want) in cases {
        assert_eq!(c.markers("profiles_save", args.clone()), want, "{args}");
    }
    assert!(c.st().profiles.list().is_empty());
}

#[test]
fn profiles_save_hides_storage_failures_behind_an_internal_error() {
    let mut c = ctx();
    // profiles.json cannot be written: a directory sits in its place.
    std::fs::create_dir_all(c.data("profiles.json")).unwrap();

    let err = c
        .invoke("profiles_save", json!({ "profile": profile_input("X") }))
        .unwrap_err();
    assert_eq!(
        err, "[code:internal] Internal error, see the log for details",
        "the cause must stay in the log"
    );
    assert!(c.log_text().contains("profiles_save failed"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "QA-T5: on macOS 14+ profiles_remove calls AppHandle::fetch_data_store_identifiers, \
              which is todo!() in tauri::test::MockRuntime (the command task panics, no response)"
)]
fn profiles_remove_clears_last_profile_and_sso_data_of_that_profile_only() {
    let mut c = ctx();
    let a = id_of(&c.save_profile(&profile_input("A"), None));
    let b = id_of(&c.save_profile(&profile_input("B"), None));
    let saml_root = c.tmp.path().join("saml");
    for id in [&a, &b] {
        std::fs::create_dir_all(saml_root.join(id).join("EBWebView")).unwrap();
    }

    // Removing a profile that is not the last used one keeps lastProfileId.
    c.ok("settings_set", json!({ "patch": { "lastProfileId": b } }));
    assert_eq!(c.ok("profiles_remove", json!({ "id": a })), Value::Null);
    assert_eq!(c.ok("settings_get", json!({}))["lastProfileId"], json!(b));
    assert!(
        !saml_root.join(&a).exists(),
        "SSO data of the removed profile kept"
    );
    assert!(saml_root.join(&b).exists(), "SSO data of another profile removed");

    // Removing the last used profile clears it (id given in upper case: normalized).
    assert_eq!(
        c.ok("profiles_remove", json!({ "id": b.to_uppercase() })),
        Value::Null
    );
    let settings = c.ok("settings_get", json!({}));
    assert!(
        settings.get("lastProfileId").is_none_or(Value::is_null),
        "{settings}"
    );
    assert_eq!(c.ok("profiles_list", json!({})), json!([]));
    assert!(!saml_root.join(&b).exists());

    for args in [json!({}), json!({ "id": "../x" }), json!({ "id": 1 })] {
        assert_eq!(
            c.markers("profiles_remove", args.clone()),
            field("profileId", "invalid"),
            "{args}"
        );
    }
}

// ------------------------------------------------------------------ settings

#[test]
fn settings_get_and_set_round_trip_and_validate() {
    let mut c = ctx();
    let initial = c.ok("settings_get", json!({}));
    assert_eq!(initial["theme"], "system");

    let next = c.ok(
        "settings_set",
        json!({ "patch": { "theme": "dark", "autoReconnect": false } }),
    );
    assert_eq!(
        (next["theme"].clone(), next["autoReconnect"].clone()),
        (json!("dark"), json!(false))
    );
    assert_eq!(c.ok("settings_get", json!({})), next);
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(c.data("settings.json")).unwrap()).unwrap();
    assert_eq!(on_disk["theme"], "dark");

    let cases = [
        (json!({}), code("invalid_type")),
        (json!({ "patch": 42 }), code("invalid_type")),
        (json!({ "patch": { "theme": "pink" } }), field("theme", "invalid")),
        (
            json!({ "patch": { "language": "de" } }),
            field("language", "invalid"),
        ),
        (
            json!({ "patch": { "bogus": 1 } }),
            field("bogus", "unknown_field"),
        ),
        (
            json!({ "patch": { "autoReconnect": "yes" } }),
            field("autoReconnect", "invalid_type"),
        ),
        (
            json!({ "patch": { "lastProfileId": "x" } }),
            field("lastProfileId", "invalid"),
        ),
        // Elevation-relevant fields are validated before any confirmation dialog. The path rules
        // are string rules, identical on every OS (Windows-style inputs included).
        (
            json!({ "patch": { "openconnectPath": r"C:\Windows\System32\cmd.exe" } }),
            field("openconnectPath", "not_openconnect"),
        ),
        (
            json!({ "patch": { "hipScriptPath": "hip.cmd" } }),
            field("hipScriptPath", "not_absolute"),
        ),
        (
            json!({ "patch": { "extraArgs": ["--script=C:\\x.cmd"] } }),
            field("extraArgs", "not_allowed"),
        ),
    ];
    for (args, want) in cases {
        assert_eq!(c.markers("settings_set", args.clone()), want, "{args}");
    }
    assert_eq!(
        c.ok("settings_get", json!({})),
        next,
        "a rejected patch changed settings"
    );
}

#[test]
fn settings_set_hides_storage_failures_behind_an_internal_error() {
    let mut c = ctx();
    std::fs::create_dir_all(c.data("settings.json")).unwrap();
    let err = c
        .invoke("settings_set", json!({ "patch": { "theme": "light" } }))
        .unwrap_err();
    assert_eq!(err, "[code:internal] Internal error, see the log for details");
    assert!(c.log_text().contains("settings_set failed"));
}

// ------------------------------------------------------------------ vpn

#[test]
fn vpn_commands_validate_input_and_report_engine_errors() {
    let mut c = ctx();
    let state = c.ok("vpn_get_state", json!({}));
    assert_eq!(state["status"], "disconnected");
    assert_eq!(c.ok("vpn_get_pending_prompts", json!({})), json!([]));
    assert_eq!(c.ok("vpn_disconnect", json!({})), Value::Null);

    let cases = [
        ("vpn_connect", json!({}), field("profileId", "invalid")),
        (
            "vpn_connect",
            json!({ "profileId": "nope" }),
            field("profileId", "invalid"),
        ),
        (
            "vpn_connect",
            json!({ "profileId": UNKNOWN_ID }),
            field("profileId", "not_found"),
        ),
        (
            "vpn_connect",
            json!({ "profileId": UNKNOWN_ID, "opts": { "x": 1 } }),
            field("x", "unknown_field"),
        ),
        (
            "vpn_connect",
            json!({ "profileId": UNKNOWN_ID, "opts": { "password": "a\nb" } }),
            field("password", "invalid_chars"),
        ),
        (
            "vpn_answer_prompt",
            json!({ "id": "x", "value": "1" }),
            field("promptId", "invalid"),
        ),
        (
            "vpn_answer_prompt",
            json!({ "id": UNKNOWN_ID, "value": 5 }),
            field("answer", "invalid_type"),
        ),
        (
            "vpn_answer_prompt",
            json!({ "id": UNKNOWN_ID, "value": "1" }),
            field("promptId", "prompt_expired"),
        ),
    ];
    for (cmd, args, want) in cases {
        assert_eq!(c.markers(cmd, args.clone()), want, "{cmd} {args}");
    }
    assert!(c.spawner.procs().is_empty());
}

#[test]
fn vpn_connect_remembers_the_profile_and_disconnect_stops_openconnect() {
    let mut c = ctx();
    let mut input = profile_input("Work");
    input["authMode"] = json!("password");
    input["username"] = json!("alice");
    let id = id_of(&c.save_profile(&input, None));

    assert_eq!(
        c.ok(
            "vpn_connect",
            json!({ "profileId": id, "opts": { "password": PASSWORD } })
        ),
        Value::Null
    );
    let proc = c.proc();
    assert_eq!(c.wait_written(&proc, 1), [format!("{PASSWORD}\n")]);
    assert_eq!(c.ok("settings_get", json!({}))["lastProfileId"], json!(id));
    // A second connect while busy is refused.
    assert_eq!(c.markers("vpn_connect", json!({ "profileId": id })), code("busy"));

    assert_eq!(c.ok("vpn_disconnect", json!({})), Value::Null);
    c.wait_status(VpnStatus::Disconnected);
    assert_eq!(c.ok("vpn_get_state", json!({}))["status"], "disconnected");
}

// ------------------------------------------------------------------ logs, system, window

#[test]
fn logs_get_returns_the_log_buffer() {
    let mut c = ctx();
    c.st().logger.info("test", "hello from the test");
    let lines = c.ok("logs_get", json!({}));
    let lines: Vec<String> = serde_json::from_value(lines).unwrap();
    assert!(
        lines.iter().any(|l| l.contains("hello from the test")),
        "{lines:?}"
    );
}

#[test]
fn system_info_describes_the_platform_and_openconnect() {
    let mut c = ctx();
    let info = c.ok("system_info", json!({}));
    assert_eq!(info["platform"], PLATFORM);
    assert_eq!(info["appVersion"], "0.1.0"); // mock_context's package version
    assert!(info["shouldUseDarkColors"].is_boolean(), "{info}");
    assert_eq!(
        info["openconnectFound"].as_bool(),
        Some(info.get("openconnectPath").is_some_and(Value::is_string)),
        "{info}"
    );
}

#[test]
fn system_open_external_accepts_https_links_only() {
    let mut c = ctx();
    for (args, want) in [
        (json!({}), field("url", "invalid")),
        (
            json!({ "url": "file:///C:/Windows/win.ini" }),
            field("url", "not_https"),
        ),
        (json!({ "url": "http://example.com/" }), field("url", "not_https")),
        // A Windows path parses as a URL with the scheme `c:`.
        (
            json!({ "url": r"C:\Windows\System32\calc.exe" }),
            field("url", "not_https"),
        ),
        (json!({ "url": "not a url" }), field("url", "invalid")),
        (json!({ "url": 42 }), field("url", "invalid")),
    ] {
        assert_eq!(c.markers("system_open_external", args.clone()), want, "{args}");
    }
}

// ------------------------------------------------------------------ settings confirmation

/// A changed openconnect path is applied only after the native dialog was accepted.
#[test]
fn settings_set_applies_elevation_settings_only_when_confirmed() {
    let mut c = ctx();
    let path = OC_PATH;
    let patch = json!({ "patch": { "openconnectPath": path } });

    c.dialog.accept.store(false, Ordering::SeqCst);
    assert_eq!(c.markers("settings_set", patch.clone()), code("not_confirmed"));
    assert_eq!(c.st().settings.get().openconnect_path, None);
    assert_eq!(c.dialog.shown.lock().unwrap().len(), 1);
    c.wait_log("was not confirmed");

    c.dialog.accept.store(true, Ordering::SeqCst);
    let next = c.ok("settings_set", patch);
    assert_eq!(next["openconnectPath"], path);
    assert_eq!(c.st().settings.get().openconnect_path.as_deref(), Some(path));
    assert!(c.st().guard.is_confirmed(&c.st().settings.get()));
    let shown = c.dialog.shown.lock().unwrap();
    assert_eq!(shown.len(), 2);
    assert!(shown[1].detail.contains(path), "{}", shown[1].detail);
}

#[test]
fn settings_set_without_elevation_settings_never_asks() {
    let mut c = ctx();
    c.dialog.accept.store(false, Ordering::SeqCst);
    let next = c.ok("settings_set", json!({ "patch": { "language": "en" } }));
    assert_eq!(next["language"], "en");
    assert!(c.dialog.shown.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------ events → main window only

/// Collects the payloads of `event` delivered to the webview `label`.
fn record(c: &Ctx, label: &str, event: &str) -> Arc<Mutex<Vec<String>>> {
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = got.clone();
    c.app
        .get_webview_window(label)
        .unwrap()
        .listen(event, move |e| sink.lock().unwrap().push(e.payload().to_string()));
    got
}

#[test]
fn engine_events_and_log_lines_reach_the_main_window_only() {
    let mut c = ctx();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let logger = Logger::in_memory();
    let main_state = record(&c, MAIN, super::EV_VPN_STATE);
    let main_prompt = record(&c, MAIN, super::EV_VPN_PROMPT);
    let main_log = record(&c, MAIN, super::EV_LOG_LINE);
    let other: Vec<_> = [super::EV_VPN_STATE, super::EV_VPN_PROMPT, super::EV_LOG_LINE]
        .iter()
        .map(|e| record(&c, OTHER, e))
        .collect();

    super::forward_events(c.app.handle(), rx, &logger);
    tx.send(EngineEvent::State(VpnState::new(VpnStatus::Connecting)))
        .unwrap();
    let prompt = AuthPrompt {
        id: UNKNOWN_ID.into(),
        kind: PromptKind::Otp,
        message: "Code".into(),
        options: None,
    };
    tx.send(EngineEvent::Prompt(prompt.clone())).unwrap();
    logger.info("t", "hello ui");

    c.pump_until("forwarded events", |_| {
        (main_state.lock().unwrap().len() == 1 && main_prompt.lock().unwrap().len() == 1).then_some(())
    });
    assert_eq!(
        serde_json::from_str::<Value>(&main_state.lock().unwrap()[0]).unwrap(),
        json!({ "status": "connecting" })
    );
    assert_eq!(
        serde_json::from_str::<AuthPrompt>(&main_prompt.lock().unwrap()[0]).unwrap(),
        prompt
    );
    let lines = main_log.lock().unwrap().clone();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("[t] hello ui"), "{}", lines[0]);

    // A reloaded UI gets the pending prompts again, also on the main window only.
    super::emit_pending_prompts(c.app.handle(), std::slice::from_ref(&prompt));
    c.pump_until("re-emitted prompt", |_| {
        (main_prompt.lock().unwrap().len() == 2).then_some(())
    });
    for o in &other {
        assert!(
            o.lock().unwrap().is_empty(),
            "another webview got {:?}",
            o.lock().unwrap()
        );
    }
}

// ------------------------------------------------------------------ secrets end to end

/// One step of a transcript fixture (format: see fixtures/openconnect/*.txt).
enum Step {
    Out { stderr: bool, text: String },
    Prompt(String),
}

fn transcript(name: &str) -> Vec<Step> {
    fixture(&format!("openconnect/{name}"))
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            if let Some(t) = l.strip_prefix("? ") {
                Step::Prompt(t.into())
            } else if let Some(t) = l.strip_prefix("! ") {
                Step::Out {
                    stderr: true,
                    text: format!("{t}\n"),
                }
            } else {
                Step::Out {
                    stderr: false,
                    text: format!("{l}\n"),
                }
            }
        })
        .collect()
}

/// Plays steps up to and including the next prompt; `false` when the transcript ended first.
fn play_until_prompt(proc: &Proc, steps: &mut std::vec::IntoIter<Step>) -> bool {
    for step in steps.by_ref() {
        match step {
            Step::Out { stderr: true, text } => proc.stderr(&text),
            Step::Out { stderr: false, text } => proc.stdout(&text),
            Step::Prompt(text) => {
                proc.stderr(&text);
                return true;
            }
        }
    }
    false
}

fn assert_no_secret(what: &str, haystack: &str, secrets: &[&str]) {
    for s in secrets {
        assert!(!haystack.contains(s), "secret {s:?} leaked into {what}");
        assert!(
            !haystack.contains(&encode_uri_component(s)),
            "URI-encoded secret {s:?} leaked into {what}"
        );
    }
}

impl Ctx {
    /// Everything that left the backend towards the UI or the disk, after a final snapshot of
    /// the calls a reloaded UI makes.
    fn check_nothing_leaked(&mut self, secrets: &[&str]) {
        for cmd in [
            "vpn_get_state",
            "vpn_get_pending_prompts",
            "logs_get",
            "profiles_list",
            "settings_get",
        ] {
            self.ok(cmd, json!({}));
        }
        self.drain_events();
        let pushed = self.pushed.lock().unwrap().join("\n");
        assert!(pushed.contains("\"connected\""), "no state events were captured");
        assert_no_secret("IPC responses", &self.responses.join("\n"), secrets);
        assert_no_secret("pushed events / log lines", &pushed, secrets);
        let args: Vec<String> = self
            .spawner
            .requests
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| r.args.clone())
            .collect();
        assert_no_secret("the openconnect command line", &args.join(" "), secrets);
        for f in ["profiles.json", "settings.json"] {
            let text = std::fs::read_to_string(self.data(f)).unwrap_or_default();
            assert_no_secret(f, &text, secrets);
        }

        let logger = self.st().logger.clone();
        logger.info("test", "END-OF-TEST-MARKER");
        logger.close();
        let file = std::fs::read_to_string(self.tmp.path().join("logs").join(LOG_FILE_NAME)).unwrap();
        assert!(file.contains("END-OF-TEST-MARKER"), "log file incomplete");
        assert_no_secret("the log file", &file, secrets);
    }
}

#[test]
fn saved_password_and_otp_never_leave_the_backend_during_a_connect() {
    let mut c = ctx();
    let mut input = profile_input("Work");
    input["authMode"] = json!("password");
    input["username"] = json!("alice");
    input["savePassword"] = json!(true);
    input["preferredGateway"] = json!("gw-us.example.com");
    let id = id_of(&c.save_profile(&input, Some(PASSWORD)));

    c.ok("vpn_connect", json!({ "profileId": id }));
    let proc = c.proc();
    // The saved password goes to stdin only.
    assert_eq!(c.wait_written(&proc, 1), [format!("{PASSWORD}\n")]);

    let mut steps = transcript("password-otp-gateways.txt").into_iter();
    // GATEWAY: answered from the preferred gateway, no prompt for the UI.
    assert!(play_until_prompt(&proc, &mut steps));
    assert_eq!(c.wait_written(&proc, 2)[1], "US East\n");

    // Challenge: an OTP prompt the UI answers.
    assert!(play_until_prompt(&proc, &mut steps));
    let prompts = c.pump_until("OTP prompt", |c| {
        let p = c.st().engine.get_pending_prompts();
        (!p.is_empty()).then_some(p)
    });
    let pending = c.ok("vpn_get_pending_prompts", json!({}));
    assert_eq!(pending[0]["kind"], "otp", "{pending}");
    assert_eq!(pending[0]["id"], json!(prompts[0].id));
    assert_eq!(
        c.ok("vpn_answer_prompt", json!({ "id": prompts[0].id, "value": OTP })),
        Value::Null
    );
    assert_eq!(c.wait_written(&proc, 3)[2], format!("{OTP}\n"));
    assert_eq!(c.ok("vpn_get_pending_prompts", json!({})), json!([]));

    assert!(!play_until_prompt(&proc, &mut steps));
    c.wait_status(VpnStatus::Connected);
    let state = c.ok("vpn_get_state", json!({}));
    assert_eq!(
        (state["status"].clone(), state["assignedIp"].clone()),
        (json!("connected"), json!("10.8.0.42"))
    );

    // A verbose openconnect echoing the secrets, plain and URI-encoded.
    proc.stderr(&format!("LEAK-PROBE-1 passwd={PASSWORD} otp={OTP}\n"));
    proc.stderr(&format!(
        "LEAK-PROBE-2 passwd={}&otp={}\n",
        encode_uri_component(PASSWORD),
        encode_uri_component(OTP)
    ));
    c.wait_log("LEAK-PROBE-2");

    assert_eq!(c.ok("vpn_disconnect", json!({})), Value::Null);
    c.wait_status(VpnStatus::Disconnected);
    c.check_nothing_leaked(&[PASSWORD, OTP]);
}

#[test]
fn saml_cookie_never_leaves_the_backend_during_a_connect() {
    let prelogin = parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap();
    let Some(SamlOutcome::Success(saml)) = extract_saml_from_html(&fixture("saml-success.html")) else {
        panic!("fixture must be a successful SAML response")
    };
    assert_eq!(saml.cookie, COOKIE);
    let mut c = ctx_with(prelogin, Some(saml));
    let id = id_of(&c.save_profile(&profile_input("SSO"), None));

    c.ok("vpn_connect", json!({ "profileId": id }));
    let proc = c.proc();
    assert_eq!(c.wait_written(&proc, 1), [format!("{COOKIE}\n")]);

    let mut steps = transcript("saml-gateways.txt").into_iter();
    assert!(play_until_prompt(&proc, &mut steps));
    assert_eq!(c.wait_written(&proc, 2)[1], "Europe\n");
    assert!(!play_until_prompt(&proc, &mut steps));
    c.wait_status(VpnStatus::Connected);

    proc.stderr(&format!("LEAK-PROBE-1 prelogin-cookie={COOKIE}\n"));
    proc.stderr(&format!(
        "LEAK-PROBE-2 Cookie: {}\n",
        encode_uri_component(COOKIE)
    ));
    c.wait_log("LEAK-PROBE-2");
    // An error path: the server rejects the cookie and the message quotes it.
    proc.stderr(&format!("Unexpected 512 result from server {COOKIE}\n"));
    proc.exit(1);
    c.pump_until("openconnect exit handled", |c| {
        (c.status() != VpnStatus::Connected).then_some(())
    });
    assert_eq!(c.ok("vpn_disconnect", json!({})), Value::Null);
    c.wait_status(VpnStatus::Disconnected);
    c.check_nothing_leaked(&[COOKIE]);
}
