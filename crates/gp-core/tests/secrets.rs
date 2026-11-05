//! Acceptance #4: passwords / OTPs / SAML cookies never
//! reach the log buffer, the log file, `VpnState` (message/detail), prompts or anything else sent
//! to the UI after submission.
//!
//! Real: VpnEngine, Logger (writing to a temp dir), masking, command-input validation. Fake:
//! openconnect process, prelogin/SAML. The UI sink receives every pushed event (state, prompt,
//! log line) plus every value / error string a command would return.

#![allow(clippy::many_single_char_names, clippy::unwrap_used)] // test crate; short names (p, s, …) keep the scenarios compact

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use gp_core::logging::{DEFAULT_CAPACITY, Logger};
use gp_core::prelogin::parse_prelogin;
use gp_core::saml::{SamlOutcome, extract_saml_from_html};
use gp_core::store::validation::validate_connect_options;
use gp_core::vpn::EngineEvent;
use gp_core::{AuthMode, VpnErrorCode};
use serde_json::{Value, json};

const PASSWORD: &str = "Hunter2-Pa$$word!";
const OTP: &str = "918273";
const COOKIE: &str = "PRELOGIN-COOKIE-abc123XYZ"; // from saml-success.html

struct World {
    h: Harness,
    logger: Arc<Logger>,
    log_file: PathBuf,
    to_renderer: Arc<Mutex<Vec<String>>>,
    events: Mutex<tokio::sync::mpsc::UnboundedReceiver<EngineEvent>>,
    _dir: tempfile::TempDir,
}

fn world(b: Builder) -> World {
    let dir = tempfile::tempdir().unwrap();
    let logger = Arc::new(Logger::new(Some(&dir.path().join("logs")), DEFAULT_CAPACITY));
    let h = b.logger(logger.clone()).build();
    let to_renderer = Arc::new(Mutex::new(Vec::new()));
    let sink = to_renderer.clone();
    logger.on_line(move |l| sink.lock().unwrap().push(json!(l).to_string()));
    let events = Mutex::new(h.engine.subscribe());
    World {
        log_file: dir.path().join("logs").join("gp-connect.log"),
        h,
        logger,
        to_renderer,
        events,
        _dir: dir,
    }
}

impl World {
    /// Moves pushed state/prompt events into the UI sink.
    fn pump(&self) {
        let mut rx = self.events.lock().unwrap();
        let mut out = self.to_renderer.lock().unwrap();
        while let Ok(ev) = rx.try_recv() {
            out.push(match ev {
                EngineEvent::State(s) => serde_json::to_string(&s).unwrap(),
                EngineEvent::Prompt(p) => serde_json::to_string(&p).unwrap(),
            });
        }
    }

    fn record(&self, v: Value) -> Value {
        self.to_renderer.lock().unwrap().push(v.to_string());
        v
    }

    /// `vpn.connect(profileId, opts)` through the command-input validation.
    fn connect(&self, opts: &Value) -> Result<(), String> {
        let r = validate_connect_options(Some(opts))
            .map_err(|e| e.to_string())
            .and_then(|o| self.h.engine.connect(PROFILE_ID, o).map_err(|e| e.to_ipc_error()));
        if let Err(e) = &r {
            self.record(json!(e));
        }
        r
    }

    fn pending_prompts(&self) -> Value {
        self.record(serde_json::to_value(self.h.engine.get_pending_prompts()).unwrap())
    }

    fn answer(&self, id: &str, v: &str) -> Result<(), String> {
        let r = self
            .h
            .engine
            .answer_prompt(id, Some(v.into()))
            .map_err(|e| e.to_ipc_error());
        if let Err(e) = &r {
            self.record(json!(e));
        }
        r
    }

    /// After the attempt: snapshot calls a reloaded UI would make.
    fn snapshot_calls(&self) {
        self.record(serde_json::to_value(self.h.engine.get_state()).unwrap());
        self.record(json!(self.logger.lines()));
        self.pending_prompts();
    }

    /// Closes the logger and returns the log file content.
    fn log_file_content(&self) -> String {
        self.logger.info("test", "END-OF-TEST-MARKER");
        self.logger.close();
        let content = std::fs::read_to_string(&self.log_file).unwrap();
        assert!(content.contains("END-OF-TEST-MARKER"));
        content
    }

    fn renderer_text(&self) -> String {
        self.pump();
        self.to_renderer.lock().unwrap().join("\n")
    }
}

fn expect_no_secret(haystack: &str, secrets: &[&str]) {
    for s in secrets {
        assert!(!haystack.contains(s), "secret {s:?} leaked");
        assert!(
            !haystack.contains(&encode_uri_component(s)),
            "encoded secret {s:?} leaked"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn password_and_otp_echoed_by_a_verbose_openconnect_then_login_fails() {
    let w = world(harness());
    w.connect(&json!({ "password": PASSWORD })).unwrap();
    flush().await;
    let proc = w.h.spawner.last();
    assert_eq!(
        proc.written()[0],
        format!("{PASSWORD}\n"),
        "the secret does reach openconnect"
    );

    // openconnect -v / --dump-http-traffic style echoes
    proc.err(&format!(
        "POST body: user=alice&passwd={}&computer=host\n",
        encode_uri_component(PASSWORD)
    ));
    proc.err(&format!("< <response><passwd>{PASSWORD}</passwd></response>\n"));
    proc.err("Enter the 6-digit code from your authenticator app\nChallenge:");
    advance(200).await;
    let prompts = w.pending_prompts();
    w.answer(prompts[0]["id"].as_str().unwrap(), OTP).unwrap();
    flush().await;
    assert_eq!(proc.last_written(), Some(format!("{OTP}\n")));

    proc.err(&format!("inputStr={OTP}&passwd={PASSWORD}\n"));
    proc.err(&format!("Login failed for user alice with {PASSWORD} / {OTP}\n"));
    proc.exit(1);
    flush().await;

    let state = w.h.engine.get_state();
    let e = state.error.unwrap();
    assert_eq!(e.code, VpnErrorCode::AuthFailed);
    assert_eq!(
        e.detail.as_deref(),
        Some("Login failed for user alice with *** / ***")
    );

    w.snapshot_calls();
    let file = w.log_file_content();
    assert!(
        file.contains("[openconnect] Login failed for user alice with *** / ***"),
        "not vacuous"
    );
    expect_no_secret(&file, &[PASSWORD, OTP]);
    expect_no_secret(&w.logger.lines().join("\n"), &[PASSWORD, OTP]);
    expect_no_secret(&w.renderer_text(), &[PASSWORD, OTP]);
    assert!(w.to_renderer.lock().unwrap().len() > 10);
}

#[tokio::test(start_paused = true)]
async fn saved_password_session_with_drop_reconnect_and_disconnect_leaks_nothing() {
    let w = world(
        harness()
            .saved_password(PASSWORD)
            .config(|c| c.backoff = vec![Duration::from_millis(100)]),
    );
    w.connect(&Value::Null).unwrap();
    flush().await;
    let first = w.h.spawner.last();
    let outs: Vec<Step> = load_transcript("password-otp-gateways.txt", false)
        .into_iter()
        .filter(|s| matches!(s, Step::Out { .. }))
        .collect();
    play_all(&first, &outs, PlayOptions::default()).await;
    // Bare values without any key ("passwd=", "Cookie:"): only masking by value can catch these.
    first.out(&format!("GPST negotiated {PASSWORD} for alice\n"));
    first.err(&format!(
        "Unexpected reply {} from gw-us.example.com\n",
        encode_uri_component(PASSWORD)
    ));
    flush().await;
    assert_eq!(w.h.status(), gp_core::VpnStatus::Connected);

    first.err("Unrecoverable I/O error; exiting.\n");
    first.exit(1);
    advance(100).await; // reconnect with the in-memory password
    let second = w.h.spawner.last();
    assert!(!second.same(&first));
    assert_eq!(second.written(), [format!("{PASSWORD}\n")]);
    second.out(&format!("ESP handshake with {PASSWORD} ok\n"));
    flush().await;
    w.h.engine.disconnect().await;

    w.snapshot_calls();
    let file = w.log_file_content();
    assert!(file.contains("Connected, assigned IP 10.8.0.42"));
    // Both attempts' echoes were logged, masked.
    assert!(file.contains("[openconnect] GPST negotiated *** for alice"));
    assert!(file.contains("[openconnect] Unexpected reply *** from gw-us.example.com"));
    assert!(file.contains("[openconnect] ESP handshake with *** ok"));
    expect_no_secret(&file, &[PASSWORD]);
    expect_no_secret(&w.logger.lines().join("\n"), &[PASSWORD]);
    expect_no_secret(&w.renderer_text(), &[PASSWORD]);
}

#[tokio::test(start_paused = true)]
async fn saml_cookie_stays_out_of_logs_file_state_and_ui() {
    let Some(SamlOutcome::Success(saml)) = extract_saml_from_html(&fixture("saml-success.html")) else {
        panic!("fixture")
    };
    let w = world(
        harness()
            .profile(|p| {
                p.auth_mode = AuthMode::Auto;
                p.username = None;
            })
            .prelogin(Ok(parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap()))
            .saml(Ok(saml)),
    );
    w.connect(&Value::Null).unwrap();
    flush().await;
    let proc = w.h.spawner.last();
    assert_eq!(proc.written(), [format!("{COOKIE}\n")]);

    proc.err(&format!(
        "POST https://gw-eu.example.com/ssl-vpn/login.esp?prelogin-cookie={COOKIE}&user=j.doe\n"
    ));
    proc.err(&format!("Set-Cookie: SESSID={COOKIE}; Path=/\n"));
    proc.err(&format!(
        "Unexpected 512 result from server; cookie {COOKIE} rejected\n"
    ));
    proc.exit(1);
    flush().await;
    assert_eq!(w.h.error_code(), Some(VpnErrorCode::AuthFailed));

    w.snapshot_calls();
    let file = w.log_file_content();
    assert!(file.contains("Unexpected 512 result from server"));
    expect_no_secret(&file, &[COOKIE]);
    expect_no_secret(&w.renderer_text(), &[COOKIE]);
}

#[tokio::test(start_paused = true)]
async fn a_rejected_multi_line_password_is_not_echoed_or_logged() {
    let w = world(harness());
    let bad = format!("{PASSWORD}\n--script=/tmp/x");
    let err = w.connect(&json!({ "password": bad })).unwrap_err();
    assert!(err.contains("single line"));
    let file = w.log_file_content();
    expect_no_secret(&file, &[PASSWORD]);
    expect_no_secret(&w.renderer_text(), &[PASSWORD]);
    assert!(w.h.spawner.requests().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_answered_password_is_not_kept_in_the_pending_prompts() {
    let w = world(harness());
    w.connect(&Value::Null).unwrap();
    flush().await;
    let id = w.pending_prompts()[0]["id"].as_str().unwrap().to_string();
    w.answer(&id, PASSWORD).unwrap();
    flush().await;
    assert_eq!(w.pending_prompts(), json!([]));
    // A late duplicate answer is refused (the prompt is gone) without echoing the value.
    assert!(w.answer(&id, PASSWORD).unwrap_err().contains("expired"));
    expect_no_secret(&w.renderer_text(), &[PASSWORD]);
}

#[tokio::test(start_paused = true)]
async fn qa2_a_secret_inside_a_newline_less_prompt_label_is_masked() {
    let w = world(harness().saved_password(PASSWORD));
    w.connect(&Value::Null).unwrap();
    flush().await;
    w.h.spawner.last().err(&format!("Second factor for {PASSWORD}:"));
    advance(200).await;
    let prompts = w.h.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].message, "Second factor for ***");
    let pending = w.pending_prompts();
    expect_no_secret(&format!("{prompts:?}{pending}{}", w.renderer_text()), &[PASSWORD]);
    expect_no_secret(&w.logger.lines().join("\n"), &[PASSWORD]);
}

#[tokio::test(start_paused = true)]
async fn qa2_secrets_in_select_options_are_masked() {
    let w = world(harness().saved_password(PASSWORD));
    w.connect(&Value::Null).unwrap();
    flush().await;
    w.h.spawner.last().err(&format!("Choose: [Push|{PASSWORD}]:"));
    advance(200).await;
    assert_eq!(
        w.h.prompts()[0].options,
        Some(vec!["Push".to_string(), "***".to_string()])
    );
    expect_no_secret(&w.renderer_text(), &[PASSWORD]);
}

fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        boundary(before) && boundary(after)
    })
}

#[tokio::test(start_paused = true)]
async fn qa3_a_short_password_never_reaches_the_log_state_or_ui() {
    let w = world(harness().saved_password("abc"));
    w.connect(&Value::Null).unwrap();
    flush().await;
    let proc = w.h.spawner.last();
    proc.err("Login failed for abc\n");
    proc.exit(1);
    flush().await;
    assert_eq!(
        w.h.state().error.unwrap().detail.as_deref(),
        Some("Login failed for ***")
    );
    assert!(!has_word(&w.logger.lines().join("\n"), "abc"));
    assert!(!has_word(&w.renderer_text(), "abc"));
    assert!(!has_word(&w.log_file_content(), "abc"));
}

#[tokio::test(start_paused = true)]
async fn classification_runs_on_the_raw_line() {
    // 1-char password "a" must not break "sudo: a password is required"
    let w = world(harness().saved_password("a"));
    w.connect(&Value::Null).unwrap();
    flush().await;
    let proc = w.h.spawner.last();
    proc.err("sudo: a password is required\n");
    proc.exit(1);
    flush().await;
    let e = w.h.state().error.unwrap();
    // classified exactly as without the secret …
    assert_eq!(e.code, VpnErrorCode::PrivilegesDenied);
    // … while the secret is masked in everything that leaves the parser
    assert_eq!(e.detail.as_deref(), Some("sudo: *** password is required"));
    let lines = w.logger.lines();
    let logged = lines.iter().find(|l| l.contains("password is required")).unwrap();
    assert!(logged.ends_with("sudo: *** password is required"));
    assert!(w.log_file_content().contains("sudo: *** password is required"));
    assert!(!w.renderer_text().contains("sudo: a password"));
}
