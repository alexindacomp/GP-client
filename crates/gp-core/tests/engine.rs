//! `VpnEngine` behaviour: state machine, prompts, reconnects, stop handling (fake process/prelogin/SAML).

#![allow(clippy::many_single_char_names, clippy::unwrap_used)] // test crate; short names (p, s, …) keep the scenarios compact

mod common;

use std::sync::Arc;

use base64::Engine as _;
use common::*;
use gp_core::openconnect::trust::UntrustedPathError;
use gp_core::prelogin::{AuthType, PreloginResult, SamlMethod};
use gp_core::process::SpawnError;
use gp_core::vpn::{ElevatedFiles, EngineError};
use gp_core::{
    AuthMode, ConnectOptions, Gateway, Language, Platform, PromptKind, VpnError, VpnErrorCode, VpnErrorHint,
    VpnState, VpnStatus,
};

use VpnStatus as S;

fn saml_prelogin() -> PreloginResult {
    PreloginResult {
        auth_type: AuthType::Saml,
        saml_method: Some(SamlMethod::Redirect),
        saml_request: Some(base64::engine::general_purpose::STANDARD.encode("https://idp.example.com/sso")),
        ..PreloginResult::password()
    }
}

fn password_prelogin_with_label() -> PreloginResult {
    PreloginResult {
        password_label: Some("Password".into()),
        ..PreloginResult::password()
    }
}

/// Defaults: saved password, SAML login succeeding.
fn setup() -> Builder {
    harness()
        .saved_password("Secr3tPass")
        .profile(|p| p.save_password = true)
        .prelogin(Ok(password_prelogin_with_label()))
        .saml(Ok(default_saml()))
}

async fn connect_and_establish(h: &Harness) -> FakeProc {
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.out("GlobalProtect login returned authentication-source=local\n");
    p.out("Connected as 10.8.0.42, using SSL, with ESP in progress\n");
    flush().await;
    p
}

fn gw(name: &str, address: &str, priority: Option<f64>) -> Gateway {
    Gateway {
        name: name.into(),
        address: address.into(),
        priority,
    }
}

fn opts_gateway(g: &str) -> ConnectOptions {
    ConnectOptions {
        gateway: Some(g.into()),
        password: None,
    }
}

// ------------------------------------------------------------------ successful connections

#[tokio::test(start_paused = true)]
async fn password_profile_connects_and_the_password_goes_to_stdin_only() {
    let h = setup().build();
    let p = connect_and_establish(&h).await;
    assert_eq!(
        h.statuses(),
        [S::Prelogin, S::Authenticating, S::Connecting, S::Connected]
    );
    assert_eq!(h.prelogin.calls(), 0, "authMode 'password' skips prelogin");
    let req = &h.spawner.requests()[0];
    assert_eq!(req.binary, std::path::PathBuf::from("/usr/sbin/openconnect"));
    assert!(req.args.contains(&"--user=alice".to_string()));
    assert!(!req.args.join(" ").contains("Secr3tPass"));
    assert_eq!(p.written(), ["Secr3tPass\n"]);
    let s = h.state();
    assert_eq!(s.status, S::Connected);
    assert_eq!(s.profile_id.as_deref(), Some(PROFILE_ID));
    assert_eq!(s.assigned_ip.as_deref(), Some("10.8.0.42"));
    assert_eq!(s.connected_at, Some(NOW_MS));
    assert_eq!(s.gateway, Some(gw("vpn.example.com", "vpn.example.com", None)));
    assert_eq!(s.error, None);
}

#[tokio::test(start_paused = true)]
async fn saml_profile_runs_prelogin_and_saml_and_passes_the_cookie_on_stdin() {
    let h = setup().profile(|p| {
        p.auth_mode = AuthMode::Auto;
        p.username = None;
    });
    let h = h.prelogin(Ok(saml_prelogin())).build();
    let p = connect_and_establish(&h).await;
    assert_eq!(h.saml.calls().len(), 1);
    let args = &h.spawner.requests()[0].args;
    assert!(args.contains(&"--usergroup=portal:prelogin-cookie".to_string()));
    assert!(args.contains(&"--user=alice@example.com".to_string()));
    assert_eq!(p.written(), ["SAML-COOKIE-VALUE\n"]);
    assert_eq!(h.status(), S::Connected);
}

#[tokio::test(start_paused = true)]
async fn records_the_gateway_list_and_auto_selects_the_preferred_gateway() {
    let h = setup()
        .profile(|p| p.preferred_gateway = Some("gw-us.example.com".into()))
        .build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    assert!(
        h.spawner.requests()[0]
            .args
            .contains(&"--authgroup=gw-us.example.com".to_string())
    );
    p.out(
        "2 gateway servers available:\n  Europe (gw-eu.example.com) [1]\n  US East (gw-us.example.com) [2]\n",
    );
    p.err("GATEWAY: [Europe|US East]:");
    advance(200).await;
    assert_eq!(p.last_written().as_deref(), Some("US East\n"));
    assert!(h.prompts().is_empty());
    p.out("Connected as 10.1.1.1\n");
    flush().await;
    let s = h.state();
    assert_eq!(s.status, S::Connected);
    assert_eq!(s.gateway, Some(gw("US East", "gw-us.example.com", Some(2.0))));
    assert_eq!(
        s.gateways,
        Some(vec![
            gw("Europe", "gw-eu.example.com", Some(1.0)),
            gw("US East", "gw-us.example.com", Some(2.0))
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn picks_the_first_gateway_when_none_is_requested() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("GATEWAY: [Europe|US East]:");
    advance(200).await;
    assert_eq!(p.last_written().as_deref(), Some("Europe\n"));
}

// ------------------------------------------------------------------ prompts

#[tokio::test(start_paused = true)]
async fn asks_for_the_password_when_none_is_saved_and_uses_the_answer() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    let prompts = h.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(
        (prompts[0].kind, prompts[0].message.as_str(), &prompts[0].options),
        (PromptKind::Password, "Пароль", &None)
    );
    assert!(h.spawner.requests().is_empty());
    h.answer(&prompts[0].id, Some("typed-pw"));
    flush().await;
    assert_eq!(h.spawner.last().written(), ["typed-pw\n"]);
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_password_prompt_ends_in_auth_cancelled_without_spawning() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    h.answer(&h.prompts()[0].id, None);
    flush().await;
    assert!(h.spawner.requests().is_empty());
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::AuthCancelled))
    );
}

#[tokio::test(start_paused = true)]
async fn forwards_an_otp_challenge_and_writes_the_answer() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Enter the code from your authenticator app\nChallenge:");
    advance(200).await;
    let prompts = h.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].kind, PromptKind::Otp);
    assert_eq!(
        prompts[0].message,
        "Enter the code from your authenticator app\nChallenge"
    );
    h.answer(&prompts[0].id, Some("123456"));
    flush().await;
    assert_eq!(p.written(), ["Secr3tPass\n", "123456\n"]);
}

#[tokio::test(start_paused = true)]
async fn an_incomplete_fragment_is_not_a_prompt_before_the_debounce() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.out("Connected as 10.0.0.1:");
    advance(50).await;
    p.out(" extra\n");
    advance(500).await;
    assert!(h.prompts().is_empty());
}

#[tokio::test(start_paused = true)]
async fn rejects_unknown_prompt_ids_and_multi_line_answers() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    assert_eq!(
        h.engine.answer_prompt("nope", Some("x".into())),
        Err(EngineError::UnknownPrompt)
    );
    let id = h.prompts()[0].id.clone();
    assert_eq!(
        h.engine.answer_prompt(&id, Some("a\nb".into())),
        Err(EngineError::MultiLineAnswer)
    );
    assert_eq!(
        h.engine.answer_prompt(&id, Some("x".repeat(4097))),
        Err(EngineError::InvalidAnswer)
    );
    assert!(EngineError::UnknownPrompt.to_string().contains("Unknown"));
    assert!(EngineError::MultiLineAnswer.to_string().contains("single line"));
}

// ------------------------------------------------------------------ errors

#[tokio::test(start_paused = true)]
async fn reports_openconnect_not_found() {
    let h = setup().binary(None).build();
    h.connect();
    flush().await;
    let s = h.state();
    assert_eq!((s.status, s.profile_id.as_deref()), (S::Error, Some(PROFILE_ID)));
    let e = s.error.unwrap();
    assert_eq!(e.code, VpnErrorCode::OpenconnectNotFound);
    assert_eq!(
        e.message,
        "Установите OpenConnect или укажите путь к нему в настройках."
    );
    assert_eq!(e.detail.as_deref(), Some("openconnect binary not found"));
    assert_eq!(e.hint, None, "errors without a specific cause carry no hint");
}

#[tokio::test(start_paused = true)]
async fn reports_portal_unreachable_from_prelogin() {
    let h = setup().profile(|p| p.auth_mode = AuthMode::Auto).build();
    h.prelogin.reject(VpnError::new(
        VpnErrorCode::PortalUnreachable,
        "Cannot reach portal: timeout",
    ));
    h.connect();
    flush().await;
    assert_eq!(h.statuses(), [S::Prelogin, S::Error]);
    assert_eq!(h.error_code(), Some(VpnErrorCode::PortalUnreachable));
}

#[tokio::test(start_paused = true)]
async fn reports_auth_cancelled_when_the_saml_window_is_closed() {
    let h = setup()
        .profile(|p| p.auth_mode = AuthMode::Saml)
        .prelogin(Ok(saml_prelogin()))
        .build();
    h.saml
        .reject(VpnError::new(VpnErrorCode::AuthCancelled, "closed"));
    h.connect();
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::AuthCancelled));
    assert!(h.spawner.requests().is_empty());
}

#[tokio::test(start_paused = true)]
async fn saml_profile_on_a_password_only_portal_is_auth_failed() {
    let h = setup().profile(|p| p.auth_mode = AuthMode::Saml).build();
    h.connect();
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::AuthFailed));
}

#[tokio::test(start_paused = true)]
async fn stops_openconnect_on_a_re_prompt_after_login_failed() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Login failed.\nPassword:");
    advance(200).await;
    assert!(h.prompts().is_empty());
    assert_eq!(p.stop_calls(), 1);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::AuthFailed))
    );
}

#[tokio::test(start_paused = true)]
async fn refuses_an_untrusted_server_certificate() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Certificate from VPN server \"vpn.example.com\" failed verification.\nEnter 'yes' to accept, 'no' to abort; anything else to view: ");
    advance(200).await;
    assert_eq!(p.last_written().as_deref(), Some("no\n"));
    p.exit(1);
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::TlsError));
}

#[tokio::test(start_paused = true)]
async fn a_denied_privilege_escalation_is_privileges_denied() {
    let h = setup().build();
    h.spawner
        .fail_with(Some(SpawnError::new(VpnErrorCode::PrivilegesDenied, "cancelled")));
    h.connect();
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::PrivilegesDenied));
}

#[tokio::test(start_paused = true)]
async fn refuses_to_spawn_an_untrusted_binary_and_fails_fast() {
    let h = setup()
        .settings(|s| s.hip_script_path = Some("/home/alice/hip.sh".into()))
        .profile(|p| p.auth_mode = AuthMode::Auto)
        .build();
    h.set_saved_password(None);
    h.oc.verify_result(Err(VpnError::new(
        VpnErrorCode::PrivilegesDenied,
        "/home/alice/hip.sh is not owned by root",
    )));
    h.connect();
    flush().await;
    assert_eq!(
        h.oc.verify_calls()[0],
        ElevatedFiles {
            binary: "/usr/sbin/openconnect".into(),
            hip_script_path: Some("/home/alice/hip.sh".into())
        }
    );
    assert!(h.spawner.requests().is_empty());
    assert_eq!(h.prelogin.calls(), 0, "no prelogin before the trust check");
    assert!(h.prompts().is_empty());
    let e = h.state().error.unwrap();
    assert_eq!((h.status(), e.code), (S::Error, VpnErrorCode::PrivilegesDenied));
    assert!(!e.message.is_empty());
    assert!(e.detail.unwrap().contains("not owned by root"));
}

#[tokio::test(start_paused = true)]
async fn re_checks_the_files_right_before_spawning() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    assert_eq!(h.oc.verify_calls().len(), 1);
    h.oc.verify_reject_once(VpnError::new(VpnErrorCode::PrivilegesDenied, "replaced"));
    h.answer(&h.prompts()[0].id, Some("pw"));
    flush().await;
    assert_eq!(h.oc.verify_calls().len(), 2);
    assert!(h.spawner.requests().is_empty());
    assert_eq!(h.error_code(), Some(VpnErrorCode::PrivilegesDenied));
}

#[tokio::test(start_paused = true)]
async fn spawns_the_verified_real_paths() {
    let h = setup()
        .settings(|s| s.hip_script_path = Some("/usr/local/bin/hip".into()))
        .build();
    h.oc.verify_result(Ok(ElevatedFiles {
        binary: "/usr/sbin/openconnect.real".into(),
        hip_script_path: Some("/usr/libexec/hip.real".into()),
    }));
    h.connect();
    flush().await;
    let req = &h.spawner.requests()[0];
    assert_eq!(req.binary, std::path::PathBuf::from("/usr/sbin/openconnect.real"));
    assert!(
        req.args
            .contains(&"--csd-wrapper=/usr/libexec/hip.real".to_string())
    );
    assert_eq!(req.elevation, gp_core::process::Elevation::Pkexec);
}

#[tokio::test(start_paused = true)]
async fn re_validates_extra_args_before_spawning() {
    let h = setup()
        .settings(|s| s.extra_args = vec!["--script=/tmp/evil".into()])
        .build();
    h.connect();
    flush().await;
    assert!(h.spawner.requests().is_empty());
    assert_eq!(h.status(), S::Error);
}

#[tokio::test(start_paused = true)]
async fn pkexec_exit_code_126_is_privileges_denied() {
    let h = setup().build();
    h.connect();
    flush().await;
    h.spawner.last().exit(126);
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::PrivilegesDenied));
}

#[tokio::test(start_paused = true)]
async fn uses_the_most_specific_error_seen_when_the_process_exits_early() {
    let h = setup().build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("getaddrinfo failed for host 'vpn.example.com': Name or service not known\n");
    p.exit(1);
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!((h.status(), e.code), (S::Error, VpnErrorCode::PortalUnreachable));
    assert_eq!(e.message, "Проверьте адрес портала и подключение к сети.");
    assert!(e.detail.unwrap().contains("Name or service not known"));
}

#[tokio::test(start_paused = true)]
async fn rejects_connect_for_an_unknown_profile_or_while_busy() {
    let h = setup().build();
    assert_eq!(
        h.engine
            .connect("99999999-2222-4333-8444-555555555555", ConnectOptions::default()),
        Err(EngineError::ProfileNotFound)
    );
    connect_and_establish(&h).await;
    let e = h
        .engine
        .connect(PROFILE_ID, ConnectOptions::default())
        .unwrap_err();
    assert_eq!(e.to_string(), "Cannot connect while connected");
}

#[tokio::test(start_paused = true)]
async fn allows_connecting_again_after_an_error() {
    let h = setup().binary(None).build();
    h.connect();
    flush().await;
    assert_eq!(h.status(), S::Error);
    h.oc.set_binary(Some("/usr/bin/openconnect"));
    connect_and_establish(&h).await;
    assert_eq!(h.status(), S::Connected);
}

// ------------------------------------------------------------------ disconnect

#[tokio::test(start_paused = true)]
async fn disconnect_stops_gracefully() {
    let h = setup().build();
    let p = connect_and_establish(&h).await;
    h.engine.disconnect().await;
    assert_eq!((p.stop_calls(), p.kill_calls()), (1, 0));
    assert_eq!(
        h.statuses()[h.statuses().len() - 2..],
        [S::Disconnecting, S::Disconnected]
    );
    let mut want = VpnState::new(S::Disconnected);
    want.profile_id = Some(PROFILE_ID.into());
    assert_eq!(h.state(), want);
}

#[tokio::test(start_paused = true)]
async fn kills_openconnect_when_it_ignores_the_graceful_stop() {
    let h = setup()
        .config(|c| c.stop_timeout = std::time::Duration::from_millis(1000))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    let done = h.disconnect_bg();
    advance(1000).await;
    done.await.unwrap();
    assert_eq!(p.kill_calls(), 1);
    assert_eq!(h.status(), S::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn disconnect_during_authentication_cancels_the_prompt_and_does_not_spawn() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    assert_eq!(h.prompts().len(), 1);
    h.engine.disconnect().await;
    flush().await;
    assert_eq!(h.status(), S::Disconnected);
    assert!(h.spawner.requests().is_empty());
    assert_eq!(
        h.engine.answer_prompt(&h.prompts()[0].id, Some("late".into())),
        Err(EngineError::UnknownPrompt)
    );
}

#[tokio::test(start_paused = true)]
async fn kills_a_process_that_finishes_spawning_after_disconnect() {
    let spawner = FakeSpawner::gated(|_| {});
    let h = setup().spawner(spawner.clone()).build();
    h.connect();
    flush().await;
    h.engine.disconnect().await;
    spawner.release();
    flush().await;
    assert_eq!(spawner.last().kill_calls(), 1);
    assert_eq!(h.status(), S::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn disconnect_when_idle_is_a_no_op() {
    let h = setup().build();
    h.engine.disconnect().await;
    assert!(h.states().is_empty());
}

// ------------------------------------------------------------------ auto-reconnect

#[tokio::test(start_paused = true)]
async fn reconnects_with_2_5_10_30_s_backoff_after_the_tunnel_drops() {
    let h = setup().build();
    let p1 = connect_and_establish(&h).await;
    p1.err("Session terminated by server; exiting.\n");
    p1.exit(2);
    flush().await;
    assert_eq!(
        (h.status(), h.state().profile_id.as_deref()),
        (S::Reconnecting, Some(PROFILE_ID))
    );
    assert_eq!(h.spawner.count(), 1);

    advance(1999).await;
    assert_eq!(h.spawner.count(), 1);
    advance(1).await;
    assert_eq!(h.spawner.count(), 2);
    // The reconnect attempt reuses the in-memory password and stays "reconnecting".
    assert_eq!(h.spawner.last().written(), ["Secr3tPass\n"]);
    assert_eq!(h.status(), S::Reconnecting);

    // Attempt 2 fails before connecting → next delay 5 s.
    h.spawner
        .last()
        .err("Failed to connect to host vpn.example.com\n");
    h.spawner.last().exit(1);
    flush().await;
    advance(4999).await;
    assert_eq!(h.spawner.count(), 2);
    advance(1).await;
    assert_eq!(h.spawner.count(), 3);

    // Attempt 3 fails → 10 s; attempt 4 fails → 30 s; then stays at 30 s.
    for delay in [10_000, 30_000, 30_000] {
        let before = h.spawner.count();
        h.spawner.last().exit(1);
        flush().await;
        advance(delay - 1).await;
        assert_eq!(h.spawner.count(), before);
        advance(1).await;
        assert_eq!(h.spawner.count(), before + 1);
    }

    // Success resets the backoff.
    h.spawner.last().out("Connected as 10.8.0.43\n");
    flush().await;
    assert_eq!(
        (h.status(), h.state().assigned_ip.as_deref()),
        (S::Connected, Some("10.8.0.43"))
    );
    h.spawner.last().exit(1);
    flush().await;
    advance(2000).await;
    assert_eq!(h.spawner.count(), 7);
}

#[tokio::test(start_paused = true)]
async fn gives_up_after_max_reconnect_attempts() {
    let h = setup()
        .config(|c| {
            c.max_reconnect_attempts = 2;
            c.backoff = vec![std::time::Duration::from_millis(100)];
        })
        .build();
    let p = connect_and_establish(&h).await;
    p.exit(1);
    for _ in 0..2 {
        advance(100).await;
        h.spawner.last().exit(1);
    }
    flush().await;
    assert_eq!(h.spawner.count(), 3);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::TunnelFailed))
    );
}

#[tokio::test(start_paused = true)]
async fn does_not_reconnect_when_auto_reconnect_is_off() {
    let h = setup().settings(|s| s.auto_reconnect = false).build();
    let p = connect_and_establish(&h).await;
    p.err("Session terminated by server; exiting.\n");
    p.exit(2);
    flush().await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::TunnelFailed))
    );
}

#[tokio::test(start_paused = true)]
async fn does_not_reconnect_a_first_attempt_that_never_connected() {
    let h = setup().build();
    h.connect();
    flush().await;
    h.spawner.last().exit(1);
    flush().await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(h.status(), S::Error);
}

#[tokio::test(start_paused = true)]
async fn stops_retrying_on_a_non_retryable_error_during_reconnect() {
    let h = setup().build();
    let p = connect_and_establish(&h).await;
    p.exit(1);
    advance(2000).await;
    h.spawner
        .last()
        .err("Error executing command as another user: Not authorized\n");
    h.spawner.last().exit(127);
    flush().await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 2);
    assert_eq!(h.error_code(), Some(VpnErrorCode::PrivilegesDenied));
}

#[tokio::test(start_paused = true)]
async fn disconnect_during_the_backoff_wait_cancels_the_reconnect() {
    let h = setup().build();
    let p = connect_and_establish(&h).await;
    p.exit(1);
    flush().await;
    assert_eq!(h.status(), S::Reconnecting);
    h.engine.disconnect().await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(h.status(), S::Disconnected);
}

// ------------------------------------------------------------------ secrets

fn everything(h: &Harness) -> String {
    format!(
        "{:?}{:?}{:?}{:?}",
        h.logger.lines(),
        h.states(),
        h.prompts(),
        h.state()
    )
}

#[tokio::test(start_paused = true)]
async fn never_puts_the_password_or_saml_cookie_into_logs_or_state() {
    let h = setup()
        .profile(|p| p.auth_mode = AuthMode::Auto)
        .prelogin(Ok(saml_prelogin()))
        .build();
    let p = connect_and_establish(&h).await;
    // openconnect echoing secrets (e.g. with --dump-http-traffic)
    p.out("POST body: prelogin-cookie=SAML-COOKIE-VALUE&user=alice\n");
    p.out("debug SAML-COOKIE-VALUE\n");
    p.err("Unexpected 512 result from server SAML-COOKIE-VALUE\n");
    p.exit(1);
    flush().await;
    assert!(!everything(&h).contains("SAML-COOKIE-VALUE"));
}

#[tokio::test(start_paused = true)]
async fn masks_a_password_typed_into_a_prompt() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    h.answer(&h.prompts()[0].id, Some("Typed-Pa55"));
    flush().await;
    h.spawner.last().err("Login failed for Typed-Pa55\n");
    h.spawner.last().exit(1);
    flush().await;
    assert!(!everything(&h).contains("Typed-Pa55"));
    assert_eq!(h.error_code(), Some(VpnErrorCode::AuthFailed));
}

// ------------------------------------------------------------------ rework round (CR-1/2/3/6/7)

#[tokio::test(start_paused = true)]
async fn cr1_keeps_backing_off_when_a_reconnect_fails_before_spawning() {
    let h = setup().profile(|p| p.auth_mode = AuthMode::Auto).build();
    let p = connect_and_establish(&h).await;
    assert_eq!(h.prelogin.calls(), 1);
    h.prelogin.reject_once(VpnError::new(
        VpnErrorCode::PortalUnreachable,
        "Cannot reach portal",
    ));
    p.exit(1);
    flush().await;
    advance(2000).await; // reconnect #1 → prelogin rejects
    assert_eq!(h.prelogin.calls(), 2);
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Reconnecting, Some(VpnErrorCode::PortalUnreachable))
    );
    advance(4999).await;
    assert_eq!(h.prelogin.calls(), 2);
    advance(1).await; // reconnect #2 after 5 s succeeds
    assert_eq!(h.prelogin.calls(), 3);
    assert_eq!(h.spawner.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn cr1_stops_reconnecting_on_a_pre_spawn_non_retryable_error() {
    for code in [
        VpnErrorCode::AuthCancelled,
        VpnErrorCode::PrivilegesDenied,
        VpnErrorCode::AuthFailed,
    ] {
        let h = setup().profile(|p| p.auth_mode = AuthMode::Auto).build();
        let p = connect_and_establish(&h).await;
        h.prelogin.reject_once(VpnError::new(code, "no"));
        p.exit(1);
        flush().await;
        advance(2000).await;
        advance(60_000).await;
        assert_eq!(h.prelogin.calls(), 2, "{code}");
        assert_eq!((h.status(), h.error_code()), (S::Error, Some(code)));
    }
}

#[tokio::test(start_paused = true)]
async fn cr1_a_failing_trust_check_during_reconnect_stops() {
    let h = setup().build();
    let p = connect_and_establish(&h).await;
    h.oc.verify_reject_once(VpnError::new(VpnErrorCode::PrivilegesDenied, "not root-owned"));
    p.exit(1);
    flush().await;
    advance(2000).await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(h.error_code(), Some(VpnErrorCode::PrivilegesDenied));
}

#[tokio::test(start_paused = true)]
async fn cr2_an_openconnect_that_survives_stop_and_kill_is_not_reported_as_disconnected() {
    let h = setup()
        .config(|c| c.stop_timeout = std::time::Duration::from_millis(1000))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    p.set_exit_on_kill(false);
    let done = h.disconnect_bg();
    advance(1000 + 3000).await;
    done.await.unwrap();
    assert_eq!(p.kill_calls(), 1);
    let s = h.state();
    assert_eq!(
        (s.status, s.assigned_ip.as_deref()),
        (S::Connected, Some("10.8.0.42"))
    );
    let e = s.error.unwrap();
    assert_eq!(e.code, VpnErrorCode::PrivilegesDenied);
    assert!(e.message.contains("Нажмите «Отключить» ещё раз"));
    assert!(!h.statuses().contains(&S::Disconnected));
    // the engine still owns the process: no second openconnect can be started
    assert!(
        h.engine
            .connect(PROFILE_ID, ConnectOptions::default())
            .unwrap_err()
            .to_string()
            .starts_with("Cannot connect")
    );
    // Disconnect can be retried …
    p.set_exit_on_stop(true);
    h.engine.disconnect().await;
    assert_eq!(p.stop_calls(), 2);
    let mut want = VpnState::new(S::Disconnected);
    want.profile_id = Some(PROFILE_ID.into());
    assert_eq!(h.state(), want);
}

#[tokio::test(start_paused = true)]
async fn cr2_a_late_exit_after_a_failed_stop_still_finishes_as_disconnected() {
    let h = setup()
        .config(|c| c.stop_timeout = std::time::Duration::from_millis(100))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    p.set_exit_on_kill(false);
    let done = h.disconnect_bg();
    advance(100 + 3000).await;
    done.await.unwrap();
    assert_eq!(h.status(), S::Connected);
    p.exit(0);
    flush().await;
    let mut want = VpnState::new(S::Disconnected);
    want.profile_id = Some(PROFILE_ID.into());
    assert_eq!(h.state(), want);
}

#[tokio::test(start_paused = true)]
async fn cr2_stop_failed_message_is_localized_and_carries_the_hint() {
    let h = setup()
        .settings(|s| s.language = Language::En)
        .config(|c| c.stop_timeout = std::time::Duration::from_millis(10))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    p.set_exit_on_kill(false);
    let done = h.disconnect_bg();
    advance(10 + 3000).await;
    done.await.unwrap();
    let e = h.state().error.unwrap();
    assert!(
        e.message.starts_with(
            "The VPN may still be active: stopping openconnect needs administrator authorization"
        )
    );
    assert_eq!(
        (e.code, e.hint),
        (VpnErrorCode::PrivilegesDenied, Some(VpnErrorHint::StopFailed))
    );
}

#[tokio::test(start_paused = true)]
async fn cr6_repeated_disconnect_calls_share_one_stop() {
    let h = setup()
        .config(|c| c.stop_timeout = std::time::Duration::from_millis(1000))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    let a = h.disconnect_bg();
    let b = h.disconnect_bg();
    let c = h.disconnect_bg();
    advance(1000).await;
    for t in [a, b, c] {
        t.await.unwrap();
    }
    assert_eq!((p.stop_calls(), p.kill_calls()), (1, 1));
    assert_eq!(h.status(), S::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn cr7_a_late_spawned_process_that_cannot_be_killed_is_re_adopted() {
    let spawner = FakeSpawner::gated(|p| p.set_kill_error(Some("pkexec: dismissed")));
    let h = setup().spawner(spawner.clone()).build();
    h.connect();
    flush().await;
    h.engine.disconnect().await;
    assert_eq!(h.status(), S::Disconnected);

    spawner.release();
    flush().await;
    advance(3000).await;
    let late = spawner.last();
    assert_eq!(late.kill_calls(), 1);
    assert!(
        h.log_text()
            .contains("Failed to kill openconnect that started after disconnect")
    );
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Authenticating, Some(VpnErrorCode::PrivilegesDenied))
    );
    assert!(h.engine.connect(PROFILE_ID, ConnectOptions::default()).is_err());
    // retrying Disconnect stops it
    h.engine.disconnect().await;
    assert_eq!(late.stop_calls(), 1);
    assert_eq!(h.status(), S::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn cr3_pending_prompts_can_be_fetched_after_the_push_was_missed() {
    let h = setup().build();
    h.set_saved_password(None);
    h.connect();
    flush().await;
    assert_eq!(h.engine.get_pending_prompts(), h.prompts());
    h.answer(&h.prompts()[0].id, Some("pw"));
    assert!(h.engine.get_pending_prompts().is_empty());
}

// ------------------------------------------------------------------ message/detail split (DR-3/DR-11)

#[tokio::test(start_paused = true)]
async fn message_is_the_next_step_and_detail_the_technical_cause() {
    let h = setup().build();
    h.connect();
    flush().await;
    h.spawner.last().err("Login failed.\n");
    h.spawner.last().exit(1);
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!(
        e,
        gp_core::VpnStateError {
            code: VpnErrorCode::AuthFailed,
            message: "Проверьте логин, пароль или одноразовый код и попробуйте снова.".into(),
            detail: Some("Login failed.".into()),
            hint: None,
        }
    );
    assert!(!e.message.contains('('));
}

#[tokio::test(start_paused = true)]
async fn tls_message_tells_where_to_find_the_pin() {
    let h = setup().settings(|s| s.language = Language::En).build();
    h.connect();
    flush().await;
    h.spawner
        .last()
        .err("Enter 'yes' to accept, 'no' to abort; anything else to view: ");
    advance(200).await;
    h.spawner.last().exit(1);
    flush().await;
    let m = h.state().error.unwrap().message;
    assert!(
        m.contains("--servercert=pin-sha256:<…>") && m.contains("the pin value is in the log"),
        "{m}"
    );
}

#[tokio::test(start_paused = true)]
async fn untrusted_binary_shows_the_install_hint_with_the_reason_in_detail() {
    let h = setup().build();
    h.oc.verify_result(Err(UntrustedPathError::new(
        "/opt/homebrew/bin/openconnect",
        "/opt/homebrew/bin is not owned by root",
    )
    .into()));
    h.connect();
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!(e.code, VpnErrorCode::PrivilegesDenied);
    assert!(e.message.contains("MacPorts"));
    assert!(
        e.detail
            .unwrap()
            .contains("/opt/homebrew/bin is not owned by root")
    );
}

#[tokio::test(start_paused = true)]
async fn detail_never_leaks_secrets() {
    let h = setup().settings(|s| s.auto_reconnect = false).build();
    let p = connect_and_establish(&h).await;
    p.err("Unexpected 512 result from server Secr3tPass\n");
    p.exit(1);
    flush().await;
    assert!(
        !h.state()
            .error
            .unwrap()
            .detail
            .unwrap_or_default()
            .contains("Secr3tPass")
    );
}

// ------------------------------------------------------------------ code-review round 2 (CR-14/CR-15)

#[tokio::test(start_paused = true)]
async fn cr14_disconnect_during_a_forced_stop_ends_disconnected_without_reconnect() {
    let h = setup()
        .config(|c| c.stop_timeout = std::time::Duration::from_secs(10))
        .build();
    let p = connect_and_establish(&h).await;
    p.set_exit_on_stop(false);
    // an internal failure while handling a prompt → forced stop with a retryable code (UNKNOWN)
    p.set_write_error(Some("EPIPE"));
    p.err("Username:");
    advance(200).await;
    assert_eq!(p.stop_calls(), 1);

    let done = h.disconnect_bg();
    flush().await;
    assert_eq!(h.status(), S::Disconnecting);
    assert_eq!(
        p.stop_calls(),
        1,
        "joined the in-flight stop, no second stop chain"
    );
    p.exit(0);
    done.await.unwrap();
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 1);
    let mut want = VpnState::new(S::Disconnected);
    want.profile_id = Some(PROFILE_ID.into());
    assert_eq!(h.state(), want);
}

#[tokio::test(start_paused = true)]
async fn cr15_connect_is_refused_until_a_process_started_during_disconnect_is_disposed() {
    let spawner = FakeSpawner::gated(|p| p.set_exit_on_kill(false)); // the kill takes a while
    let h = setup().spawner(spawner.clone()).build();
    h.connect();
    flush().await;
    h.engine.disconnect().await;
    assert_eq!(h.status(), S::Disconnected);
    assert_eq!(
        h.engine.connect(PROFILE_ID, ConnectOptions::default()),
        Err(EngineError::StillRunning)
    );

    spawner.release();
    flush().await;
    let late = spawner.last();
    assert_eq!(late.kill_calls(), 1);
    assert!(
        h.engine.connect(PROFILE_ID, ConnectOptions::default()).is_err(),
        "kill still pending"
    );
    late.exit_signal("SIGKILL");
    flush().await;
    h.connect(); // now accepted
    assert_ne!(h.status(), S::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn cr15_a_spawn_failure_after_disconnect_releases_the_busy_marker() {
    let spawner = FakeSpawner::gated(|_| {});
    let h = setup().spawner(spawner.clone()).build();
    h.connect();
    flush().await;
    h.engine.disconnect().await;
    let e = h
        .engine
        .connect(PROFILE_ID, ConnectOptions::default())
        .unwrap_err();
    assert!(e.to_string().contains("still running"));
    spawner.fail_pending(SpawnError::new(VpnErrorCode::PrivilegesDenied, "UAC cancelled"));
    flush().await;
    assert_eq!(h.status(), S::Disconnected);
    h.connect();
}

#[tokio::test(start_paused = true)]
async fn cr15_if_the_late_kill_fails_the_engine_keeps_ownership() {
    let spawner = FakeSpawner::gated(|p| p.set_kill_error(Some("pkexec dismissed")));
    let h = setup().spawner(spawner.clone()).build();
    h.connect();
    flush().await;
    h.engine.disconnect().await;
    spawner.release();
    flush().await;
    advance(3000).await;
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Authenticating, Some(VpnErrorCode::PrivilegesDenied))
    );
    assert!(h.engine.connect(PROFILE_ID, ConnectOptions::default()).is_err());
    h.engine.disconnect().await;
    assert_eq!(spawner.last().stop_calls(), 1);
    assert_eq!(h.status(), S::Disconnected);
    h.connect();
}

// ------------------------------------------------------------------ masked values from the UI (CR-17)

#[tokio::test(start_paused = true)]
async fn cr17a_a_masked_select_option_is_mapped_back_to_the_raw_option() {
    let h = setup().saved_password("Berlin").build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Choose site: [Berlin-GW|Munich-GW]:");
    advance(200).await;
    let prompt = h.prompts()[0].clone();
    assert_eq!(
        prompt.options,
        Some(vec!["***-GW".to_string(), "Munich-GW".to_string()])
    );
    h.answer(&prompt.id, Some("***-GW"));
    flush().await;
    assert_eq!(p.written(), ["Berlin\n", "Berlin-GW\n"]);
    assert_ne!(h.status(), S::Error);
}

#[tokio::test(start_paused = true)]
async fn cr17a_an_ambiguous_masked_option_is_rejected_safely() {
    let h = setup().saved_password("Berlin").build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Challenge:");
    advance(200).await;
    h.answer(&h.prompts()[0].id, Some("Munich")); // second registered secret
    flush().await;
    p.err("Choose site: [Berlin-GW|Munich-GW]:");
    advance(200).await;
    let prompt = h.prompts()[1].clone();
    assert_eq!(
        prompt.options,
        Some(vec!["***-GW".to_string(), "***-GW".to_string()])
    );
    h.answer(&prompt.id, Some("***-GW"));
    flush().await;
    assert_eq!(p.written(), ["Berlin\n", "Munich\n"]);
    assert_eq!(h.error_code(), Some(VpnErrorCode::AuthCancelled));
}

async fn connect_with_gateways(h: &Harness, list: &str) {
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.out(list);
    p.out("Connected as 10.0.0.2\n");
    flush().await;
    h.engine.disconnect().await;
}

#[tokio::test(start_paused = true)]
async fn cr17b_a_masked_gateway_from_the_ui_is_translated_back_for_authgroup() {
    let h = setup().saved_password("Berlin").build();
    connect_with_gateways(
        &h,
        "2 gateway servers available:\n  Berlin-GW (berlin.example.com)\n  Munich-GW (munich.example.com)\n",
    )
    .await;
    // while connected the UI saw the masked name
    assert!(
        h.states()
            .iter()
            .any(|s| s.gateways.iter().flatten().any(|g| g.name == "***-GW"))
    );
    h.connect_with(opts_gateway("***-GW"));
    flush().await;
    assert!(
        h.spawner
            .requests()
            .last()
            .unwrap()
            .args
            .contains(&"--authgroup=Berlin-GW".to_string())
    );
}

#[tokio::test(start_paused = true)]
async fn cr17b_unmasked_gateways_pass_through_unchanged() {
    let h = setup().saved_password("Berlin").build();
    connect_with_gateways(
        &h,
        "2 gateway servers available:\n  Berlin-GW (berlin.example.com)\n  Munich-GW (munich.example.com)\n",
    )
    .await;
    h.connect_with(opts_gateway("Munich-GW"));
    flush().await;
    assert!(
        h.spawner
            .requests()
            .last()
            .unwrap()
            .args
            .contains(&"--authgroup=Munich-GW".to_string())
    );
}

#[tokio::test(start_paused = true)]
async fn cr17b_an_ambiguous_masked_gateway_falls_back_to_automatic_selection() {
    let h = setup().saved_password("Berlin").build();
    h.connect();
    flush().await;
    let p = h.spawner.last();
    p.err("Challenge:");
    advance(200).await;
    h.answer(&h.prompts()[0].id, Some("Munich"));
    flush().await;
    p.out("2 gateway servers available:\n  Berlin-GW (b.example.com)\n  Munich-GW (m.example.com)\n");
    p.out("Connected as 10.0.0.2\n");
    flush().await;
    h.engine.disconnect().await;
    h.connect_with(opts_gateway("***-GW"));
    flush().await;
    assert!(
        !h.spawner
            .requests()
            .last()
            .unwrap()
            .args
            .iter()
            .any(|a| a.starts_with("--authgroup"))
    );
    assert!(h.log_text().contains("Gateway \"***-GW\" is ambiguous"));
}

// ------------------------------------------------------------------ localization and hints (B2/A2)

#[tokio::test(start_paused = true)]
async fn relocalizes_an_existing_error_keeping_code_hint_and_detail() {
    let h = setup().binary(Some("/home/alice/openconnect")).build();
    h.oc.verify_result(Err(UntrustedPathError::new(
        "/home/alice/openconnect",
        "/home/alice is not owned by root",
    )
    .into()));
    h.connect();
    flush().await;
    let ru = h.state().error.unwrap();
    assert_eq!(
        (ru.code, ru.hint),
        (
            VpnErrorCode::PrivilegesDenied,
            Some(VpnErrorHint::UntrustedBinary)
        )
    );
    assert!(ru.message.contains("apt install"));

    let emitted = h.states().len();
    h.set_language(Language::Uk);
    h.engine.relocalize();
    let uk = h.state().error.unwrap();
    assert_eq!(h.states().len(), emitted + 1);
    assert!(uk.message.starts_with("Встановіть OpenConnect із репозиторію"));
    assert_eq!((uk.code, uk.hint, &uk.detail), (ru.code, ru.hint, &ru.detail));

    h.engine.relocalize(); // same language → no extra emission
    assert_eq!(h.states().len(), emitted + 1);
}

#[tokio::test(start_paused = true)]
async fn relocalize_is_a_no_op_without_an_error() {
    let h = setup().build();
    h.engine.relocalize();
    assert!(h.states().is_empty());
}

#[tokio::test(start_paused = true)]
async fn uses_the_platform_for_the_untrusted_binary_text() {
    let h = setup().platform(Platform::Win32).build();
    h.oc.verify_result(Err(
        VpnError::new(VpnErrorCode::PrivilegesDenied, "x").with_hint(VpnErrorHint::UntrustedBinary)
    ));
    h.connect();
    flush().await;
    assert!(h.state().error.unwrap().message.contains("Program Files"));
}

#[tokio::test(start_paused = true)]
async fn settings_not_confirmed_hint_is_carried_into_state() {
    let h = setup().build();
    h.oc.verify_result(Err(VpnError::new(
        VpnErrorCode::PrivilegesDenied,
        "Changed openconnect settings were not confirmed",
    )
    .with_hint(VpnErrorHint::SettingsNotConfirmed)));
    h.connect();
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!(e.hint, Some(VpnErrorHint::SettingsNotConfirmed));
    assert!(e.message.contains("подтвердите"));
}

#[tokio::test(start_paused = true)]
async fn subscribers_can_unsubscribe_by_dropping_the_receiver() {
    let h = setup().build();
    let extra = h.engine.subscribe();
    drop(extra);
    connect_and_establish(&h).await;
    assert_eq!(h.status(), S::Connected);
    let _ = Arc::strong_count(&h.logger);
}
