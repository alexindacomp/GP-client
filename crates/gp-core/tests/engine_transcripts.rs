//! The engine driven by recorded openconnect
//! 9.x GlobalProtect output (fixtures/openconnect/*.txt).

#![allow(clippy::many_single_char_names, clippy::unwrap_used)] // test crate; short names (p, s, …) keep the scenarios compact

mod common;

use std::time::Duration;

use common::*;
use gp_core::prelogin::{SamlMethod, parse_prelogin};
use gp_core::saml::{SamlCookieName, SamlOutcome, extract_saml_from_html};
use gp_core::{AuthMode, ConnectOptions, Gateway, PromptKind, VpnErrorCode, VpnState, VpnStatus};

use VpnStatus as S;

fn gw(name: &str, address: &str, priority: Option<f64>) -> Gateway {
    Gateway {
        name: name.into(),
        address: address.into(),
        priority,
    }
}

const MODES: [(&str, PlayOptions); 3] = [
    (
        "line by line",
        PlayOptions {
            chunk_size: None,
            split_prompt_gap_ms: None,
        },
    ),
    // Pipe reads do not respect line boundaries; prompts may arrive in pieces within the debounce.
    (
        "re-chunked every 7 chars, prompts split 100 ms apart",
        PlayOptions {
            chunk_size: Some(7),
            split_prompt_gap_ms: Some(100),
        },
    ),
    (
        "re-chunked every 1 char, prompts split 140 ms apart",
        PlayOptions {
            chunk_size: Some(1),
            split_prompt_gap_ms: Some(140),
        },
    ),
];

async fn password_otp_gateways(play: PlayOptions, mode: &str) {
    let h = harness()
        .profile(|p| p.preferred_gateway = Some("gw-us.example.com".into()))
        .saved_password("C0rrect-Horse")
        .build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    // The password goes to stdin as soon as the process starts; never on the command line.
    assert_eq!(proc.written(), ["C0rrect-Horse\n"], "{mode}");
    assert!(!h.spawner.requests()[0].args.join(" ").contains("C0rrect-Horse"));

    let rest = play_until_prompt(&proc, &load_transcript("password-otp-gateways.txt", false), play).await;
    // Preferred gateway given by address is matched to the portal's label automatically.
    assert_eq!(proc.last_written().as_deref(), Some("US East\n"), "{mode}");
    assert!(h.prompts().is_empty(), "{mode}");

    let rest = play_until_prompt(&proc, &rest, play).await;
    let prompts = h.prompts();
    assert_eq!(prompts.len(), 1, "{mode}");
    assert_eq!(prompts[0].kind, PromptKind::Otp);
    assert_eq!(
        prompts[0].message,
        "Enter the 6-digit code from your authenticator app\nChallenge"
    );
    assert_eq!(prompts[0].options, None);
    assert_eq!(h.engine.get_pending_prompts().len(), 1);
    assert_eq!(h.status(), S::Authenticating);

    h.answer(&prompts[0].id, Some("481516"));
    flush().await;
    assert_eq!(proc.last_written().as_deref(), Some("481516\n"));
    assert!(h.engine.get_pending_prompts().is_empty());

    play_all(&proc, &rest, play).await;
    // Nothing else (e.g. a half-received line) was ever taken for a prompt or answered.
    assert_eq!(h.prompts().len(), 1, "{mode}");
    assert_eq!(
        proc.written(),
        ["C0rrect-Horse\n", "US East\n", "481516\n"],
        "{mode}"
    );
    assert_eq!(
        h.status_path(),
        [S::Prelogin, S::Authenticating, S::Connecting, S::Connected],
        "{mode}"
    );
    let mut want = VpnState::new(S::Connected);
    want.profile_id = Some(PROFILE_ID.into());
    want.assigned_ip = Some("10.8.0.42".into());
    want.connected_at = Some(NOW_MS);
    want.gateway = Some(gw("US East", "gw-us.example.com", Some(2.0)));
    want.gateways = Some(vec![
        gw("Europe", "gw-eu.example.com", Some(1.0)),
        gw("US East", "gw-us.example.com", Some(2.0)),
    ]);
    assert_eq!(h.state(), want, "{mode}");
}

#[tokio::test(start_paused = true)]
async fn password_otp_gateways_line_by_line() {
    password_otp_gateways(MODES[0].1, MODES[0].0).await;
}

#[tokio::test(start_paused = true)]
async fn password_otp_gateways_rechunked_7() {
    password_otp_gateways(MODES[1].1, MODES[1].0).await;
}

#[tokio::test(start_paused = true)]
async fn password_otp_gateways_rechunked_1() {
    password_otp_gateways(MODES[2].1, MODES[2].0).await;
}

#[tokio::test(start_paused = true)]
async fn asks_for_username_and_password_using_the_prelogin_labels() {
    let prelogin = parse_prelogin(&fixture("prelogin-password.xml")).unwrap();
    let h = harness()
        .profile(|p| {
            p.auth_mode = AuthMode::Auto;
            p.username = None;
        })
        .prelogin(Ok(prelogin))
        .build();
    h.connect();
    flush().await;
    let p = h.prompts().last().cloned().unwrap();
    assert_eq!((p.kind, p.message.as_str()), (PromptKind::Text, "Корп. логин"));
    h.answer(&p.id, Some("  bob  "));
    flush().await;
    let p = h.prompts().last().cloned().unwrap();
    assert_eq!(
        (p.kind, p.message.as_str()),
        (
            PromptKind::Password,
            "Enter login credentials & OTP\nPassword + <token>"
        )
    );
    h.answer(&p.id, Some("pw-and-123456"));
    flush().await;
    assert!(h.spawner.requests()[0].args.contains(&"--user=bob".to_string()));
    assert_eq!(h.spawner.last().written(), ["pw-and-123456\n"]);
}

#[tokio::test(start_paused = true)]
async fn an_empty_username_answer_cancels_without_spawning() {
    let h = harness().profile(|p| p.username = None).build();
    h.connect();
    flush().await;
    h.answer(&h.prompts()[0].id, Some("   "));
    flush().await;
    assert!(h.spawner.requests().is_empty());
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::AuthCancelled))
    );
}

#[tokio::test(start_paused = true)]
async fn answers_a_later_username_prompt_with_the_known_username() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    proc.err("Enter login credentials\nUsername:");
    advance(PROMPT_SETTLE_MS).await;
    assert_eq!(proc.last_written().as_deref(), Some("alice\n"));
    assert!(h.prompts().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_password_re_asked_after_a_failed_login_is_not_answered_in_a_loop() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    play_all(
        &proc,
        &load_transcript("login-failed.txt", false),
        PlayOptions::default(),
    )
    .await;
    flush().await;
    // Only the initial password was written; the re-prompt stopped openconnect.
    assert_eq!(proc.written(), ["C0rrect-Horse\n"]);
    assert_eq!(proc.stop_calls(), 1);
    assert!(h.prompts().is_empty());
    let e = h.state().error.unwrap();
    // QA-1: the specific cause, not the generic follow-up "Login failed."
    assert_eq!(
        (h.status(), e.code, e.detail.as_deref()),
        (
            S::Error,
            VpnErrorCode::AuthFailed,
            Some("Invalid username or password")
        )
    );
}

// ------------------------------------------------------------------ SAML

fn saml_harness() -> Harness {
    let prelogin = parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap();
    let Some(SamlOutcome::Success(saml)) = extract_saml_from_html(&fixture("saml-success.html")) else {
        panic!("fixture must be a successful SAML response")
    };
    harness()
        .profile(|p| {
            p.auth_mode = AuthMode::Auto;
            p.username = None;
        })
        .prelogin(Ok(prelogin))
        .saml(Ok(saml))
        .build()
}

#[tokio::test(start_paused = true)]
async fn saml_connects_with_the_cookie_on_stdin_and_picks_the_first_gateway() {
    let h = saml_harness();
    h.connect();
    flush().await;
    let calls = h.saml.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, PROFILE_ID);
    assert_eq!(calls[0].1.saml_method, Some(SamlMethod::Redirect));
    let args = h.spawner.requests()[0].args.clone();
    for a in [
        "--protocol=gp",
        "--usergroup=portal:prelogin-cookie",
        "--user=j.doe@example.com",
        "--passwd-on-stdin",
    ] {
        assert!(args.contains(&a.to_string()), "{a}");
    }
    assert!(!args.join(" ").contains("PRELOGIN-COOKIE-abc123XYZ"));
    let proc = h.spawner.last();
    assert_eq!(proc.written(), ["PRELOGIN-COOKIE-abc123XYZ\n"]);
    play_all(
        &proc,
        &load_transcript("saml-gateways.txt", false),
        PlayOptions::default(),
    )
    .await;
    assert_eq!(proc.last_written().as_deref(), Some("Europe\n"));
    assert!(h.prompts().is_empty(), "SAML needs no password prompt");
    assert_eq!(
        h.status_path(),
        [S::Prelogin, S::Authenticating, S::Connecting, S::Connected]
    );
    let s = h.state();
    assert_eq!(
        (s.status, s.assigned_ip.as_deref()),
        (S::Connected, Some("10.8.0.77"))
    );
    let g = s.gateway.unwrap();
    assert_eq!(
        (g.name.as_str(), g.address.as_str()),
        ("Europe", "gw-eu.example.com")
    );
    assert_eq!(SamlCookieName::PreloginCookie.as_str(), "prelogin-cookie");
}

#[tokio::test(start_paused = true)]
async fn the_cookie_never_appears_in_logs_states_or_prompts() {
    let h = saml_harness();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    proc.err("POST https://gw-eu.example.com/ssl-vpn/login.esp\n");
    proc.err("prelogin-cookie=PRELOGIN-COOKIE-abc123XYZ&user=j.doe%40example.com\n");
    proc.err(&format!(
        "Cookie: {}\n",
        encode_uri_component("PRELOGIN-COOKIE-abc123XYZ")
    ));
    proc.err("Unexpected 512 result from server PRELOGIN-COOKIE-abc123XYZ\n");
    proc.exit(1);
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::AuthFailed));
    let everything = format!(
        "{:?}{:?}{:?}{:?}",
        h.logger.lines(),
        h.states(),
        h.prompts(),
        h.state()
    );
    assert!(!everything.contains("PRELOGIN-COOKIE-abc123XYZ"));
}

// ------------------------------------------------------------------ gateway selection

async fn select_from(h: &Harness, options: &str) -> Option<String> {
    let proc = h.spawner.last();
    proc.err(
        "2 gateway servers available:\n  Europe (gw-eu.example.com) [1]\n  US East (gw-us.example.com) [2]\n",
    );
    proc.err(&format!(
        "Please select GlobalProtect gateway.\nGATEWAY: [{options}]:"
    ));
    advance(PROMPT_SETTLE_MS).await;
    proc.last_written()
}

#[tokio::test(start_paused = true)]
async fn a_gateway_chosen_for_this_connection_overrides_the_profile_preference() {
    let h = harness()
        .profile(|p| p.preferred_gateway = Some("Europe".into()))
        .saved_password("C0rrect-Horse")
        .build();
    h.connect_with(ConnectOptions {
        gateway: Some("US East".into()),
        password: None,
    });
    flush().await;
    assert!(
        h.spawner.requests()[0]
            .args
            .contains(&"--authgroup=US East".to_string())
    );
    assert_eq!(
        select_from(&h, "Europe|US East").await.as_deref(),
        Some("US East\n")
    );
}

#[tokio::test(start_paused = true)]
async fn matches_the_preferred_gateway_by_label_case_insensitively() {
    let h = harness()
        .profile(|p| p.preferred_gateway = Some("us east".into()))
        .saved_password("C0rrect-Horse")
        .build();
    h.connect();
    flush().await;
    assert_eq!(
        select_from(&h, "Europe|US East").await.as_deref(),
        Some("US East\n")
    );
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_the_first_gateway_when_the_preferred_one_is_not_offered() {
    let h = harness()
        .profile(|p| p.preferred_gateway = Some("gw-asia.example.com".into()))
        .saved_password("C0rrect-Horse")
        .build();
    h.connect();
    flush().await;
    assert_eq!(
        select_from(&h, "Europe|US East").await.as_deref(),
        Some("Europe\n")
    );
    assert!(
        h.log_text()
            .contains("Gateway \"gw-asia.example.com\" is not offered by the portal")
    );
}

#[tokio::test(start_paused = true)]
async fn remembers_the_gateway_list_after_disconnecting() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    select_from(&h, "Europe|US East").await;
    h.spawner.last().err("Connected as 10.8.0.42, using SSL\n");
    flush().await;
    h.engine.disconnect().await;
    let mut want = VpnState::new(S::Disconnected);
    want.profile_id = Some(PROFILE_ID.into());
    want.gateways = Some(vec![
        gw("Europe", "gw-eu.example.com", Some(1.0)),
        gw("US East", "gw-us.example.com", Some(2.0)),
    ]);
    assert_eq!(h.state(), want);
}

#[tokio::test(start_paused = true)]
async fn forwards_a_non_gateway_choice_and_rejects_an_answer_that_is_not_an_option() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    proc.err("Choose your authentication method\nMETHOD: [Push|SMS]:");
    advance(PROMPT_SETTLE_MS).await;
    let prompts = h.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].kind, PromptKind::Select);
    assert_eq!(prompts[0].message, "Choose your authentication method");
    assert_eq!(
        prompts[0].options,
        Some(vec!["Push".to_string(), "SMS".to_string()])
    );
    h.answer(&prompts[0].id, Some("Carrier pigeon"));
    flush().await;
    assert_eq!(
        proc.written(),
        ["C0rrect-Horse\n"],
        "nothing written for the bad answer"
    );
    assert_eq!(proc.stop_calls(), 1);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::AuthCancelled))
    );
}

// ------------------------------------------------------------------ error codes from realistic output

async fn run_failing(name: &str) -> Harness {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    play_all(&proc, &load_transcript(name, false), PlayOptions::default()).await;
    proc.exit(1);
    flush().await;
    h
}

#[tokio::test(start_paused = true)]
async fn realistic_failures_map_to_codes_with_the_root_cause_as_detail() {
    for (name, code, detail_check) in [
        (
            "portal-dns-failure.txt",
            VpnErrorCode::PortalUnreachable,
            "=getaddrinfo failed for host 'vpn.example.com': Name or service not known",
        ),
        (
            "portal-unreachable.txt",
            VpnErrorCode::PortalUnreachable,
            "=Failed to connect to 203.0.113.10:443: Connection timed out",
        ),
        (
            "tun-not-root.txt",
            VpnErrorCode::PrivilegesDenied,
            "~Failed to bind local tun device (TUNSETIFF): Operation not permitted",
        ),
        (
            "vpnc-script-error.txt",
            VpnErrorCode::TunnelFailed,
            "~vpnc-script' returned error 1",
        ),
    ] {
        let h = run_failing(name).await;
        let s = h.state();
        assert_eq!(s.status, S::Error, "{name}");
        let e = s.error.unwrap();
        assert_eq!(e.code, code, "{name}");
        let detail = e.detail.unwrap();
        match detail_check.split_at(1) {
            ("=", want) => assert_eq!(detail, want, "{name}"),
            (_, want) => assert!(detail.contains(want), "{name}: {detail}"),
        }
        assert!(!e.message.is_empty());
        // A first attempt that never connected is not retried.
        advance(60_000).await;
        assert_eq!(h.spawner.count(), 1, "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn qa1_the_specific_auth_failure_wins_over_the_later_generic_one() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    proc.err("Invalid username or password\nLogin failed.\n");
    proc.exit(1);
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!(
        (e.code, e.detail.as_deref()),
        (VpnErrorCode::AuthFailed, Some("Invalid username or password"))
    );
}

#[tokio::test(start_paused = true)]
async fn qa1_a_strictly_more_specific_code_replaces_a_less_specific_one() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    proc.err("Failed to connect to host vpn.example.com\n");
    proc.err("Server certificate verify failed: signer not found\n");
    proc.exit(1);
    flush().await;
    assert_eq!(h.error_code(), Some(VpnErrorCode::TlsError));
}

#[tokio::test(start_paused = true)]
async fn untrusted_certificate_answers_no_and_reports_the_pin_line_as_detail() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    play_all(
        &proc,
        &load_transcript("cert-untrusted.txt", false),
        PlayOptions::default(),
    )
    .await;
    assert_eq!(proc.last_written().as_deref(), Some("no\n"));
    assert!(
        h.prompts().is_empty(),
        "the user is never asked to accept an untrusted certificate"
    );
    proc.err("SSL connection failure: Error in the certificate verification.\n");
    proc.err("Failed to open HTTPS connection to vpn.example.com\nFailed to complete authentication\n");
    proc.exit(1);
    flush().await;
    let e = h.state().error.unwrap();
    assert_eq!((h.status(), e.code), (S::Error, VpnErrorCode::TlsError));
    assert_eq!(
        e.detail.as_deref(),
        Some("--servercert pin-sha256:xp3scfzy3rOgQEXnfPiYKrUk7D66a8b8O+gEXaMPleE=")
    );
}

#[tokio::test(start_paused = true)]
async fn a_dropped_established_tunnel_goes_to_reconnecting_with_the_cause() {
    let h = harness().saved_password("C0rrect-Horse").build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    play_all(
        &proc,
        &load_transcript("saml-gateways.txt", false),
        PlayOptions::default(),
    )
    .await;
    assert_eq!(h.status(), S::Connected);
    play_all(
        &proc,
        &load_transcript("session-drop.txt", false),
        PlayOptions::default(),
    )
    .await;
    proc.exit(1);
    flush().await;
    let s = h.state();
    assert_eq!(
        (s.status, s.profile_id.as_deref()),
        (S::Reconnecting, Some(PROFILE_ID))
    );
    let e = s.error.unwrap();
    assert_eq!(
        (e.code, e.detail.as_deref()),
        (
            VpnErrorCode::TunnelFailed,
            Some("Unrecoverable I/O error; exiting.")
        )
    );
}

// ------------------------------------------------------------------ auto-reconnect

async fn establish(h: &Harness) {
    h.connect();
    flush().await;
    h.spawner
        .last()
        .err("GlobalProtect login returned authentication-source=local\nConnected as 10.8.0.42, using SSL\n");
    flush().await;
    assert_eq!(h.status(), S::Connected);
}

fn backoff_100ms(c: &mut gp_core::vpn::EngineConfig) {
    c.backoff = vec![Duration::from_millis(100)];
}

#[tokio::test(start_paused = true)]
async fn waits_2_5_10_30_30_s_between_failing_reconnect_attempts() {
    let h = harness().saved_password("C0rrect-Horse").build();
    establish(&h).await;
    let mut spawn_times = Vec::new();
    h.spawner.last().exit(1);
    flush().await;
    for _ in 0..5 {
        let before = h.spawner.count();
        let mut t = 0;
        while h.spawner.count() == before {
            advance(500).await;
            t += 500;
        }
        spawn_times.push(t);
        h.spawner
            .last()
            .err("Failed to connect to host vpn.example.com\n");
        h.spawner.last().exit(1);
        flush().await;
    }
    assert_eq!(spawn_times, [2000, 5000, 10_000, 30_000, 30_000]);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Reconnecting, Some(VpnErrorCode::PortalUnreachable))
    );
}

#[tokio::test(start_paused = true)]
async fn reconnect_attempts_keep_the_gateway_chosen_for_the_original_connection() {
    let h = harness()
        .saved_password("C0rrect-Horse")
        .config(backoff_100ms)
        .build();
    h.connect_with(ConnectOptions {
        gateway: Some("US East".into()),
        password: None,
    });
    flush().await;
    h.spawner.last().err("Connected as 10.8.0.42, using SSL\n");
    flush().await;
    h.spawner.last().exit(1);
    advance(100).await;
    assert_eq!(h.spawner.count(), 2);
    assert!(
        h.spawner.requests()[1]
            .args
            .contains(&"--authgroup=US East".to_string())
    );
}

#[tokio::test(start_paused = true)]
async fn a_typed_password_is_reused_for_reconnects_then_forgotten_on_disconnect() {
    let h = harness().config(backoff_100ms).build();
    h.connect();
    flush().await;
    h.answer(&h.prompts()[0].id, Some("Typed-Pa55"));
    flush().await;
    h.spawner.last().err("Connected as 10.8.0.42, using SSL\n");
    flush().await;
    h.spawner.last().exit(1);
    advance(100).await;
    assert_eq!(h.prompts().len(), 1);
    assert_eq!(h.spawner.last().written(), ["Typed-Pa55\n"]);
    h.engine.disconnect().await;
    h.connect();
    flush().await;
    let prompts = h.prompts();
    assert_eq!(prompts.len(), 2, "asked again after an explicit disconnect");
    assert_eq!(prompts[1].kind, PromptKind::Password);
}

#[tokio::test(start_paused = true)]
async fn disconnect_while_a_reconnect_attempt_is_running_schedules_nothing_more() {
    let h = harness()
        .saved_password("C0rrect-Horse")
        .config(backoff_100ms)
        .build();
    establish(&h).await;
    h.spawner.last().exit(1);
    advance(100).await;
    assert_eq!(h.spawner.count(), 2);
    assert_eq!(h.status(), S::Reconnecting);
    h.engine.disconnect().await;
    assert_eq!(h.spawner.last().stop_calls(), 1);
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 2);
    assert_eq!((h.status(), h.state().error), (S::Disconnected, None));
}

#[tokio::test(start_paused = true)]
async fn a_profile_deleted_during_the_backoff_wait_ends_as_disconnected() {
    let h = harness()
        .saved_password("C0rrect-Horse")
        .config(backoff_100ms)
        .build();
    establish(&h).await;
    h.spawner.last().exit(1);
    flush().await;
    h.set_profile_exists(false);
    advance(100).await;
    assert_eq!(h.spawner.count(), 1);
    assert_eq!(h.state(), VpnState::new(S::Disconnected));
}

#[tokio::test(start_paused = true)]
async fn an_untrusted_certificate_during_a_reconnect_is_not_retried() {
    let h = harness()
        .saved_password("C0rrect-Horse")
        .config(backoff_100ms)
        .build();
    establish(&h).await;
    h.spawner.last().exit(1);
    advance(100).await;
    let proc = h.spawner.last();
    play_all(
        &proc,
        &load_transcript("cert-untrusted.txt", false),
        PlayOptions::default(),
    )
    .await;
    proc.exit(1);
    flush().await;
    advance(60_000).await;
    assert_eq!(h.spawner.count(), 2);
    assert_eq!(
        (h.status(), h.error_code()),
        (S::Error, Some(VpnErrorCode::TlsError))
    );
}
