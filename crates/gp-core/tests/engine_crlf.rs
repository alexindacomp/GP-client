//! openconnect.exe on Windows (and the elevated helper)
//! may emit CRLF line endings and prompts terminated by a lone CR. Every recorded transcript is
//! replayed with LF and with CRLF in every chunking mode; the engine must behave identically.

#![allow(clippy::many_single_char_names, clippy::unwrap_used)] // test crate; short names (p, s, …) keep the scenarios compact

mod common;

use common::*;
use gp_core::{AuthPrompt, VpnState};

const MODES: [(&str, PlayOptions); 4] = [
    (
        "line by line",
        PlayOptions {
            chunk_size: None,
            split_prompt_gap_ms: None,
        },
    ),
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
    // CR and LF of the same line delivered in different reads
    (
        "re-chunked every 2 chars",
        PlayOptions {
            chunk_size: Some(2),
            split_prompt_gap_ms: None,
        },
    ),
];

fn transcripts() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir().join("openconnect"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
        })
        .collect();
    names.sort();
    names
}

#[derive(Debug, PartialEq)]
struct Observed {
    states: Vec<VpnState>,
    /// prompts without their ids
    prompts: Vec<(gp_core::PromptKind, String, Option<Vec<String>>)>,
    written: Vec<Vec<String>>,
    /// log lines without their timestamp
    log: Vec<String>,
    final_state: VpnState,
}

/// Plays a transcript to the end, answering every prompt, and returns what is observable.
async fn run(name: &str, crlf: bool, play: PlayOptions) -> Observed {
    let h = harness()
        .profile(|p| p.preferred_gateway = Some("gw-us.example.com".into()))
        .saved_password("C0rrect-Horse")
        .build();
    h.connect();
    flush().await;
    let proc = h.spawner.last();
    let mut rest = load_transcript(name, crlf);
    let mut answered = 0;
    while !rest.is_empty() {
        rest = play_until_prompt(&proc, &rest, play).await;
        let prompts: Vec<AuthPrompt> = h.prompts();
        for p in &prompts[answered..] {
            answered += 1;
            if h.engine.get_pending_prompts().iter().any(|x| x.id == p.id) {
                let answer = p.options.as_ref().map_or("481516", |o| o[0].as_str()).to_string();
                h.answer(&p.id, Some(&answer));
                flush().await;
            }
        }
    }
    if h.spawner.count() == 1 {
        proc.exit(1);
    }
    flush().await;
    Observed {
        states: h.states(),
        prompts: h
            .prompts()
            .into_iter()
            .map(|p| (p.kind, p.message, p.options))
            .collect(),
        written: h.spawner.processes().iter().map(FakeProc::written).collect(),
        log: h
            .logger
            .lines()
            .iter()
            .map(|l| l.split_once(' ').map_or(l.clone(), |(_, rest)| rest.to_string()))
            .collect(),
        final_state: h.state(),
    }
}

#[test]
fn covers_all_recorded_transcripts() {
    assert!(transcripts().len() >= 9);
}

#[tokio::test(start_paused = true)]
async fn crlf_output_behaves_exactly_like_lf_for_every_transcript_and_chunking() {
    let mut cases = 0;
    for name in transcripts() {
        for (mode, play) in MODES {
            let lf = run(&name, false, play).await;
            let crlf = run(&name, true, play).await;
            assert_eq!(crlf, lf, "{name} / {mode}");
            // and nothing leaks a carriage return into what the UI or the log sees
            assert!(!format!("{crlf:?}").contains("\\r"), "{name} / {mode}");
            assert!(!lf.log.is_empty());
            cases += 1;
        }
    }
    assert_eq!(cases, transcripts().len() * MODES.len());
}
