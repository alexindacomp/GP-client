use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;

use super::*;
use crate::store::confirm_dialog::ConfirmDialogText;
use crate::store::secret_store::MemorySecretStore;
use crate::store::validation::validate_settings_patch;

struct Env {
    _dir: tempfile::TempDir,
    file: PathBuf,
    secrets: Arc<MemorySecretStore>,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    Env {
        file: d.path().join("confirmed-settings.json"),
        _dir: d,
        secrets: Arc::new(MemorySecretStore::new()),
    }
}

impl Env {
    fn guard(&self) -> ConfirmedSettingsGuard {
        ConfirmedSettingsGuard::open(&self.file, self.secrets.clone(), Arc::new(|_| {}))
    }
}

fn custom() -> Settings {
    Settings {
        openconnect_path: Some("/usr/local/sbin/openconnect".into()),
        hip_script_path: None,
        extra_args: vec!["-v".into()],
        ..Settings::default()
    }
}

#[test]
fn defaults_need_no_confirmation() {
    let e = env();
    assert!(e.guard().is_confirmed(&Settings::default()));
    assert!(e.guard().unconfirmed_fields(&Settings::default()).is_empty());
    assert!(is_default_guarded(&Settings::default()));
}

#[test]
fn unconfirmed_disk_values_need_confirmation() {
    let e = env();
    assert!(!e.guard().is_confirmed(&custom()));
}

#[test]
fn remembers_confirmed_values_across_restarts_and_detects_tampering() {
    let e = env();
    e.guard().confirm(&custom(), &GuardedKey::ALL);
    let g = e.guard();
    assert!(g.is_confirmed(&custom()));
    assert!(!g.is_confirmed(&Settings {
        extra_args: vec!["-v".into(), "--no-dtls".into()],
        ..custom()
    }));
    assert!(!g.is_confirmed(&Settings {
        openconnect_path: Some("/tmp/openconnect".into()),
        ..custom()
    }));
    assert!(!g.is_confirmed(&Settings {
        hip_script_path: Some("/tmp/hip.sh".into()),
        ..custom()
    }));
    let raw = fs::read_to_string(&e.file).unwrap();
    assert!(raw.contains("\"version\": 3"));
    assert!(
        !raw.contains(&e.secrets.snapshot()[HMAC_KEY_NAME]),
        "the key never goes to the file"
    );
}

#[test]
fn cannot_be_forged_by_editing_the_record_without_the_keystore_key() {
    let e = env();
    e.guard().confirm(&custom(), &GuardedKey::ALL);
    // attacker computes MACs for their own value with a key they know
    let attacker_key = [7u8; 32];
    let evil = Settings {
        openconnect_path: Some("/tmp/openconnect".into()),
        ..custom()
    };
    let forged = json!({"version": 3, "macs": {
        "openconnectPath": compute(&attacker_key, GuardedKey::OpenconnectPath, &evil),
        "extraArgs": compute(&attacker_key, GuardedKey::ExtraArgs, &evil),
    }});
    fs::write(&e.file, forged.to_string()).unwrap();
    assert!(!e.guard().is_confirmed(&evil));
    // a replaced keystore key invalidates the old record as well
    e.secrets.force_set(
        HMAC_KEY_NAME,
        &base64::engine::general_purpose::STANDARD.encode(attacker_key),
    );
    assert!(!e.guard().is_confirmed(&custom()));
}

#[test]
fn without_a_keystore_the_confirmation_is_in_memory_only() {
    let e = env();
    e.secrets.set_available(false);
    let g = e.guard();
    g.confirm(&custom(), &GuardedKey::ALL);
    assert!(g.is_confirmed(&custom()));
    assert!(!e.file.exists());
    assert!(!e.guard().is_confirmed(&custom()));
}

#[test]
fn confirming_one_field_does_not_confirm_another() {
    let e = env();
    let g = e.guard();
    let s = Settings {
        openconnect_path: Some("/usr/local/sbin/openconnect".into()),
        hip_script_path: Some("/tmp/evil.sh".into()),
        extra_args: vec!["-v".into()],
        ..Settings::default()
    };
    assert_eq!(g.unconfirmed_fields(&s), GuardedKey::ALL);
    g.confirm(&s, &[GuardedKey::OpenconnectPath]);
    assert_eq!(
        g.unconfirmed_fields(&s),
        [GuardedKey::HipScriptPath, GuardedKey::ExtraArgs]
    );
    assert_eq!(
        e.guard().unconfirmed_fields(&s),
        [GuardedKey::HipScriptPath, GuardedKey::ExtraArgs]
    );
}

#[test]
fn ignores_records_of_older_formats_and_bad_macs() {
    let e = env();
    fs::write(
        &e.file,
        json!({"version": 1, "key": "x", "mac": "f".repeat(64)}).to_string(),
    )
    .unwrap();
    assert!(!e.guard().is_confirmed(&custom()));
    fs::write(
        &e.file,
        json!({"version": 2, "key": "x", "macs": {"extraArgs": "f".repeat(64)}}).to_string(),
    )
    .unwrap();
    assert!(!e.guard().is_confirmed(&custom()));
    e.guard().confirm(&custom(), &GuardedKey::ALL);
    let mut rec: Value = serde_json::from_str(&fs::read_to_string(&e.file).unwrap()).unwrap();
    rec["macs"]["extraArgs"] = json!("XYZ");
    fs::write(&e.file, rec.to_string()).unwrap();
    assert_eq!(e.guard().unconfirmed_fields(&custom()), [GuardedKey::ExtraArgs]);
    fs::write(&e.file, "{corrupt").unwrap();
    assert!(!e.guard().is_confirmed(&custom()));
}

#[test]
fn canonical_value_matches_json_stringify() {
    assert_eq!(
        canonical_value(GuardedKey::HipScriptPath, &custom()),
        r#"["hipScriptPath",null]"#
    );
    assert_eq!(
        canonical_value(GuardedKey::ExtraArgs, &custom()),
        r#"["extraArgs",["-v"]]"#
    );
    assert_eq!(
        canonical_value(GuardedKey::OpenconnectPath, &custom()),
        r#"["openconnectPath","/usr/local/sbin/openconnect"]"#
    );
}

// ------------------------------------------------------------------ dialog flows

struct FakeDialog {
    answer: AtomicBool,
    calls: AtomicUsize,
    last: Mutex<Option<ConfirmDialogText>>,
}

fn dialog(answer: bool) -> FakeDialog {
    FakeDialog {
        answer: AtomicBool::new(answer),
        calls: AtomicUsize::new(0),
        last: Mutex::new(None),
    }
}

#[async_trait]
impl ConfirmDialog for FakeDialog {
    async fn confirm(&self, text: &ConfirmDialogText) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(text.clone());
        self.answer.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn ensure_confirmed_asks_for_disk_edited_values_and_remembers_the_answer() {
    let e = env();
    let g = e.guard();
    let logger = Logger::in_memory();
    let d = dialog(false);
    let err = ensure_settings_confirmed(&custom(), &g, &d, &logger)
        .await
        .unwrap_err();
    assert_eq!(
        (err.code, err.hint),
        (
            VpnErrorCode::PrivilegesDenied,
            Some(VpnErrorHint::SettingsNotConfirmed)
        )
    );
    assert!(
        logger
            .lines()
            .join("\n")
            .contains("openconnectPath=/usr/local/sbin/openconnect; extraArgs=-v")
    );
    let text = d.last.lock().unwrap().clone().unwrap();
    assert!(text.detail.contains("(изменено вне GP Connect)"));

    d.answer.store(true, Ordering::SeqCst);
    ensure_settings_confirmed(&custom(), &g, &d, &logger)
        .await
        .unwrap();
    ensure_settings_confirmed(&custom(), &g, &d, &logger)
        .await
        .unwrap();
    assert_eq!(d.calls.load(Ordering::SeqCst), 2, "no dialog once confirmed");
    assert!(
        ensure_settings_confirmed(&Settings::default(), &g, &dialog(false), &logger)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn settings_change_is_applied_only_when_confirmed_and_shows_extra_disk_edits() {
    let e = env();
    let dir = tempfile::tempdir().unwrap();
    let settings_file = dir.path().join("settings.json");
    // hipScriptPath edited on disk, never confirmed
    fs::write(
        &settings_file,
        r#"{"hipScriptPath": "/opt/hip.sh", "language": "en"}"#,
    )
    .unwrap();
    let store = SettingsStore::open(&settings_file, &|_| {});
    let g = e.guard();
    let logger = Logger::in_memory();
    let patch = validate_settings_patch(&json!({"extraArgs": ["--no-dtls"]})).unwrap();

    let declined = dialog(false);
    let err = set_settings_with_confirmation(&store, &g, &declined, &logger, &patch)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "[code:not_confirmed] The change was not confirmed"
    );
    assert!(store.get().extra_args.is_empty());
    let text = declined.last.lock().unwrap().clone().unwrap();
    assert_eq!(
        text.detail,
        "Extra arguments: --no-dtls\nHIP script: /opt/hip.sh (changed outside GP Connect)"
    );

    let ok = dialog(true);
    let next = set_settings_with_confirmation(&store, &g, &ok, &logger, &patch)
        .await
        .unwrap();
    assert_eq!(next.extra_args, ["--no-dtls"]);
    assert!(g.is_confirmed(&next));
    assert!(logger.lines().join("\n").contains(
        "Confirmed: extraArgs: --no-dtls; hipScriptPath: /opt/hip.sh (changed outside GP Connect)"
    ));

    // non-sensitive changes need no dialog
    let quiet = dialog(false);
    set_settings_with_confirmation(
        &store,
        &g,
        &quiet,
        &logger,
        &validate_settings_patch(&json!({"theme": "dark"})).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(quiet.calls.load(Ordering::SeqCst), 0);
}
