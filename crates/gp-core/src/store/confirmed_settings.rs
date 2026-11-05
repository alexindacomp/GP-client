//! Remembers which values of the elevation-relevant settings (openconnectPath, hipScriptPath,
//! extraArgs) the user confirmed in the native dialog.
//!
//! A value set edited on disk (bypassing the confirmation) has a different fingerprint and must be
//! confirmed again before the next elevated spawn. The fingerprint is a per-field HMAC-SHA256
//! whose key lives in the OS keystore ([`SecretStore`]), so an attacker who can only edit files
//! cannot forge it. Without a keystore the key lives in memory only: confirmation is then asked
//! once per app run.
//!
//! File format (`confirmed-settings.json`): `{"version": 3, "macs": {"<field>": "<hex>"}}`.
//! Records of the Electron version (v2, key encrypted with safeStorage) are ignored.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use super::confirm_dialog::{ConfirmDialog, ConfirmItem, ConfirmKind, ConfirmValue, confirm_dialog_text};
use super::json_file::{read_json_file, write_json_file};
use super::secret_store::SecretStore;
use super::sensitive_settings::{sensitive_changes, show_setting_value};
use super::settings::{SettingsStore, WarningFn};
use super::validation::{SettingsPatch, ValidationError, not_confirmed_error};
use crate::logging::Logger;
use crate::types::{Settings, VpnErrorCode, VpnErrorHint};
use crate::vpn::VpnError;

/// Keystore entry holding the base64 HMAC key.
pub const HMAC_KEY_NAME: &str = "confirmed-settings-hmac-key";
const FILE_VERSION: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuardedKey {
    OpenconnectPath,
    HipScriptPath,
    ExtraArgs,
}

impl GuardedKey {
    pub const ALL: [GuardedKey; 3] = [
        GuardedKey::OpenconnectPath,
        GuardedKey::HipScriptPath,
        GuardedKey::ExtraArgs,
    ];

    /// Name of the setting (`Settings` JSON field).
    pub fn as_str(self) -> &'static str {
        match self {
            GuardedKey::OpenconnectPath => "openconnectPath",
            GuardedKey::HipScriptPath => "hipScriptPath",
            GuardedKey::ExtraArgs => "extraArgs",
        }
    }

    /// The value of this field in `s`, for the dialog.
    pub fn value_of(self, s: &Settings) -> ConfirmValue {
        let path = |p: &Option<String>| p.clone().map_or(ConfirmValue::Default, ConfirmValue::Path);
        match self {
            GuardedKey::OpenconnectPath => path(&s.openconnect_path),
            GuardedKey::HipScriptPath => path(&s.hip_script_path),
            GuardedKey::ExtraArgs => ConfirmValue::Args(s.extra_args.clone()),
        }
    }
}

/// `JSON.stringify([key, value])`.
fn canonical_value(key: GuardedKey, s: &Settings) -> String {
    let v = match key {
        GuardedKey::OpenconnectPath => json!([key.as_str(), s.openconnect_path]),
        GuardedKey::HipScriptPath => json!([key.as_str(), s.hip_script_path]),
        GuardedKey::ExtraArgs => json!([key.as_str(), s.extra_args]),
    };
    v.to_string()
}

/// A field at its default needs no confirmation: nothing user-chosen runs elevated.
pub fn is_default_field(key: GuardedKey, s: &Settings) -> bool {
    match key {
        GuardedKey::OpenconnectPath => s.openconnect_path.is_none(),
        GuardedKey::HipScriptPath => s.hip_script_path.is_none(),
        GuardedKey::ExtraArgs => s.extra_args.is_empty(),
    }
}

pub fn is_default_guarded(s: &Settings) -> bool {
    GuardedKey::ALL.iter().all(|k| is_default_field(*k, s))
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn is_mac_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Default)]
struct GuardState {
    key: Option<[u8; 32]>,
    macs: BTreeMap<GuardedKey, String>,
}

/// Per-field confirmation record. Confirming one field never confirms another, so a value
/// edited on disk cannot ride along with an unrelated confirmed change.
pub struct ConfirmedSettingsGuard {
    file: PathBuf,
    secrets: Arc<dyn SecretStore>,
    on_warning: WarningFn,
    state: Mutex<GuardState>,
}

impl ConfirmedSettingsGuard {
    pub fn open(file: impl Into<PathBuf>, secrets: Arc<dyn SecretStore>, on_warning: WarningFn) -> Self {
        let g = ConfirmedSettingsGuard {
            file: file.into(),
            secrets,
            on_warning,
            state: Mutex::new(GuardState::default()),
        };
        g.load();
        g
    }

    fn state(&self) -> MutexGuard<'_, GuardState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Guarded fields of `s` that are neither default nor confirmed.
    pub fn unconfirmed_fields(&self, s: &Settings) -> Vec<GuardedKey> {
        let st = self.state();
        GuardedKey::ALL
            .into_iter()
            .filter(|k| !is_default_field(*k, s) && !matches(&st, *k, s))
            .collect()
    }

    /// True when every guarded field is default or exactly what the user confirmed.
    pub fn is_confirmed(&self, s: &Settings) -> bool {
        self.unconfirmed_fields(s).is_empty()
    }

    /// Records the given fields of `s` (the ones shown to the user) as confirmed.
    pub fn confirm(&self, s: &Settings, keys: &[GuardedKey]) {
        let mut st = self.state();
        let key = if let Some(k) = st.key {
            k
        } else {
            let mut k = [0u8; 32];
            if getrandom::fill(&mut k).is_err() {
                (self.on_warning)("Cannot create a confirmation key; confirmations are not remembered");
                return;
            }
            if self.secrets.available()
                && let Err(e) = self.secrets.set(
                    HMAC_KEY_NAME,
                    &base64::engine::general_purpose::STANDARD.encode(k),
                )
            {
                (self.on_warning)(&format!("Cannot persist confirmed settings: {e}"));
            }
            st.key = Some(k);
            k
        };
        for k in keys {
            if is_default_field(*k, s) {
                st.macs.remove(k);
            } else {
                st.macs.insert(*k, compute(&key, *k, s));
            }
        }
        if !self.secrets.available() {
            return; // in-memory only
        }
        let macs: serde_json::Map<String, Value> = st
            .macs
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), Value::String(v.clone())))
            .collect();
        if let Err(e) = write_json_file(&self.file, &json!({ "version": FILE_VERSION, "macs": macs })) {
            (self.on_warning)(&format!("Cannot persist confirmed settings: {e}"));
        }
    }

    fn load(&self) {
        let raw = match read_json_file(&self.file) {
            Ok(Some(v)) => v,
            Ok(None) => return,
            Err(e) => {
                (self.on_warning)(&format!("Ignoring confirmed-settings record: {e}"));
                return;
            }
        };
        if raw.get("version").and_then(Value::as_u64) != Some(FILE_VERSION) {
            return;
        }
        let Some(file_macs) = raw.get("macs").and_then(Value::as_object) else {
            return;
        };
        if !self.secrets.available() {
            return;
        }
        let Some(key) = self
            .secrets
            .get(HMAC_KEY_NAME)
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
        else {
            return;
        };
        let mut st = self.state();
        st.key = Some(key);
        st.macs = GuardedKey::ALL
            .into_iter()
            .filter_map(|k| {
                let m = file_macs.get(k.as_str())?.as_str()?;
                is_mac_hex(m).then(|| (k, m.to_string()))
            })
            .collect();
    }
}

fn hmac(key: &[u8; 32], k: GuardedKey, s: &Settings) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical_value(k, s).as_bytes());
    mac
}

fn compute(key: &[u8; 32], k: GuardedKey, s: &Settings) -> String {
    crate::util::hex(&hmac(key, k, s).finalize().into_bytes())
}

fn matches(st: &GuardState, k: GuardedKey, s: &Settings) -> bool {
    let (Some(key), Some(mac)) = (st.key.as_ref(), st.macs.get(&k)) else {
        return false;
    };
    let Some(want) = from_hex(mac) else { return false };
    // constant-time comparison
    hmac(key, k, s).verify_slice(&want).is_ok()
}

/// Before an elevated spawn: values changed on disk (not via the confirmed settings path) must be
/// confirmed in the dialog. Declining fails with `PRIVILEGES_DENIED` / `settings_not_confirmed`.
pub async fn ensure_settings_confirmed(
    settings: &Settings,
    guard: &ConfirmedSettingsGuard,
    dialog: &dyn ConfirmDialog,
    logger: &Logger,
) -> Result<(), VpnError> {
    let unconfirmed = guard.unconfirmed_fields(settings);
    if unconfirmed.is_empty() {
        return Ok(());
    }
    let items: Vec<ConfirmItem> = unconfirmed
        .iter()
        .map(|k| ConfirmItem {
            key: *k,
            value: k.value_of(settings),
            external: true,
        })
        .collect();
    if !dialog
        .confirm(&confirm_dialog_text(
            ConfirmKind::External,
            settings.language,
            &items,
        ))
        .await
    {
        let shown: Vec<String> = unconfirmed
            .iter()
            .map(|k| format!("{}={}", k.as_str(), show_setting_value(settings, *k)))
            .collect();
        logger.warn(
            "settings",
            &format!(
                "Externally changed elevation settings were not confirmed: {}",
                shown.join("; ")
            ),
        );
        return Err(VpnError::new(
            VpnErrorCode::PrivilegesDenied,
            "Changed openconnect settings were not confirmed",
        )
        .with_hint(VpnErrorHint::SettingsNotConfirmed));
    }
    guard.confirm(settings, &unconfirmed);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsChangeError {
    /// Declined (`[code:not_confirmed] …`).
    #[error(transparent)]
    NotConfirmed(#[from] ValidationError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// `settings.set` with confirmation: a patch that changes guarded settings is shown in the
/// dialog (together with guarded values edited on disk and never confirmed, so they cannot ride
/// along silently) and applied only when confirmed.
pub async fn set_settings_with_confirmation(
    store: &SettingsStore,
    guard: &ConfirmedSettingsGuard,
    dialog: &dyn ConfirmDialog,
    logger: &Logger,
    patch: &SettingsPatch,
) -> Result<Settings, SettingsChangeError> {
    let current = store.get();
    let changes = sensitive_changes(&current, patch);
    if changes.is_empty() {
        return Ok(store.set(patch)?);
    }
    let mut prospective = current.clone();
    patch.apply_to(&mut prospective);
    let changed: Vec<GuardedKey> = changes.iter().map(|c| c.key).collect();
    let extra: Vec<GuardedKey> = guard
        .unconfirmed_fields(&prospective)
        .into_iter()
        .filter(|k| !changed.contains(k))
        .collect();
    let items: Vec<ConfirmItem> = changed
        .iter()
        .map(|k| ConfirmItem {
            key: *k,
            value: k.value_of(&prospective),
            external: false,
        })
        .chain(extra.iter().map(|k| ConfirmItem {
            key: *k,
            value: k.value_of(&prospective),
            external: true,
        }))
        .collect();
    let all: Vec<GuardedKey> = changed.iter().chain(extra.iter()).copied().collect();
    let names = all.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ");
    if !dialog
        .confirm(&confirm_dialog_text(
            ConfirmKind::Change,
            prospective.language,
            &items,
        ))
        .await
    {
        logger.warn("settings", &format!("Change of {names} was not confirmed"));
        return Err(not_confirmed_error().into());
    }
    let lines: Vec<String> = changes
        .iter()
        .map(|c| format!("{}: {}", c.key.as_str(), c.value))
        .chain(extra.iter().map(|k| {
            format!(
                "{}: {} (changed outside GP Connect)",
                k.as_str(),
                show_setting_value(&prospective, *k)
            )
        }))
        .collect();
    logger.info("settings", &format!("Confirmed: {}", lines.join("; ")));
    let next = store.set(patch)?;
    guard.confirm(&next, &all);
    Ok(next)
}

#[cfg(test)]
mod tests;
