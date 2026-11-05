//! Tauri commands = `GpApi` of src/shared/ipc.ts (docs/ARCHITECTURE-TAURI.md, contract table).
//!
//! * Arguments arrive as raw JSON and are validated with the gp-core validators (same rules and
//!   messages as the Electron version).
//! * Errors are `Err(String)` in the `[field:<f>][code:<c>] <message>` format that
//!   `parseIpcError` (src/shared/validation.ts) understands; unexpected failures are logged and
//!   reported as `[code:internal]` without details.
//! * Only the main window may call them: enforced by the capability (capabilities/main.json) and
//!   re-checked here.
//!
//! All commands are `async` so they run on the async runtime, never on the UI thread (engine
//! calls need the runtime; store writes and keystore access may block).
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // Tauri command signatures

use gp_core::openconnect::discovery_log::openconnect_system_info;
use gp_core::platform::Platform;
use gp_core::store::confirmed_settings::{SettingsChangeError, set_settings_with_confirmation};
use gp_core::store::profiles::ProfileStoreError;
use gp_core::store::validation::{
    SettingsPatch, ValidationError, validate_answer, validate_connect_options, validate_external_url,
    validate_id_as, validate_password, validate_profile_input, validate_settings_patch,
};
use gp_core::types::{AuthPrompt, ConnectOptions, Profile, ProfileInput, Settings, SystemInfo, VpnState};
use gp_core::validation::format_ipc_error;
use serde_json::Value;
use tauri::{AppHandle, Manager, Runtime, State, Webview};
use tauri_plugin_opener::OpenerExt;

use crate::app_state::AppState;
use crate::saml::clear_profile_data;
use crate::window::{MAIN, is_dark};

type CmdResult<T> = Result<T, String>;

const NULL: Value = Value::Null;

fn v(arg: Option<&Value>) -> &Value {
    arg.unwrap_or(&NULL)
}

fn invalid(e: ValidationError) -> String {
    e.to_string()
}

/// Logs the cause and returns the generic, detail-free error (`publicError` fallback).
fn internal(st: &AppState, command: &str, cause: impl std::fmt::Display) -> String {
    st.logger.error("ipc", &format!("{command} failed: {cause}"));
    format_ipc_error(None, Some("internal"), "Internal error, see the log for details")
}

/// Defence in depth behind the capability: only the main window's webview is trusted.
fn ensure_main<R: Runtime>(st: &AppState, webview: &Webview<R>, command: &str) -> CmdResult<()> {
    if webview.label() == MAIN {
        Ok(())
    } else {
        st.logger
            .warn("ipc", &format!("Rejected {command} from untrusted sender"));
        Err("Untrusted sender".into())
    }
}

// ------------------------------------------------------------------ argument parsing (pure)

pub(crate) fn parse_profile_save(
    profile: Option<&Value>,
    password: Option<&Value>,
) -> CmdResult<(ProfileInput, Option<String>)> {
    let input = validate_profile_input(v(profile)).map_err(invalid)?;
    let password = validate_password(password).map_err(invalid)?;
    Ok((input, password))
}

pub(crate) fn parse_profile_id(id: Option<&Value>) -> CmdResult<String> {
    validate_id_as(id, "profile id", "profileId").map_err(invalid)
}

pub(crate) fn parse_connect(
    profile_id: Option<&Value>,
    opts: Option<&Value>,
) -> CmdResult<(String, ConnectOptions)> {
    let id = parse_profile_id(profile_id)?;
    let opts = validate_connect_options(opts).map_err(invalid)?;
    Ok((id, opts))
}

pub(crate) fn parse_answer(id: Option<&Value>, value: Option<&Value>) -> CmdResult<(String, Option<String>)> {
    let answer = validate_answer(value).map_err(invalid)?;
    let id = validate_id_as(id, "prompt id", "promptId").map_err(invalid)?;
    Ok((id, answer))
}

pub(crate) fn parse_settings_patch(patch: Option<&Value>) -> CmdResult<SettingsPatch> {
    validate_settings_patch(v(patch)).map_err(invalid)
}

pub(crate) fn parse_external_url(url: Option<&Value>) -> CmdResult<String> {
    validate_external_url(v(url)).map_err(invalid)
}

// ------------------------------------------------------------------ profiles

#[tauri::command]
pub(crate) async fn profiles_list<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<Vec<Profile>> {
    ensure_main(&st, &webview, "profiles_list")?;
    Ok(st.profiles.list())
}

#[tauri::command]
pub(crate) async fn profiles_save<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
    profile: Option<Value>,
    password: Option<Value>,
) -> CmdResult<Profile> {
    ensure_main(&st, &webview, "profiles_save")?;
    let (input, password) = parse_profile_save(profile.as_ref(), password.as_ref())?;
    let saved = st
        .profiles
        .save(&input, password.as_deref())
        .map_err(|e| match e {
            ProfileStoreError::Validation(v) => v.to_string(),
            ProfileStoreError::Io(e) => internal(&st, "profiles_save", e),
        })?;
    st.refresh_tray();
    Ok(saved)
}

#[tauri::command]
pub(crate) async fn profiles_remove<R: Runtime>(
    app: AppHandle<R>,
    st: State<'_, AppState>,
    webview: Webview<R>,
    id: Option<Value>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "profiles_remove")?;
    let id = parse_profile_id(id.as_ref())?;
    st.profiles
        .remove(&id)
        .map_err(|e| internal(&st, "profiles_remove", e))?;
    if let Err(e) = clear_profile_data(&app, &st.saml_sessions, &st.saml_data_root, &id).await {
        st.logger
            .warn("profiles", &format!("Failed to clear SSO data: {e}"));
    }
    if st.settings.get().last_profile_id.as_deref() == Some(id.as_str()) {
        st.set_last_profile(None);
    }
    st.refresh_tray();
    Ok(())
}

// ------------------------------------------------------------------ vpn

#[tauri::command]
pub(crate) async fn vpn_connect<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
    profile_id: Option<Value>,
    opts: Option<Value>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "vpn_connect")?;
    let (id, opts) = parse_connect(profile_id.as_ref(), opts.as_ref())?;
    st.connect(&id, opts).map_err(|e| e.to_ipc_error())
}

#[tauri::command]
pub(crate) async fn vpn_disconnect<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "vpn_disconnect")?;
    st.engine.disconnect().await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn vpn_get_state<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<VpnState> {
    ensure_main(&st, &webview, "vpn_get_state")?;
    Ok(st.engine.get_state())
}

#[tauri::command]
pub(crate) async fn vpn_answer_prompt<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
    id: Option<Value>,
    value: Option<Value>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "vpn_answer_prompt")?;
    let (id, answer) = parse_answer(id.as_ref(), value.as_ref())?;
    st.engine.answer_prompt(&id, answer).map_err(|e| e.to_ipc_error())
}

#[tauri::command]
pub(crate) async fn vpn_get_pending_prompts<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<Vec<AuthPrompt>> {
    ensure_main(&st, &webview, "vpn_get_pending_prompts")?;
    Ok(st.engine.get_pending_prompts())
}

// ------------------------------------------------------------------ logs

#[tauri::command]
pub(crate) async fn logs_get<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<Vec<String>> {
    ensure_main(&st, &webview, "logs_get")?;
    Ok(st.logger.lines())
}

#[tauri::command]
pub(crate) async fn logs_open_folder<R: Runtime>(
    app: AppHandle<R>,
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "logs_open_folder")?;
    let dir = st.logs_dir.to_string_lossy().into_owned();
    app.opener()
        .open_path(dir, None::<&str>)
        .map_err(|e| internal(&st, "logs_open_folder", e))
}

// ------------------------------------------------------------------ settings

#[tauri::command]
pub(crate) async fn settings_get<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<Settings> {
    ensure_main(&st, &webview, "settings_get")?;
    Ok(st.settings.get())
}

/// Changes of elevation-relevant settings (openconnectPath, hipScriptPath, extraArgs) are applied
/// only after the user confirms them in a native dialog.
#[tauri::command]
pub(crate) async fn settings_set<R: Runtime>(
    st: State<'_, AppState>,
    webview: Webview<R>,
    patch: Option<Value>,
) -> CmdResult<Settings> {
    ensure_main(&st, &webview, "settings_set")?;
    let patch = parse_settings_patch(patch.as_ref())?;
    set_settings_with_confirmation(&st.settings, &st.guard, st.dialog.as_ref(), &st.logger, &patch)
        .await
        .map_err(|e| match e {
            SettingsChangeError::NotConfirmed(v) => v.to_string(),
            SettingsChangeError::Io(e) => internal(&st, "settings_set", e),
        })
}

// ------------------------------------------------------------------ system

#[tauri::command]
pub(crate) async fn system_info<R: Runtime>(
    app: AppHandle<R>,
    st: State<'_, AppState>,
    webview: Webview<R>,
) -> CmdResult<SystemInfo> {
    ensure_main(&st, &webview, "system_info")?;
    let oc = openconnect_system_info(&st.discovery.find(true).await);
    let dark = app.get_webview_window(MAIN).is_some_and(|w| is_dark(&w));
    Ok(SystemInfo {
        platform: Platform::current(),
        openconnect_version: oc.openconnect_version,
        openconnect_found: oc.openconnect_found,
        openconnect_path: oc.openconnect_path,
        openconnect_trusted: oc.openconnect_trusted,
        app_version: app.package_info().version.to_string(),
        should_use_dark_colors: dark,
    })
}

#[tauri::command]
pub(crate) async fn system_open_external<R: Runtime>(
    app: AppHandle<R>,
    st: State<'_, AppState>,
    webview: Webview<R>,
    url: Option<Value>,
) -> CmdResult<()> {
    ensure_main(&st, &webview, "system_open_external")?;
    let url = parse_external_url(url.as_ref())?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| internal(&st, "system_open_external", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_core::validation::parse_ipc_error;
    use serde_json::json;

    const ID: &str = "3F2B8C4E-1D2A-4B5C-8D9E-0F1A2B3C4D5E";

    fn markers(err: &str) -> (Option<String>, Option<String>) {
        let info = parse_ipc_error(err);
        (info.field, info.code)
    }

    fn some(s: &str) -> (Option<String>, Option<String>) {
        (None, Some(s.to_string()))
    }

    fn field(f: &str, c: &str) -> (Option<String>, Option<String>) {
        (Some(f.to_string()), Some(c.to_string()))
    }

    #[test]
    fn profile_save_validates_profile_and_password() {
        let profile = json!({
            "name": "Office",
            "portalUrl": "vpn.example.com",
            "authMode": "auto",
            "savePassword": true
        });
        let (input, pw) = parse_profile_save(Some(&profile), Some(&json!("secret"))).unwrap();
        assert_eq!(input.portal_url, "https://vpn.example.com");
        assert_eq!(input.id, None);
        assert_eq!(pw.as_deref(), Some("secret"));
        // Absent / null / empty password: keep the stored one.
        for p in [None, Some(json!(null)), Some(json!(""))] {
            assert_eq!(parse_profile_save(Some(&profile), p.as_ref()).unwrap().1, None);
        }

        let err = parse_profile_save(None, None).unwrap_err();
        assert_eq!(markers(&err), some("invalid_type"));
        let mut bad = profile.clone();
        bad["portalUrl"] = json!("ftp://x");
        assert_eq!(
            markers(&parse_profile_save(Some(&bad), None).unwrap_err())
                .0
                .as_deref(),
            Some("portalUrl")
        );
        let mut extra = profile.clone();
        extra["admin"] = json!(true);
        assert_eq!(
            markers(&parse_profile_save(Some(&extra), None).unwrap_err()),
            field("admin", "unknown_field")
        );
        assert_eq!(
            markers(&parse_profile_save(Some(&profile), Some(&json!("a\nb"))).unwrap_err()),
            field("password", "invalid_chars")
        );
        assert_eq!(
            markers(&parse_profile_save(Some(&profile), Some(&json!(42))).unwrap_err()),
            field("password", "invalid_type")
        );
    }

    #[test]
    fn ids_must_be_uuids_and_are_lowercased() {
        assert_eq!(parse_profile_id(Some(&json!(ID))).unwrap(), ID.to_lowercase());
        for bad in [None, Some(json!(null)), Some(json!("../x")), Some(json!(1))] {
            let err = parse_profile_id(bad.as_ref()).unwrap_err();
            assert_eq!(markers(&err), field("profileId", "invalid"), "{bad:?}");
        }
    }

    #[test]
    fn connect_validates_id_and_options() {
        let (id, opts) = parse_connect(Some(&json!(ID)), None).unwrap();
        assert_eq!(
            (id.as_str(), opts),
            (ID.to_lowercase().as_str(), ConnectOptions::default())
        );
        let (_, opts) = parse_connect(
            Some(&json!(ID)),
            Some(&json!({ "gateway": "gw1", "password": "p" })),
        )
        .unwrap();
        assert_eq!(
            (opts.gateway.as_deref(), opts.password.as_deref()),
            (Some("gw1"), Some("p"))
        );
        assert_eq!(
            markers(&parse_connect(Some(&json!(ID)), Some(&json!({ "x": 1 }))).unwrap_err()),
            field("x", "unknown_field")
        );
        assert_eq!(
            markers(&parse_connect(Some(&json!("nope")), None).unwrap_err()),
            field("profileId", "invalid")
        );
    }

    #[test]
    fn answers_are_strings_or_null_and_prompt_ids_are_checked() {
        assert_eq!(
            parse_answer(Some(&json!(ID)), Some(&json!("123456"))).unwrap(),
            (ID.to_lowercase(), Some("123456".into()))
        );
        assert_eq!(
            parse_answer(Some(&json!(ID)), Some(&json!(null))).unwrap().1,
            None
        );
        assert_eq!(parse_answer(Some(&json!(ID)), None).unwrap().1, None);
        assert_eq!(
            markers(&parse_answer(Some(&json!(ID)), Some(&json!(5))).unwrap_err()),
            field("answer", "invalid_type")
        );
        assert_eq!(
            markers(&parse_answer(Some(&json!("x")), Some(&json!("1"))).unwrap_err()),
            field("promptId", "invalid")
        );
    }

    #[test]
    fn settings_patch_is_validated() {
        let p = parse_settings_patch(Some(&json!({ "theme": "dark", "openconnectPath": null }))).unwrap();
        assert_eq!(p.theme, Some(gp_core::types::Theme::Dark));
        assert_eq!(p.openconnect_path, Some(None));
        assert_eq!(
            markers(&parse_settings_patch(None).unwrap_err()),
            some("invalid_type")
        );
        assert_eq!(
            markers(&parse_settings_patch(Some(&json!({ "theme": "pink" }))).unwrap_err())
                .0
                .as_deref(),
            Some("theme")
        );
        assert_eq!(
            markers(&parse_settings_patch(Some(&json!({ "openconnectPath": "/usr/bin/bash" }))).unwrap_err()),
            field("openconnectPath", "not_openconnect")
        );
    }

    #[test]
    fn only_https_links_open_externally() {
        assert_eq!(
            parse_external_url(Some(&json!("https://github.com/x"))).unwrap(),
            "https://github.com/x"
        );
        assert_eq!(
            markers(&parse_external_url(Some(&json!("file:///etc/passwd"))).unwrap_err()),
            field("url", "not_https")
        );
        assert_eq!(
            markers(&parse_external_url(None).unwrap_err()),
            field("url", "invalid")
        );
    }
}
