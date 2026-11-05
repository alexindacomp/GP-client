//! Validation of untrusted input (command payloads and files on disk). Every function fails with [`ValidationError`], whose `Display`
//! is the marker format `[field:<name>][code:<code>] <English message>` understood by
//! `parseIpcError` in src/shared/validation.ts — return `err.to_string()` from Tauri commands.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};
use url::Url;

use crate::openconnect::args::validate_extra_args_value;
use crate::types::{AuthMode, ConnectOptions, Language, ProfileInput, Settings, Theme};
use crate::util::{js_len, js_trim};
use crate::validation::{
    format_ipc_error, has_control_chars, is_absolute_path, is_openconnect_binary_path, normalize_portal_url,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", format_ipc_error(self.field.as_deref(), self.code.as_deref(), &self.message))]
pub struct ValidationError {
    pub field: Option<String>,
    pub code: Option<String>,
    pub message: String,
}

impl ValidationError {
    pub fn new(message: impl Into<String>, field: Option<&str>, code: Option<&str>) -> Self {
        ValidationError {
            field: field.map(String::from),
            code: code.map(String::from),
            message: message.into(),
        }
    }

    fn field(message: impl Into<String>, field: &str, code: &str) -> Self {
        Self::new(message, Some(field), Some(code))
    }
}

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").expect("valid regex")
});

fn as_object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, ValidationError> {
    v.as_object()
        .ok_or_else(|| ValidationError::new(format!("{what} must be an object"), None, Some("invalid_type")))
}

fn reject_unknown_keys(
    obj: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ValidationError> {
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(ValidationError::field(
            format!("Unknown {what} field \"{k}\""),
            k,
            "unknown_field",
        )),
        None => Ok(()),
    }
}

/// A UUID (lower-cased). `what` names it in the message, `field` in the marker.
pub fn validate_id_as(v: Option<&Value>, what: &str, field: &str) -> Result<String, ValidationError> {
    match v.and_then(Value::as_str) {
        Some(s) if UUID_RE.is_match(s) => Ok(s.to_lowercase()),
        _ => Err(ValidationError::field(
            format!("Invalid {what}"),
            field,
            "invalid",
        )),
    }
}

pub fn validate_id(v: &Value) -> Result<String, ValidationError> {
    validate_id_as(Some(v), "id", "id")
}

fn text(v: Option<&Value>, field: &str, max: usize) -> Result<String, ValidationError> {
    let Some(s) = v.and_then(Value::as_str) else {
        return Err(ValidationError::field(
            format!("{field} must be a string"),
            field,
            "invalid_type",
        ));
    };
    let t = js_trim(s);
    if t.is_empty() {
        return Err(ValidationError::field(
            format!("{field} must not be empty"),
            field,
            "required",
        ));
    }
    if js_len(t) > max {
        return Err(ValidationError::field(
            format!("{field} is too long (max {max})"),
            field,
            "too_long",
        ));
    }
    if has_control_chars(t) {
        return Err(ValidationError::field(
            format!("{field} contains invalid characters"),
            field,
            "invalid_chars",
        ));
    }
    Ok(t.to_string())
}

fn optional_text(v: Option<&Value>, field: &str, max: usize) -> Result<Option<String>, ValidationError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if js_trim(s).is_empty() => Ok(None),
        other => text(other, field, max).map(Some),
    }
}

fn absolute_path(v: Option<&Value>, field: &str) -> Result<Option<String>, ValidationError> {
    let p = optional_text(v, field, 1024)?;
    if let Some(p) = &p
        && !is_absolute_path(p)
    {
        return Err(ValidationError::field(
            format!("{field} must be an absolute path"),
            field,
            "not_absolute",
        ));
    }
    Ok(p)
}

fn boolean(v: Option<&Value>, field: &str) -> Result<bool, ValidationError> {
    v.and_then(Value::as_bool)
        .ok_or_else(|| ValidationError::field(format!("{field} must be a boolean"), field, "invalid_type"))
}

fn one_of<T: Copy>(
    v: Option<&Value>,
    all: &[T],
    name: fn(T) -> &'static str,
    field: &str,
) -> Result<T, ValidationError> {
    let s = v.and_then(Value::as_str);
    all.iter().copied().find(|x| Some(name(*x)) == s).ok_or_else(|| {
        let names: Vec<&str> = all.iter().map(|x| name(*x)).collect();
        ValidationError::field(
            format!("{field} must be one of: {}", names.join(", ")),
            field,
            "invalid",
        )
    })
}

const PROFILE_KEYS: &[&str] = &[
    "id",
    "name",
    "portalUrl",
    "username",
    "authMode",
    "preferredGateway",
    "savePassword",
];

pub fn validate_profile_input(raw: &Value) -> Result<ProfileInput, ValidationError> {
    let obj = as_object(raw, "Profile")?;
    reject_unknown_keys(obj, PROFILE_KEYS, "profile")?;
    let portal_text = text(obj.get("portalUrl"), "portalUrl", 2048)?;
    let portal_url = normalize_portal_url(&portal_text)
        .map_err(|c| ValidationError::field(c.message(), "portalUrl", c.as_str()))?;
    let name = text(obj.get("name"), "name", 100)?;
    let auth_mode = one_of(obj.get("authMode"), &AuthMode::ALL, AuthMode::as_str, "authMode")?;
    let save_password = boolean(obj.get("savePassword"), "savePassword")?;
    let id = match obj.get("id") {
        None => None,
        Some(v) => Some(validate_id_as(Some(v), "profile id", "id")?),
    };
    Ok(ProfileInput {
        id,
        name,
        portal_url,
        username: optional_text(obj.get("username"), "username", 256)?,
        auth_mode,
        preferred_gateway: optional_text(obj.get("preferredGateway"), "preferredGateway", 255)?,
        save_password,
    })
}

pub fn validate_password(v: Option<&Value>) -> Result<Option<String>, ValidationError> {
    let field = "password";
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => {
            if js_len(s) > 1024 {
                return Err(ValidationError::field("Password is too long", field, "too_long"));
            }
            if s.contains(['\r', '\n', '\0']) {
                return Err(ValidationError::field(
                    "Password must be a single line",
                    field,
                    "invalid_chars",
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(ValidationError::field(
            "Password must be a string",
            field,
            "invalid_type",
        )),
    }
}

pub fn validate_connect_options(v: Option<&Value>) -> Result<ConnectOptions, ValidationError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(ConnectOptions::default());
    };
    let obj = as_object(v, "Connect options")?;
    reject_unknown_keys(obj, &["gateway", "password"], "connect option")?;
    Ok(ConnectOptions {
        gateway: optional_text(obj.get("gateway"), "gateway", 255)?,
        password: validate_password(obj.get("password"))?,
    })
}

/// `answerPrompt` value: a string or `null` (cancel).
pub fn validate_answer(v: Option<&Value>) -> Result<Option<String>, ValidationError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ValidationError::field(
            "Answer must be a string or null",
            "answer",
            "invalid_type",
        )),
    }
}

/// A validated `Partial<Settings>`. For optional strings, `Some(None)` clears the setting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsPatch {
    pub theme: Option<Theme>,
    pub language: Option<Language>,
    pub launch_at_login: Option<bool>,
    pub connect_on_startup: Option<bool>,
    pub auto_reconnect: Option<bool>,
    pub openconnect_path: Option<Option<String>>,
    pub hip_script_path: Option<Option<String>>,
    pub last_profile_id: Option<Option<String>>,
    pub extra_args: Option<Vec<String>>,
}

impl SettingsPatch {
    /// `{ ...settings, ...patch }`.
    pub fn apply_to(&self, s: &mut Settings) {
        if let Some(v) = self.theme {
            s.theme = v;
        }
        if let Some(v) = self.language {
            s.language = v;
        }
        if let Some(v) = self.launch_at_login {
            s.launch_at_login = v;
        }
        if let Some(v) = self.connect_on_startup {
            s.connect_on_startup = v;
        }
        if let Some(v) = self.auto_reconnect {
            s.auto_reconnect = v;
        }
        if let Some(v) = &self.openconnect_path {
            s.openconnect_path.clone_from(v);
        }
        if let Some(v) = &self.hip_script_path {
            s.hip_script_path.clone_from(v);
        }
        if let Some(v) = &self.last_profile_id {
            s.last_profile_id.clone_from(v);
        }
        if let Some(v) = &self.extra_args {
            s.extra_args.clone_from(v);
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == SettingsPatch::default()
    }
}

const SETTINGS_KEYS: &[&str] = &[
    "theme",
    "launchAtLogin",
    "connectOnStartup",
    "autoReconnect",
    "openconnectPath",
    "extraArgs",
    "hipScriptPath",
    "language",
    "lastProfileId",
];

/// Validates a settings patch. Optional string settings may be cleared with `null` / `""`.
pub fn validate_settings_patch(raw: &Value) -> Result<SettingsPatch, ValidationError> {
    let obj = as_object(raw, "Settings patch")?;
    reject_unknown_keys(obj, SETTINGS_KEYS, "settings")?;
    let mut out = SettingsPatch::default();
    let get = |k: &str| obj.get(k);
    if obj.contains_key("theme") {
        out.theme = Some(one_of(get("theme"), &Theme::ALL, Theme::as_str, "theme")?);
    }
    if obj.contains_key("language") {
        out.language = Some(one_of(
            get("language"),
            &Language::ALL,
            Language::as_str,
            "language",
        )?);
    }
    if obj.contains_key("launchAtLogin") {
        out.launch_at_login = Some(boolean(get("launchAtLogin"), "launchAtLogin")?);
    }
    if obj.contains_key("connectOnStartup") {
        out.connect_on_startup = Some(boolean(get("connectOnStartup"), "connectOnStartup")?);
    }
    if obj.contains_key("autoReconnect") {
        out.auto_reconnect = Some(boolean(get("autoReconnect"), "autoReconnect")?);
    }
    if obj.contains_key("openconnectPath") {
        let p = absolute_path(get("openconnectPath"), "openconnectPath")?;
        // Only the openconnect binary itself may be configured (not an arbitrary program).
        if p.as_deref().is_some_and(|p| !is_openconnect_binary_path(p)) {
            return Err(ValidationError::field(
                "openconnectPath must point to the openconnect binary (openconnect / openconnect.exe)",
                "openconnectPath",
                "not_openconnect",
            ));
        }
        out.openconnect_path = Some(p);
    }
    if obj.contains_key("hipScriptPath") {
        out.hip_script_path = Some(absolute_path(get("hipScriptPath"), "hipScriptPath")?);
    }
    if obj.contains_key("lastProfileId") {
        out.last_profile_id = Some(match get("lastProfileId") {
            None | Some(Value::Null) => None,
            v => Some(validate_id_as(v, "id", "lastProfileId")?),
        });
    }
    if let Some(v) = get("extraArgs") {
        out.extra_args = Some(
            validate_extra_args_value(v)
                .map_err(|e| ValidationError::field(e.message, "extraArgs", e.code.as_str()))?,
        );
    }
    Ok(out)
}

/// Only https URLs may be opened externally.
pub fn validate_external_url(v: &Value) -> Result<String, ValidationError> {
    let invalid = || ValidationError::field("Invalid URL", "url", "invalid");
    let s = v.as_str().filter(|s| js_len(s) <= 2048).ok_or_else(invalid)?;
    let url = Url::parse(s).map_err(|_| invalid())?;
    if url.scheme() != "https" {
        return Err(ValidationError::field(
            "Only https:// links can be opened",
            "url",
            "not_https",
        ));
    }
    Ok(url.to_string())
}

/// Rejection used when the user declines the confirmation dialog.
pub fn not_confirmed_error() -> ValidationError {
    ValidationError::new("The change was not confirmed", None, Some("not_confirmed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "3f2b8c1e-4a5d-4e6f-8a9b-0c1d2e3f4a5b";

    #[test]
    fn profile_input_normalises_the_portal_url_and_trims_fields() {
        let p = validate_profile_input(
            &json!({"name": " Work ", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false, "username": "  "}),
        )
        .unwrap();
        assert_eq!(
            p,
            ProfileInput {
                id: None,
                name: "Work".into(),
                portal_url: "https://vpn.example.com".into(),
                username: None,
                auth_mode: AuthMode::Auto,
                preferred_gateway: None,
                save_password: false,
            }
        );
        let with_id = validate_profile_input(
            &json!({"id": ID.to_uppercase(), "name": "x", "portalUrl": "vpn.example.com", "authMode": "saml", "savePassword": false}),
        )
        .unwrap();
        assert_eq!(with_id.id.as_deref(), Some(ID));
    }

    #[test]
    fn profile_input_rejects_bad_values() {
        for v in [
            json!({"name": "x", "portalUrl": "http://vpn.example.com", "authMode": "auto", "savePassword": false}),
            json!({"name": "", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false}),
            json!({"name": "x", "portalUrl": "vpn.example.com", "authMode": "kerberos", "savePassword": false}),
            json!({"name": "x", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": "yes"}),
            json!({"name": "x", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false, "id": "../etc"}),
            json!({"name": "x", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false, "admin": true}),
            json!({"name": "x".repeat(101), "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false}),
            json!({"name": "a\u{7}b", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false}),
            json!(null),
        ] {
            assert!(validate_profile_input(&v).is_err(), "{v}");
        }
    }

    #[test]
    fn settings_patch_accepts_openconnect_binary_paths_only() {
        for p in ["/usr/sbin/openconnect", "C:\\Program Files\\OC\\OpenConnect.exe"] {
            let patch = validate_settings_patch(&json!({"openconnectPath": p})).unwrap();
            assert_eq!(patch.openconnect_path, Some(Some(p.to_string())));
        }
    }

    #[test]
    fn settings_patch_is_partial_and_clears_optional_strings() {
        let patch = validate_settings_patch(
            &json!({"theme": "dark", "openconnectPath": "", "extraArgs": ["--no-dtls"]}),
        )
        .unwrap();
        assert_eq!(
            patch,
            SettingsPatch {
                theme: Some(Theme::Dark),
                openconnect_path: Some(None),
                extra_args: Some(vec!["--no-dtls".into()]),
                ..Default::default()
            }
        );
        let cleared =
            validate_settings_patch(&json!({"hipScriptPath": null, "lastProfileId": null})).unwrap();
        assert_eq!(
            (cleared.hip_script_path, cleared.last_profile_id),
            (Some(None), Some(None))
        );
        for lang in ["ru", "en", "uk"] {
            assert!(validate_settings_patch(&json!({ "language": lang })).is_ok());
        }
    }

    #[test]
    fn settings_patch_rejects_bad_values() {
        for v in [
            json!({"theme": "blue"}),
            json!({"language": "de"}),
            json!({"autoReconnect": 1}),
            json!({"openconnectPath": "openconnect"}),
            json!({"openconnectPath": "/usr/bin/python3"}),
            json!({"openconnectPath": "C:\\Windows\\System32\\cmd.exe"}),
            json!({"extraArgs": ["--user=root"]}),
            json!({"extraArgs": ["--script=/tmp/x"]}),
            json!({"lastProfileId": "not-a-uuid"}),
            json!({"unknown": true}),
            json!([]),
        ] {
            assert!(validate_settings_patch(&v).is_err(), "{v}");
        }
    }

    #[test]
    fn connect_options_and_passwords() {
        assert_eq!(validate_connect_options(None).unwrap(), ConnectOptions::default());
        assert_eq!(
            validate_connect_options(Some(&Value::Null)).unwrap(),
            ConnectOptions::default()
        );
        assert_eq!(
            validate_connect_options(Some(&json!({"gateway": "Europe", "password": "pw"}))).unwrap(),
            ConnectOptions {
                gateway: Some("Europe".into()),
                password: Some("pw".into())
            }
        );
        assert!(validate_connect_options(Some(&json!({"password": "a\nb"}))).is_err());
        assert!(validate_connect_options(Some(&json!({"bogus": 1}))).is_err());
        assert!(validate_password(Some(&json!("x".repeat(1025)))).is_err());
        assert_eq!(validate_password(Some(&json!(""))).unwrap(), None);
        assert!(validate_answer(Some(&json!(1))).is_err());
        assert_eq!(validate_answer(Some(&Value::Null)).unwrap(), None);
    }

    #[test]
    fn external_urls_must_be_https() {
        assert_eq!(
            validate_external_url(&json!("https://example.com/docs")).unwrap(),
            "https://example.com/docs"
        );
        assert!(validate_external_url(&json!("file:///etc/passwd")).is_err());
        assert!(validate_external_url(&json!("javascript:alert(1)")).is_err());
        assert!(validate_external_url(&json!(42)).is_err());
    }

    #[test]
    fn errors_carry_machine_readable_markers() {
        let cases: Vec<(Result<(), ValidationError>, &str)> = vec![
            (validate_settings_patch(&json!({"extraArgs": ["--script=/x"]})).map(drop), "[field:extraArgs][code:not_allowed] "),
            (validate_settings_patch(&json!({"extraArgs": ["--mtu=1"]})).map(drop), "[field:extraArgs][code:bad_value] "),
            (
                validate_settings_patch(&json!({"openconnectPath": "/usr/bin/python3"})).map(drop),
                "[field:openconnectPath][code:not_openconnect] ",
            ),
            (validate_settings_patch(&json!({"hipScriptPath": "hip.sh"})).map(drop), "[field:hipScriptPath][code:not_absolute] "),
            (
                validate_profile_input(&json!({"name": "x", "portalUrl": "http://v.example.com", "authMode": "auto", "savePassword": false}))
                    .map(drop),
                "[field:portalUrl][code:not_https] ",
            ),
            (
                validate_profile_input(&json!({"name": "", "portalUrl": "v.example.com", "authMode": "auto", "savePassword": false}))
                    .map(drop),
                "[field:name][code:required] ",
            ),
            (validate_settings_patch(&json!({"bogus": 1})).map(drop), "[field:bogus][code:unknown_field] "),
            (validate_settings_patch(&json!(42)).map(drop), "[code:invalid_type] "),
        ];
        for (r, prefix) in cases {
            let msg = r.unwrap_err().to_string();
            assert!(msg.starts_with(prefix), "{msg}");
            let info = crate::validation::parse_ipc_error(&msg);
            assert!(!info.message.starts_with('['));
        }
        assert_eq!(
            not_confirmed_error().to_string(),
            "[code:not_confirmed] The change was not confirmed"
        );
    }
}
