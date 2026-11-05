//! Wire types of the UI contract. Field names and enum values are identical to
//! `src/shared/ipc.ts` (camelCase JSON, string unions as lowercase / SCREAMING_CASE strings).

use serde::{Deserialize, Serialize};

use crate::platform::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Auto,
    Password,
    Saml,
}

impl AuthMode {
    pub const ALL: [AuthMode; 3] = [AuthMode::Auto, AuthMode::Password, AuthMode::Saml];

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Auto => "auto",
            AuthMode::Password => "password",
            AuthMode::Saml => "saml",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub portal_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub auth_mode: AuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_gateway: Option<String>,
    pub save_password: bool,
}

/// Input of `profiles.save`: `id` absent → create, present → update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub portal_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub auth_mode: AuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_gateway: Option<String>,
    pub save_password: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    Disconnected,
    Prelogin,
    Authenticating,
    Connecting,
    Connected,
    Disconnecting,
    Reconnecting,
    Error,
}

impl VpnStatus {
    pub const ALL: [VpnStatus; 8] = [
        VpnStatus::Disconnected,
        VpnStatus::Prelogin,
        VpnStatus::Authenticating,
        VpnStatus::Connecting,
        VpnStatus::Connected,
        VpnStatus::Disconnecting,
        VpnStatus::Reconnecting,
        VpnStatus::Error,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VpnStatus::Disconnected => "disconnected",
            VpnStatus::Prelogin => "prelogin",
            VpnStatus::Authenticating => "authenticating",
            VpnStatus::Connecting => "connecting",
            VpnStatus::Connected => "connected",
            VpnStatus::Disconnecting => "disconnecting",
            VpnStatus::Reconnecting => "reconnecting",
            VpnStatus::Error => "error",
        }
    }
}

impl std::fmt::Display for VpnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    pub name: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VpnErrorCode {
    OpenconnectNotFound,
    AuthFailed,
    AuthCancelled,
    PortalUnreachable,
    TlsError,
    PrivilegesDenied,
    TunnelFailed,
    Unknown,
}

impl VpnErrorCode {
    pub const ALL: [VpnErrorCode; 8] = [
        VpnErrorCode::OpenconnectNotFound,
        VpnErrorCode::AuthFailed,
        VpnErrorCode::AuthCancelled,
        VpnErrorCode::PortalUnreachable,
        VpnErrorCode::TlsError,
        VpnErrorCode::PrivilegesDenied,
        VpnErrorCode::TunnelFailed,
        VpnErrorCode::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VpnErrorCode::OpenconnectNotFound => "OPENCONNECT_NOT_FOUND",
            VpnErrorCode::AuthFailed => "AUTH_FAILED",
            VpnErrorCode::AuthCancelled => "AUTH_CANCELLED",
            VpnErrorCode::PortalUnreachable => "PORTAL_UNREACHABLE",
            VpnErrorCode::TlsError => "TLS_ERROR",
            VpnErrorCode::PrivilegesDenied => "PRIVILEGES_DENIED",
            VpnErrorCode::TunnelFailed => "TUNNEL_FAILED",
            VpnErrorCode::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for VpnErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Specific cause behind an error code (see `VpnErrorHint` in src/shared/ipc.ts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnErrorHint {
    UntrustedBinary,
    UntrustedHomebrew,
    StopFailed,
    SettingsNotConfirmed,
}

impl VpnErrorHint {
    pub const ALL: [VpnErrorHint; 4] = [
        VpnErrorHint::UntrustedBinary,
        VpnErrorHint::UntrustedHomebrew,
        VpnErrorHint::StopFailed,
        VpnErrorHint::SettingsNotConfirmed,
    ];
}

/// `VpnState.error`: `message` is the localized next step, `detail` the masked technical cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStateError {
    pub code: VpnErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<VpnErrorHint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnState {
    pub status: VpnStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Gateway>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,
    /// Epoch milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<VpnStateError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateways: Option<Vec<Gateway>>,
}

impl VpnState {
    pub fn new(status: VpnStatus) -> Self {
        VpnState {
            status,
            profile_id: None,
            gateway: None,
            assigned_ip: None,
            connected_at: None,
            error: None,
            gateways: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptKind {
    Password,
    Otp,
    Text,
    Select,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPrompt {
    pub id: String,
    pub kind: PromptKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    System,
    Light,
    Dark,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::System, Theme::Light, Theme::Dark];

    pub fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Ru,
    En,
    Uk,
}

impl Language {
    pub const ALL: [Language; 3] = [Language::Ru, Language::En, Language::Uk];

    pub fn as_str(self) -> &'static str {
        match self {
            Language::Ru => "ru",
            Language::En => "en",
            Language::Uk => "uk",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub theme: Theme,
    pub launch_at_login: bool,
    pub connect_on_startup: bool,
    pub auto_reconnect: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openconnect_path: Option<String>,
    pub extra_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hip_script_path: Option<String>,
    pub language: Language,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_profile_id: Option<String>,
}

/// `DEFAULT_SETTINGS` of src/shared/ipc.ts.
impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: Theme::System,
            launch_at_login: false,
            connect_on_startup: false,
            auto_reconnect: true,
            openconnect_path: None,
            extra_args: Vec::new(),
            hip_script_path: None,
            language: Language::Ru,
            last_profile_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openconnect_version: Option<String>,
    pub openconnect_found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openconnect_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openconnect_trusted: Option<bool>,
    pub app_version: String,
    pub should_use_dark_colors: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_settings_match_the_ts_contract() {
        assert_eq!(
            serde_json::to_value(Settings::default()).unwrap(),
            json!({
                "theme": "system",
                "launchAtLogin": false,
                "connectOnStartup": false,
                "autoReconnect": true,
                "extraArgs": [],
                "language": "ru"
            })
        );
    }

    #[test]
    fn vpn_state_serializes_camel_case_without_absent_fields() {
        let mut s = VpnState::new(VpnStatus::Connected);
        s.profile_id = Some("p".into());
        s.assigned_ip = Some("10.0.0.1".into());
        s.connected_at = Some(1_700_000_000_000);
        s.error = Some(VpnStateError {
            code: VpnErrorCode::PrivilegesDenied,
            message: "m".into(),
            detail: None,
            hint: Some(VpnErrorHint::StopFailed),
        });
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({
                "status": "connected",
                "profileId": "p",
                "assignedIp": "10.0.0.1",
                "connectedAt": 1_700_000_000_000_i64,
                "error": { "code": "PRIVILEGES_DENIED", "message": "m", "hint": "stop_failed" }
            })
        );
    }

    #[test]
    fn enum_strings_match_the_ts_unions() {
        for code in VpnErrorCode::ALL {
            assert_eq!(serde_json::to_value(code).unwrap(), json!(code.as_str()));
        }
        for st in VpnStatus::ALL {
            assert_eq!(serde_json::to_value(st).unwrap(), json!(st.as_str()));
        }
        assert_eq!(
            serde_json::to_value(VpnErrorHint::SettingsNotConfirmed).unwrap(),
            json!("settings_not_confirmed")
        );
        assert_eq!(serde_json::to_value(PromptKind::Otp).unwrap(), json!("otp"));
        let p: AuthPrompt =
            serde_json::from_value(json!({"id": "1", "kind": "select", "message": "m", "options": ["a"]}))
                .unwrap();
        assert_eq!(p.options.as_deref(), Some(&["a".to_string()][..]));
    }
}
