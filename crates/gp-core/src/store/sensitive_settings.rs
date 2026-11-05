//! Settings that influence what runs with administrator rights.

use super::confirmed_settings::GuardedKey;
use super::validation::SettingsPatch;
use crate::types::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveChange {
    pub key: GuardedKey,
    /// Human-readable new value (`(default)` / `(none)` when cleared).
    pub value: String,
}

/// Value of an optional path setting for logs/dialogs.
pub fn show_path_value(v: Option<&str>) -> String {
    v.map_or_else(|| "(default)".into(), String::from)
}

/// Value of the extra arguments for logs/dialogs.
pub fn show_args_value(v: &[String]) -> String {
    if v.is_empty() {
        "(none)".into()
    } else {
        v.join(" ")
    }
}

/// Human-readable value of a guarded setting.
pub fn show_setting_value(s: &Settings, key: GuardedKey) -> String {
    match key {
        GuardedKey::OpenconnectPath => show_path_value(s.openconnect_path.as_deref()),
        GuardedKey::HipScriptPath => show_path_value(s.hip_script_path.as_deref()),
        GuardedKey::ExtraArgs => show_args_value(&s.extra_args),
    }
}

/// Sensitive settings that a (validated) patch actually changes, with the new value rendered.
pub fn sensitive_changes(current: &Settings, patch: &SettingsPatch) -> Vec<SensitiveChange> {
    let mut out = Vec::new();
    if let Some(next) = &patch.openconnect_path
        && *next != current.openconnect_path
    {
        out.push(SensitiveChange {
            key: GuardedKey::OpenconnectPath,
            value: show_path_value(next.as_deref()),
        });
    }
    if let Some(next) = &patch.hip_script_path
        && *next != current.hip_script_path
    {
        out.push(SensitiveChange {
            key: GuardedKey::HipScriptPath,
            value: show_path_value(next.as_deref()),
        });
    }
    if let Some(next) = &patch.extra_args
        && *next != current.extra_args
    {
        out.push(SensitiveChange {
            key: GuardedKey::ExtraArgs,
            value: show_args_value(next),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Theme;

    fn current() -> Settings {
        Settings {
            openconnect_path: Some("/usr/sbin/openconnect".into()),
            extra_args: vec!["-v".into()],
            ..Settings::default()
        }
    }

    fn change(key: GuardedKey, value: &str) -> SensitiveChange {
        SensitiveChange {
            key,
            value: value.into(),
        }
    }

    #[test]
    fn lists_changed_security_relevant_settings() {
        let patch = SettingsPatch {
            openconnect_path: Some(Some("/usr/local/sbin/openconnect".into())),
            hip_script_path: Some(Some("/usr/libexec/hipreport.sh".into())),
            extra_args: Some(vec!["-v".into(), "--no-dtls".into()]),
            theme: Some(Theme::Dark),
            ..Default::default()
        };
        assert_eq!(
            sensitive_changes(&current(), &patch),
            [
                change(GuardedKey::OpenconnectPath, "/usr/local/sbin/openconnect"),
                change(GuardedKey::HipScriptPath, "/usr/libexec/hipreport.sh"),
                change(GuardedKey::ExtraArgs, "-v --no-dtls"),
            ]
        );
    }

    #[test]
    fn shows_cleared_values() {
        let patch = SettingsPatch {
            openconnect_path: Some(None),
            extra_args: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            sensitive_changes(&current(), &patch),
            [
                change(GuardedKey::OpenconnectPath, "(default)"),
                change(GuardedKey::ExtraArgs, "(none)")
            ]
        );
    }

    #[test]
    fn ignores_unchanged_and_non_sensitive_settings() {
        let same = SettingsPatch {
            openconnect_path: Some(Some("/usr/sbin/openconnect".into())),
            extra_args: Some(vec!["-v".into()]),
            ..Default::default()
        };
        assert!(sensitive_changes(&current(), &same).is_empty());
        let other = SettingsPatch {
            theme: Some(Theme::Light),
            auto_reconnect: Some(false),
            ..Default::default()
        };
        assert!(sensitive_changes(&current(), &other).is_empty());
    }
}
