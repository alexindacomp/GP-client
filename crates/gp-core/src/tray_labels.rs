//! Tray menu / tooltip strings.

use crate::types::{Language, VpnStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrayLabelKey {
    Connect,
    Disconnect,
    Profiles,
    NoProfiles,
    Show,
    Quit,
    Status(VpnStatus),
}

impl TrayLabelKey {
    /// Every key, for completeness checks.
    pub fn all() -> Vec<TrayLabelKey> {
        let mut keys = vec![
            TrayLabelKey::Connect,
            TrayLabelKey::Disconnect,
            TrayLabelKey::Profiles,
            TrayLabelKey::NoProfiles,
            TrayLabelKey::Show,
            TrayLabelKey::Quit,
        ];
        keys.extend(VpnStatus::ALL.into_iter().map(TrayLabelKey::Status));
        keys
    }
}

pub fn tray_label(lang: Language, key: TrayLabelKey) -> &'static str {
    use TrayLabelKey as K;
    use VpnStatus as S;
    match lang {
        Language::Ru => match key {
            K::Connect => "Подключить",
            K::Disconnect => "Отключить",
            K::Profiles => "Профиль",
            K::NoProfiles => "Нет профилей",
            K::Show => "Показать окно",
            K::Quit => "Выход",
            K::Status(S::Disconnected) => "Отключено",
            K::Status(S::Prelogin) => "Подготовка…",
            K::Status(S::Authenticating) => "Вход…",
            K::Status(S::Connecting) => "Подключение…",
            K::Status(S::Connected) => "Подключено",
            K::Status(S::Disconnecting) => "Отключение…",
            K::Status(S::Reconnecting) => "Переподключение…",
            K::Status(S::Error) => "Ошибка",
        },
        Language::En => match key {
            K::Connect => "Connect",
            K::Disconnect => "Disconnect",
            K::Profiles => "Profile",
            K::NoProfiles => "No profiles",
            K::Show => "Show window",
            K::Quit => "Quit",
            K::Status(S::Disconnected) => "Disconnected",
            K::Status(S::Prelogin) => "Preparing…",
            K::Status(S::Authenticating) => "Signing in…",
            K::Status(S::Connecting) => "Connecting…",
            K::Status(S::Connected) => "Connected",
            K::Status(S::Disconnecting) => "Disconnecting…",
            K::Status(S::Reconnecting) => "Reconnecting…",
            K::Status(S::Error) => "Error",
        },
        Language::Uk => match key {
            K::Connect => "Підключити",
            K::Disconnect => "Відключити",
            K::Profiles => "Профіль",
            K::NoProfiles => "Немає профілів",
            K::Show => "Показати вікно",
            K::Quit => "Вихід",
            K::Status(S::Disconnected) => "Відключено",
            K::Status(S::Prelogin) => "Підготовка…",
            K::Status(S::Authenticating) => "Вхід…",
            K::Status(S::Connecting) => "Підключення…",
            K::Status(S::Connected) => "Підключено",
            K::Status(S::Disconnecting) => "Відключення…",
            K::Status(S::Reconnecting) => "Перепідключення…",
            K::Status(S::Error) => "Помилка",
        },
    }
}

/// Tooltip text, e.g. "GP Connect: Подключено — 10.0.0.5".
pub fn tray_tooltip(lang: Language, status: VpnStatus, assigned_ip: Option<&str>) -> String {
    let label = tray_label(lang, TrayLabelKey::Status(status));
    match assigned_ip {
        Some(ip) if status == VpnStatus::Connected && !ip.is_empty() => format!("GP Connect: {label} — {ip}"),
        _ => format!("GP Connect: {label}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_languages_have_non_empty_values_for_every_key() {
        for lang in Language::ALL {
            for key in TrayLabelKey::all() {
                assert!(!tray_label(lang, key).is_empty(), "{lang:?}/{key:?}");
            }
        }
    }

    #[test]
    fn tooltip_is_localized_and_shows_the_ip_only_when_connected() {
        assert_eq!(
            tray_tooltip(Language::Uk, VpnStatus::Connected, Some("10.0.0.5")),
            "GP Connect: Підключено — 10.0.0.5"
        );
        assert_eq!(
            tray_tooltip(Language::En, VpnStatus::Connecting, Some("10.0.0.5")),
            "GP Connect: Connecting…"
        );
        assert_eq!(
            tray_tooltip(Language::Ru, VpnStatus::Disconnected, None),
            "GP Connect: Отключено"
        );
    }
}
