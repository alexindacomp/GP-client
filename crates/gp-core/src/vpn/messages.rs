//! User-facing texts for `VpnState.error.message`.
//!
//! `message` is only the next step for the user: the renderer shows its own title per error
//! code (and per hint), the technical cause goes to `error.detail`. Messages must not reference
//! the README (installed users don't have it) and must use paths/tools of the platform.

use crate::platform::Platform;
use crate::types::{Language, VpnErrorCode, VpnErrorHint};
use crate::util::{js_len, js_trim, js_truncate};

const MAX_DETAIL: usize = 300;

fn code_message(lang: Language, code: VpnErrorCode) -> &'static str {
    use VpnErrorCode as C;
    match lang {
        Language::Ru => match code {
            C::OpenconnectNotFound => "Установите OpenConnect или укажите путь к нему в настройках.",
            C::AuthFailed => "Проверьте логин, пароль или одноразовый код и попробуйте снова.",
            C::AuthCancelled => "Нажмите «Подключить», чтобы войти снова.",
            C::PortalUnreachable => "Проверьте адрес портала и подключение к сети.",
            C::TlsError => {
                "Сервер предъявил неизвестный сертификат. Если вы доверяете ему, добавьте в доп. аргументы --servercert=pin-sha256:<…> — значение pin есть в журнале."
            }
            C::PrivilegesDenied => "Подтвердите запрос прав администратора при подключении.",
            C::TunnelFailed | C::Unknown => "Попробуйте подключиться снова; подробности — в журнале.",
        },
        Language::En => match code {
            C::OpenconnectNotFound => "Install OpenConnect or set its path in Settings.",
            C::AuthFailed => "Check your username, password or one-time code and try again.",
            C::AuthCancelled => "Press Connect to sign in again.",
            C::PortalUnreachable => "Check the portal address and your network connection.",
            C::TlsError => {
                "The server presented an unknown certificate. If you trust it, add --servercert=pin-sha256:<…> to extra arguments — the pin value is in the log."
            }
            C::PrivilegesDenied => "Approve the administrator prompt when connecting.",
            C::TunnelFailed | C::Unknown => "Try connecting again; see the log for details.",
        },
        Language::Uk => match code {
            C::OpenconnectNotFound => "Встановіть OpenConnect або вкажіть шлях до нього в налаштуваннях.",
            C::AuthFailed => "Перевірте логін, пароль або одноразовий код і спробуйте ще раз.",
            C::AuthCancelled => "Натисніть «Підключити», щоб увійти знову.",
            C::PortalUnreachable => "Перевірте адресу порталу та підключення до мережі.",
            C::TlsError => {
                "Сервер надав невідомий сертифікат. Якщо ви йому довіряєте, додайте в додаткові аргументи --servercert=pin-sha256:<…> — значення pin є в журналі."
            }
            C::PrivilegesDenied => "Підтвердьте запит прав адміністратора під час підключення.",
            C::TunnelFailed | C::Unknown => "Спробуйте підключитися ще раз; подробиці — у журналі.",
        },
    }
}

fn untrusted_binary(lang: Language, platform: Platform) -> &'static str {
    match (lang, platform) {
        (Language::Ru, Platform::Win32) => {
            "Переустановите GP Connect (установщик кладёт OpenConnect в Program Files) или укажите путь к openconnect.exe в папке, которую может менять только администратор."
        }
        (Language::Ru, Platform::Darwin) => {
            "Установите OpenConnect через MacPorts: sudo port install openconnect — клиент запускает openconnect только из папок, которые может менять лишь администратор."
        }
        (Language::Ru, Platform::Linux) => {
            "Установите OpenConnect из репозитория (sudo apt install openconnect — он окажется в /usr/sbin или /usr/bin) — клиент запускает openconnect только из папок, которые может менять лишь администратор."
        }
        (Language::En, Platform::Win32) => {
            "Reinstall GP Connect (its installer puts OpenConnect into Program Files), or set the path to an openconnect.exe in a folder only an administrator can change."
        }
        (Language::En, Platform::Darwin) => {
            "Install OpenConnect with MacPorts: sudo port install openconnect — the client only runs openconnect from folders that only an administrator can change."
        }
        (Language::En, Platform::Linux) => {
            "Install OpenConnect from your distribution (sudo apt install openconnect — it goes to /usr/sbin or /usr/bin) — the client only runs openconnect from folders that only an administrator can change."
        }
        (Language::Uk, Platform::Win32) => {
            "Перевстановіть GP Connect (інсталятор розміщує OpenConnect у Program Files) або вкажіть шлях до openconnect.exe у папці, яку може змінювати тільки адміністратор."
        }
        (Language::Uk, Platform::Darwin) => {
            "Встановіть OpenConnect через MacPorts: sudo port install openconnect — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор."
        }
        (Language::Uk, Platform::Linux) => {
            "Встановіть OpenConnect із репозиторію (sudo apt install openconnect — він опиниться в /usr/sbin або /usr/bin) — клієнт запускає openconnect лише з папок, які може змінювати тільки адміністратор."
        }
    }
}

fn other_hint(lang: Language, hint: VpnErrorHint) -> &'static str {
    use VpnErrorHint as H;
    match lang {
        Language::Ru => match hint {
            H::UntrustedHomebrew => {
                "OpenConnect из Homebrew может изменить любая программа пользователя. Установите его через MacPorts: sudo port install openconnect."
            }
            H::StopFailed => {
                "VPN может быть ещё активен: для остановки openconnect нужна авторизация администратора. Нажмите «Отключить» ещё раз."
            }
            H::SettingsNotConfirmed => {
                "Подключитесь снова и подтвердите изменённые настройки openconnect или исправьте их в настройках."
            }
            H::UntrustedBinary => untrusted_binary(lang, Platform::Linux),
        },
        Language::En => match hint {
            H::UntrustedHomebrew => {
                "Homebrew’s OpenConnect can be modified by any of your programs. Install it with MacPorts: sudo port install openconnect."
            }
            H::StopFailed => {
                "The VPN may still be active: stopping openconnect needs administrator authorization. Press Disconnect again."
            }
            H::SettingsNotConfirmed => {
                "Connect again and confirm the changed openconnect settings, or correct them in Settings."
            }
            H::UntrustedBinary => untrusted_binary(lang, Platform::Linux),
        },
        Language::Uk => match hint {
            H::UntrustedHomebrew => {
                "OpenConnect із Homebrew може змінити будь-яка програма користувача. Встановіть його через MacPorts: sudo port install openconnect."
            }
            H::StopFailed => {
                "VPN може бути ще активним: для зупинки openconnect потрібна авторизація адміністратора. Натисніть «Відключити» ще раз."
            }
            H::SettingsNotConfirmed => {
                "Підключіться знову й підтвердьте змінені налаштування openconnect або виправте їх у налаштуваннях."
            }
            H::UntrustedBinary => untrusted_binary(lang, Platform::Linux),
        },
    }
}

/// User-facing next step for an error code (or a cause-specific hint), for the given platform.
pub fn error_message(
    code: VpnErrorCode,
    lang: Language,
    hint: Option<VpnErrorHint>,
    platform: Platform,
) -> &'static str {
    match hint {
        Some(VpnErrorHint::UntrustedBinary) => untrusted_binary(lang, platform),
        Some(h) => other_hint(lang, h),
        None => code_message(lang, code),
    }
}

/// Technical detail for `VpnState.error.detail` (already masked by the caller), trimmed and
/// capped at 300 characters (UTF-16 units, like the TS version) plus an ellipsis.
pub fn error_detail(detail: Option<&str>) -> Option<String> {
    let d = js_trim(detail?);
    if d.is_empty() {
        return None;
    }
    if js_len(d) > MAX_DETAIL {
        return Some(format!("{}…", js_truncate(d, MAX_DETAIL)));
    }
    Some(d.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptLabel {
    Username,
    Password,
}

pub fn prompt_label(kind: PromptLabel, lang: Language) -> &'static str {
    match (lang, kind) {
        (Language::Ru, PromptLabel::Username) => "Имя пользователя",
        (Language::En, PromptLabel::Username) => "Username",
        (Language::Uk, PromptLabel::Username) => "Ім’я користувача",
        (Language::Ru | Language::Uk, PromptLabel::Password) => "Пароль",
        (Language::En, PromptLabel::Password) => "Password",
    }
}

/// Shown when openconnect survives both the graceful stop and the kill.
pub fn stop_failed_message(lang: Language) -> &'static str {
    other_hint(lang, VpnErrorHint::StopFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_cyrillic_straight_apostrophe(t: &str) -> bool {
        let chars: Vec<char> = t.chars().collect();
        let cyr = |c: char| ('\u{0400}'..='\u{04ff}').contains(&c);
        chars.windows(3).any(|w| cyr(w[0]) && w[1] == '\'' && cyr(w[2]))
    }

    #[test]
    fn exist_for_every_language_code_hint_platform_without_readme_references() {
        for lang in Language::ALL {
            for platform in Platform::ALL {
                for code in VpnErrorCode::ALL {
                    let m = error_message(code, lang, None, platform);
                    assert!(m.trim().chars().count() > 10, "{lang:?}/{code:?}");
                    assert!(!m.to_lowercase().contains("readme"));
                }
                for hint in VpnErrorHint::ALL {
                    let m = error_message(VpnErrorCode::PrivilegesDenied, lang, Some(hint), platform);
                    assert!(m.trim().chars().count() > 10, "{lang:?}/{hint:?}");
                    assert!(!m.to_lowercase().contains("readme"));
                }
            }
            assert!(!prompt_label(PromptLabel::Username, lang).is_empty());
            assert!(!prompt_label(PromptLabel::Password, lang).is_empty());
            assert_eq!(
                stop_failed_message(lang),
                error_message(
                    VpnErrorCode::PrivilegesDenied,
                    lang,
                    Some(VpnErrorHint::StopFailed),
                    Platform::current()
                )
            );
        }
    }

    #[test]
    fn uk_is_a_real_translation() {
        for code in VpnErrorCode::ALL {
            let uk = error_message(code, Language::Uk, None, Platform::Linux);
            assert_ne!(uk, error_message(code, Language::Ru, None, Platform::Linux));
            assert_ne!(uk, error_message(code, Language::En, None, Platform::Linux));
        }
    }

    #[test]
    fn untrusted_binary_is_platform_specific() {
        for lang in Language::ALL {
            let hint = Some(VpnErrorHint::UntrustedBinary);
            let win = error_message(VpnErrorCode::PrivilegesDenied, lang, hint, Platform::Win32);
            let mac = error_message(VpnErrorCode::PrivilegesDenied, lang, hint, Platform::Darwin);
            let lin = error_message(VpnErrorCode::PrivilegesDenied, lang, hint, Platform::Linux);
            assert!(
                win.contains("Program Files")
                    && win.contains("GP Connect")
                    && !win.contains("OpenConnect-GUI")
            );
            assert!(
                !["/usr/", "apt", "MacPorts", "port install"]
                    .iter()
                    .any(|s| win.contains(s))
            );
            assert!(mac.contains("MacPorts"));
            assert!(!mac.contains("Program Files") && !mac.contains("apt install"));
            assert!(lin.contains("apt install openconnect") && lin.contains("/usr/sbin"));
            assert!(!lin.contains("Program Files") && !lin.contains("MacPorts"));
        }
    }

    #[test]
    fn the_ru_windows_text_matches_the_agreed_copy() {
        assert_eq!(
            error_message(
                VpnErrorCode::PrivilegesDenied,
                Language::Ru,
                Some(VpnErrorHint::UntrustedBinary),
                Platform::Win32
            ),
            "Переустановите GP Connect (установщик кладёт OpenConnect в Program Files) или укажите путь к openconnect.exe в папке, которую может менять только администратор."
        );
    }

    #[test]
    fn ukrainian_uses_the_typographic_apostrophe() {
        let mut texts = vec![
            prompt_label(PromptLabel::Username, Language::Uk),
            prompt_label(PromptLabel::Password, Language::Uk),
        ];
        for platform in Platform::ALL {
            for code in VpnErrorCode::ALL {
                texts.push(error_message(code, Language::Uk, None, platform));
            }
            for hint in VpnErrorHint::ALL {
                texts.push(error_message(
                    VpnErrorCode::PrivilegesDenied,
                    Language::Uk,
                    Some(hint),
                    platform,
                ));
            }
        }
        for t in texts {
            assert!(!has_cyrillic_straight_apostrophe(t), "{t}");
        }
        assert_eq!(
            prompt_label(PromptLabel::Username, Language::Uk),
            "Ім’я користувача"
        );
    }

    #[test]
    fn error_detail_trims_and_caps() {
        assert_eq!(error_detail(None), None);
        assert_eq!(error_detail(Some("   ")), None);
        assert_eq!(
            error_detail(Some("  Login failed. ")).as_deref(),
            Some("Login failed.")
        );
        let long = "x".repeat(301);
        assert_eq!(error_detail(Some(&long)), Some(format!("{}…", "x".repeat(300))));
        assert_eq!(error_detail(Some(&"y".repeat(300))), Some("y".repeat(300)));
    }
}
