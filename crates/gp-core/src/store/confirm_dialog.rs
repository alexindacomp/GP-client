//! Texts of the native confirmation dialog for elevation-relevant settings. Localized with human labels; Cancel is button 0 and is both
//! the default and the cancel button.

use async_trait::async_trait;

use super::confirmed_settings::GuardedKey;
use crate::types::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    /// The user changes the settings in the app.
    Change,
    /// Values were changed outside the app (on disk) and are about to be used.
    External,
}

/// A guarded setting value as shown in the dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmValue {
    /// Not set (default).
    Default,
    Path(String),
    Args(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmItem {
    pub key: GuardedKey,
    pub value: ConfirmValue,
    /// Value was changed outside the app (on disk) and is shown for confirmation too.
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialogText {
    pub title: String,
    pub message: String,
    pub detail: String,
    /// `[cancel, apply]` — index 0 is the default and the cancel button.
    pub buttons: [String; 2],
}

/// Native confirmation dialog (implemented by the app with tauri-plugin-dialog). Returns `true`
/// only when the user pressed the apply button (index 1).
#[async_trait]
pub trait ConfirmDialog: Send + Sync {
    async fn confirm(&self, text: &ConfirmDialogText) -> bool;
}

struct Strings {
    labels: [&'static str; 3],
    default: &'static str,
    none: &'static str,
    external_suffix: &'static str,
    change: &'static str,
    external: &'static str,
    buttons: [&'static str; 2],
}

fn strings(lang: Language) -> Strings {
    match lang {
        Language::Ru => Strings {
            labels: ["Путь к openconnect", "HIP-скрипт", "Дополнительные аргументы"],
            default: "по умолчанию",
            none: "нет",
            external_suffix: " (изменено вне GP Connect)",
            change: "Подтвердите изменения: эти параметры определяют, что запускается с правами администратора.",
            external: "Эти настройки изменены вне GP Connect. Использовать их при запуске с правами администратора?",
            buttons: ["Отмена", "Применить"],
        },
        Language::En => Strings {
            labels: ["OpenConnect path", "HIP script", "Extra arguments"],
            default: "default",
            none: "none",
            external_suffix: " (changed outside GP Connect)",
            change: "Confirm the changes: these settings control what runs with administrator rights.",
            external: "These settings were changed outside GP Connect. Use them when running with administrator rights?",
            buttons: ["Cancel", "Apply"],
        },
        Language::Uk => Strings {
            labels: ["Шлях до openconnect", "HIP-скрипт", "Додаткові аргументи"],
            default: "за замовчуванням",
            none: "немає",
            external_suffix: " (змінено поза GP Connect)",
            change: "Підтвердьте зміни: ці параметри визначають, що запускається з правами адміністратора.",
            external: "Ці налаштування змінено поза GP Connect. Використовувати їх під час запуску з правами адміністратора?",
            buttons: ["Скасувати", "Застосувати"],
        },
    }
}

fn label(s: &Strings, key: GuardedKey) -> &'static str {
    match key {
        GuardedKey::OpenconnectPath => s.labels[0],
        GuardedKey::HipScriptPath => s.labels[1],
        GuardedKey::ExtraArgs => s.labels[2],
    }
}

fn format_value(v: &ConfirmValue, s: &Strings) -> String {
    match v {
        ConfirmValue::Default => s.default.to_string(),
        ConfirmValue::Args(a) if a.is_empty() => s.none.to_string(),
        ConfirmValue::Args(a) => a.join(" "),
        ConfirmValue::Path(p) => p.clone(),
    }
}

pub fn confirm_dialog_text(kind: ConfirmKind, lang: Language, items: &[ConfirmItem]) -> ConfirmDialogText {
    let s = strings(lang);
    let detail = items
        .iter()
        .map(|it| {
            let suffix = if it.external { s.external_suffix } else { "" };
            format!("{}: {}{suffix}", label(&s, it.key), format_value(&it.value, &s))
        })
        .collect::<Vec<_>>()
        .join("\n");
    ConfirmDialogText {
        title: "GP Connect".into(),
        message: match kind {
            ConfirmKind::Change => s.change,
            ConfirmKind::External => s.external,
        }
        .into(),
        detail,
        buttons: s.buttons.map(String::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_human_labels_and_localized_values_ru() {
        let t = confirm_dialog_text(
            ConfirmKind::Change,
            Language::Ru,
            &[
                ConfirmItem {
                    key: GuardedKey::OpenconnectPath,
                    value: ConfirmValue::Path("C:\\Program Files\\OpenConnect-GUI\\openconnect.exe".into()),
                    external: false,
                },
                ConfirmItem {
                    key: GuardedKey::HipScriptPath,
                    value: ConfirmValue::Default,
                    external: false,
                },
                ConfirmItem {
                    key: GuardedKey::ExtraArgs,
                    value: ConfirmValue::Args(vec!["-v".into(), "--no-dtls".into()]),
                    external: true,
                },
            ],
        );
        assert_eq!(t.title, "GP Connect");
        assert!(t.message.contains("правами администратора"));
        assert_eq!(
            t.detail,
            [
                "Путь к openconnect: C:\\Program Files\\OpenConnect-GUI\\openconnect.exe",
                "HIP-скрипт: по умолчанию",
                "Дополнительные аргументы: -v --no-dtls (изменено вне GP Connect)",
            ]
            .join("\n")
        );
        assert_eq!(t.buttons, ["Отмена", "Применить"]);
        assert!(
            !["openconnectPath", "hipScriptPath", "extraArgs"]
                .iter()
                .any(|k| t.detail.contains(k))
        );
    }

    #[test]
    fn en_and_uk() {
        for (lang, path_label, empty_args, buttons) in [
            (
                Language::En,
                "OpenConnect path",
                "Extra arguments: none",
                ["Cancel", "Apply"],
            ),
            (
                Language::Uk,
                "Шлях до openconnect",
                "Додаткові аргументи: немає",
                ["Скасувати", "Застосувати"],
            ),
        ] {
            let t = confirm_dialog_text(
                ConfirmKind::External,
                lang,
                &[
                    ConfirmItem {
                        key: GuardedKey::OpenconnectPath,
                        value: ConfirmValue::Path("/usr/sbin/openconnect".into()),
                        external: true,
                    },
                    ConfirmItem {
                        key: GuardedKey::ExtraArgs,
                        value: ConfirmValue::Args(vec![]),
                        external: false,
                    },
                ],
            );
            let lines: Vec<&str> = t.detail.split('\n').collect();
            assert!(lines[0].starts_with(&format!("{path_label}: /usr/sbin/openconnect")));
            assert_eq!(lines[1], empty_args);
            assert_eq!(t.buttons, buttons);
        }
    }

    #[test]
    fn cancel_is_first_and_the_two_kinds_differ() {
        for lang in Language::ALL {
            let a = confirm_dialog_text(ConfirmKind::Change, lang, &[]);
            let b = confirm_dialog_text(ConfirmKind::External, lang, &[]);
            assert_ne!(a.message, b.message);
            assert!(["Отмена", "Cancel", "Скасувати"].contains(&a.buttons[0].as_str()));
        }
    }
}
