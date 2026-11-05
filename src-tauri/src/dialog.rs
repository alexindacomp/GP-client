//! Native confirmation dialog for elevation-relevant settings (tauri-plugin-dialog).
//!
//! The plugin cannot choose the default button: the first button is the default on Windows
//! (TaskDialog) and macOS (NSAlert). So the localized Cancel label goes into the first ("ok")
//! slot and Apply into the second; only an explicit click on Apply confirms. Enter (default),
//! Escape and closing the dialog all decline — same as Electron's `defaultId/cancelId: 0`.

use async_trait::async_trait;
use gp_core::store::confirm_dialog::{ConfirmDialog, ConfirmDialogText};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind, MessageDialogResult};
use tokio::sync::oneshot;

use crate::window::MAIN;

pub(crate) struct TauriConfirmDialog {
    app: AppHandle,
}

impl TauriConfirmDialog {
    pub(crate) fn new(app: AppHandle) -> Self {
        TauriConfirmDialog { app }
    }
}

/// Dialog body: the message, then the detail block.
pub(crate) fn dialog_body(text: &ConfirmDialogText) -> String {
    if text.detail.is_empty() {
        text.message.clone()
    } else {
        format!("{}\n\n{}", text.message, text.detail)
    }
}

/// `true` only for an explicit click on the apply button.
pub(crate) fn is_apply(result: &MessageDialogResult, cancel: &str, apply: &str) -> bool {
    cancel != apply && matches!(result, MessageDialogResult::Custom(label) if label == apply)
}

#[async_trait]
impl ConfirmDialog for TauriConfirmDialog {
    async fn confirm(&self, text: &ConfirmDialogText) -> bool {
        let [cancel, apply] = text.buttons.clone();
        let mut builder = self
            .app
            .dialog()
            .message(dialog_body(text))
            .title(&text.title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                cancel.clone(),
                apply.clone(),
            ));
        if let Some(main) = self.app.get_webview_window(MAIN)
            && main.is_visible().unwrap_or(false)
        {
            builder = builder.parent(&main);
        }
        let (tx, rx) = oneshot::channel();
        builder.show_with_result(move |r| {
            let _ = tx.send(r);
        });
        let result = rx.await.unwrap_or(MessageDialogResult::Cancel);
        is_apply(&result, &cancel, &apply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_apply_button_confirms() {
        let (cancel, apply) = ("Отмена", "Применить");
        assert!(is_apply(
            &MessageDialogResult::Custom(apply.into()),
            cancel,
            apply
        ));
        for declined in [
            MessageDialogResult::Custom(cancel.into()),
            MessageDialogResult::Cancel,
            MessageDialogResult::Ok,
            MessageDialogResult::Yes,
            MessageDialogResult::Custom("other".into()),
        ] {
            assert!(!is_apply(&declined, cancel, apply), "{declined:?}");
        }
        // Indistinguishable labels never confirm.
        assert!(!is_apply(
            &MessageDialogResult::Custom("Same".into()),
            "Same",
            "Same"
        ));
    }

    #[test]
    fn body_joins_message_and_detail() {
        let mut t = ConfirmDialogText {
            title: "t".into(),
            message: "m".into(),
            detail: "d".into(),
            buttons: ["c".into(), "a".into()],
        };
        assert_eq!(dialog_body(&t), "m\n\nd");
        t.detail.clear();
        assert_eq!(dialog_body(&t), "m");
    }
}
