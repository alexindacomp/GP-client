//! Main window: creation from tauri.conf.json, navigation lock-down, theme, platform backdrop
//! (Windows 11 Mica with a solid fallback, macOS vibrancy, Linux opaque) and show/focus.

use gp_core::types::Theme as SettingsTheme;
use tauri::window::Color;
use tauri::{AppHandle, Manager, Runtime, Theme, Url, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;

/// Label of the main window (the only window that may call commands).
pub(crate) const MAIN: &str = "main";

/// Command-line flag of a start at login: start in the tray without showing the window.
pub(crate) const HIDDEN_ARG: &str = "--hidden";

/// `nativeTheme.themeSource`: `None` follows the OS.
pub(crate) fn window_theme(theme: SettingsTheme) -> Option<Theme> {
    match theme {
        SettingsTheme::System => None,
        SettingsTheme::Light => Some(Theme::Light),
        SettingsTheme::Dark => Some(Theme::Dark),
    }
}

/// Solid background where no material is available (same colours as the Electron version).
pub(crate) fn solid_background(dark: bool) -> Color {
    if dark {
        Color(0x20, 0x20, 0x20, 0xff)
    } else {
        Color(0xf3, 0xf3, 0xf3, 0xff)
    }
}

/// The app's own pages: the bundled assets (`tauri://localhost` on macOS/Linux,
/// `http(s)://tauri.localhost` on Windows) or, in development, the dev server's origin.
pub(crate) fn is_app_url(url: &Url, dev_url: Option<&Url>) -> bool {
    if let Some(dev) = dev_url
        && url.origin() == dev.origin()
    {
        return true;
    }
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => url.port().is_none(),
        _ => false,
    }
}

/// Creates the (initially hidden) main window from the `main` entry of tauri.conf.json.
pub(crate) fn create_main_window(
    app: &AppHandle,
    on_page_loaded: impl Fn() + Send + Sync + 'static,
) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN)
        .cloned()
        .ok_or_else(|| tauri::Error::WindowNotFound)?;
    let dev_url = if cfg!(dev) {
        app.config().build.dev_url.clone()
    } else {
        None
    };
    let opener = app.clone();
    let builder = WebviewWindowBuilder::from_config(app, &config)?
        // Mica / vibrancy show through a transparent webview; Linux keeps an opaque window.
        .transparent(cfg!(any(windows, target_os = "macos")))
        // The UI never navigates away from its own page.
        .on_navigation(move |url| is_app_url(url, dev_url.as_ref()))
        // Links with target=_blank go to the system browser (https only).
        .on_new_window(move |url, _features| {
            if url.scheme() == "https" {
                let _ = opener.opener().open_url(url.as_str(), None::<&str>);
            }
            tauri::webview::NewWindowResponse::Deny
        })
        .on_page_load(move |_w, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                on_page_loaded();
            }
        });
    // Clipboard writes ("Copy" in the log view) need an explicit opt-in on WebKitGTK only.
    #[cfg(target_os = "linux")]
    let builder = builder.enable_clipboard_access();
    builder.build()
}

/// Effective dark mode of the main window (respects the theme forced in the settings).
pub(crate) fn is_dark<R: Runtime>(window: &WebviewWindow<R>) -> bool {
    matches!(window.theme(), Ok(Theme::Dark))
}

/// Applies the `theme` setting; the backdrop follows on the resulting `ThemeChanged` event and
/// is also refreshed here (no event is emitted when the effective theme does not change).
pub(crate) fn apply_theme_setting(window: &WebviewWindow, theme: SettingsTheme) {
    let _ = window.set_theme(window_theme(theme));
    apply_backdrop(window, is_dark(window));
}

/// Platform material behind the (transparent) webview, or a solid colour where unavailable.
pub(crate) fn apply_backdrop(window: &WebviewWindow, dark: bool) {
    #[cfg(windows)]
    {
        // Windows 11 22H2+; older systems get the solid theme colour behind the translucent UI.
        if window_vibrancy::apply_mica(window, Some(dark)).is_err() {
            let _ = window
                .as_ref()
                .window()
                .set_background_color(Some(solid_background(dark)));
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::sync::atomic::{AtomicBool, Ordering};

        use window_vibrancy::{NSVisualEffectMaterial, NSVisualEffectState, apply_vibrancy};

        // NSVisualEffectView adapts to light/dark itself; apply once.
        static APPLIED: AtomicBool = AtomicBool::new(false);
        if !APPLIED.swap(true, Ordering::SeqCst)
            && apply_vibrancy(
                window,
                NSVisualEffectMaterial::UnderWindowBackground,
                Some(NSVisualEffectState::Active),
                None,
            )
            .is_err()
        {
            let _ = window
                .as_ref()
                .window()
                .set_background_color(Some(solid_background(dark)));
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = window.set_background_color(Some(solid_background(dark)));
    }
}

/// Shows, restores and focuses the main window.
pub(crate) fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(MAIN) {
        if w.is_minimized().unwrap_or(false) {
            let _ = w.unminimize();
        }
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn maps_the_theme_setting_to_the_window_theme() {
        assert_eq!(window_theme(SettingsTheme::System), None);
        assert_eq!(window_theme(SettingsTheme::Light), Some(Theme::Light));
        assert_eq!(window_theme(SettingsTheme::Dark), Some(Theme::Dark));
    }

    #[test]
    fn only_the_app_origin_is_an_app_url() {
        for ok in [
            "tauri://localhost/",
            "tauri://localhost/index.html#/settings",
            "http://tauri.localhost/",
            "https://tauri.localhost/index.html",
        ] {
            assert!(is_app_url(&u(ok), None), "{ok}");
        }
        for bad in [
            "https://example.com/",
            "http://tauri.localhost.evil.com/",
            "http://tauri.localhost:8080/",
            "http://localhost:1420/",
            "file:///C:/index.html",
            "tauri://evil/",
            "data:text/html,hi",
        ] {
            assert!(!is_app_url(&u(bad), None), "{bad}");
        }
        let dev = u("http://localhost:1420");
        assert!(is_app_url(&u("http://localhost:1420/src/main.tsx"), Some(&dev)));
        assert!(!is_app_url(&u("http://localhost:1421/"), Some(&dev)));
    }

    #[test]
    fn solid_backgrounds_match_the_electron_colours() {
        assert_eq!(solid_background(true), Color(0x20, 0x20, 0x20, 0xff));
        assert_eq!(solid_background(false), Color(0xf3, 0xf3, 0xf3, 0xff));
    }
}
