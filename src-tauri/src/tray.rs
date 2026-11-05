//! Tray icon and its localized menu. The menu is described by a pure
//! [`TrayMenuModel`] (unit-tested) and rebuilt on every state/profile/language change.

use gp_core::tray_labels::{TrayLabelKey, tray_label, tray_tooltip};
use gp_core::types::{Language, Profile, VpnState, VpnStatus};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Wry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IconState {
    Disconnected,
    Connecting,
    Connected,
}

pub(crate) fn icon_state_for(status: VpnStatus) -> IconState {
    match status {
        VpnStatus::Connected => IconState::Connected,
        VpnStatus::Disconnected | VpnStatus::Error => IconState::Disconnected,
        _ => IconState::Connecting,
    }
}

/// What a menu item does; encoded in the menu item id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrayAction {
    Connect(String),
    Disconnect,
    SelectProfile(String),
    Show,
    Quit,
}

impl TrayAction {
    pub(crate) fn menu_id(&self) -> String {
        match self {
            TrayAction::Connect(id) => format!("connect:{id}"),
            TrayAction::Disconnect => "disconnect".into(),
            TrayAction::SelectProfile(id) => format!("profile:{id}"),
            TrayAction::Show => "show".into(),
            TrayAction::Quit => "quit".into(),
        }
    }

    pub(crate) fn parse(menu_id: &str) -> Option<TrayAction> {
        if let Some(id) = menu_id.strip_prefix("connect:") {
            return (!id.is_empty()).then(|| TrayAction::Connect(id.into()));
        }
        if let Some(id) = menu_id.strip_prefix("profile:") {
            return (!id.is_empty()).then(|| TrayAction::SelectProfile(id.into()));
        }
        match menu_id {
            "disconnect" => Some(TrayAction::Disconnect),
            "show" => Some(TrayAction::Show),
            "quit" => Some(TrayAction::Quit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileEntry {
    pub(crate) label: String,
    pub(crate) action: TrayAction,
    pub(crate) checked: bool,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrayMenuModel {
    pub(crate) status_label: String,
    pub(crate) primary_label: String,
    /// `None`: the primary item is disabled.
    pub(crate) primary_action: Option<TrayAction>,
    pub(crate) profiles_label: String,
    /// Empty: a disabled "No profiles" entry is shown instead.
    pub(crate) profiles: Vec<ProfileEntry>,
    pub(crate) no_profiles_label: String,
    pub(crate) show_label: String,
    pub(crate) quit_label: String,
    pub(crate) tooltip: String,
    pub(crate) icon: IconState,
}

/// Selected profile: the explicitly selected one if it still exists, else the first.
fn selected_profile<'a>(profiles: &'a [Profile], selected: Option<&str>) -> Option<&'a Profile> {
    selected
        .and_then(|id| profiles.iter().find(|p| p.id == id))
        .or_else(|| profiles.first())
}

pub(crate) fn build_model(
    state: &VpnState,
    profiles: &[Profile],
    selected_profile_id: Option<&str>,
    lang: Language,
) -> TrayMenuModel {
    let l = |k| tray_label(lang, k).to_string();
    let status = state.status;
    let busy = !matches!(status, VpnStatus::Disconnected | VpnStatus::Error);
    let selected = selected_profile(profiles, selected_profile_id);
    let (primary_label, primary_action) = if busy {
        // A stop already in flight: another click would only add admin dialogs.
        let action = (status != VpnStatus::Disconnecting).then_some(TrayAction::Disconnect);
        (l(TrayLabelKey::Disconnect), action)
    } else {
        (
            l(TrayLabelKey::Connect),
            selected.map(|p| TrayAction::Connect(p.id.clone())),
        )
    };
    TrayMenuModel {
        status_label: l(TrayLabelKey::Status(status)),
        primary_label,
        primary_action,
        profiles_label: l(TrayLabelKey::Profiles),
        profiles: profiles
            .iter()
            .map(|p| ProfileEntry {
                label: p.name.clone(),
                action: TrayAction::SelectProfile(p.id.clone()),
                checked: selected.is_some_and(|s| s.id == p.id),
                enabled: !busy,
            })
            .collect(),
        no_profiles_label: l(TrayLabelKey::NoProfiles),
        show_label: l(TrayLabelKey::Show),
        quit_label: l(TrayLabelKey::Quit),
        tooltip: tray_tooltip(lang, status, state.assigned_ip.as_deref()),
        icon: icon_state_for(status),
    }
}

// ------------------------------------------------------------------ rendering

const TRAY_ID: &str = "main";

fn icon_bytes(state: IconState) -> &'static [u8] {
    // macOS menu bar: monochrome template images adapt to the light/dark menu bar.
    if cfg!(target_os = "macos") {
        match state {
            IconState::Disconnected => {
                include_bytes!("../../resources/tray/tray-disconnectedTemplate@2x.png")
            }
            IconState::Connecting => include_bytes!("../../resources/tray/tray-connectingTemplate@2x.png"),
            IconState::Connected => include_bytes!("../../resources/tray/tray-connectedTemplate@2x.png"),
        }
    } else {
        match state {
            IconState::Disconnected => include_bytes!("../../resources/tray/tray-disconnected@2x.png"),
            IconState::Connecting => include_bytes!("../../resources/tray/tray-connecting@2x.png"),
            IconState::Connected => include_bytes!("../../resources/tray/tray-connected@2x.png"),
        }
    }
}

fn icon(state: IconState) -> tauri::Result<Image<'static>> {
    Image::from_bytes(icon_bytes(state))
}

fn render_menu(app: &AppHandle, m: &TrayMenuModel) -> tauri::Result<Menu<Wry>> {
    let none = None::<&str>;
    let status = MenuItem::with_id(app, "status", &m.status_label, false, none)?;
    let primary_id = m
        .primary_action
        .as_ref()
        .map_or_else(|| "primary".to_string(), TrayAction::menu_id);
    let primary = MenuItem::with_id(
        app,
        primary_id,
        &m.primary_label,
        m.primary_action.is_some(),
        none,
    )?;

    let profile_items: Vec<CheckMenuItem<Wry>> = m
        .profiles
        .iter()
        .map(|p| CheckMenuItem::with_id(app, p.action.menu_id(), &p.label, p.enabled, p.checked, none))
        .collect::<tauri::Result<_>>()?;
    let no_profiles = MenuItem::with_id(app, "no-profiles", &m.no_profiles_label, false, none)?;
    let submenu_items: Vec<&dyn IsMenuItem<Wry>> = if profile_items.is_empty() {
        vec![&no_profiles]
    } else {
        profile_items.iter().map(|i| i as &dyn IsMenuItem<Wry>).collect()
    };
    let profiles = Submenu::with_id_and_items(app, "profiles", &m.profiles_label, true, &submenu_items)?;

    let show = MenuItem::with_id(app, TrayAction::Show.menu_id(), &m.show_label, true, none)?;
    let quit = MenuItem::with_id(app, TrayAction::Quit.menu_id(), &m.quit_label, true, none)?;
    Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &primary,
            &profiles,
            &PredefinedMenuItem::separator(app)?,
            &show,
            &quit,
        ],
    )
}

pub(crate) struct AppTray {
    tray: TrayIcon<Wry>,
    icon: std::sync::Mutex<IconState>,
}

impl AppTray {
    /// Creates the tray icon; menu clicks are delivered as [`TrayAction`]s, a left click on the
    /// icon (Windows/Linux) shows the window.
    pub(crate) fn create(
        app: &AppHandle,
        model: &TrayMenuModel,
        on_action: impl Fn(&AppHandle, TrayAction) + Send + Sync + 'static,
    ) -> tauri::Result<Self> {
        let on_action = std::sync::Arc::new(on_action);
        let on_click = on_action.clone();
        let tray = TrayIconBuilder::with_id(TRAY_ID)
            .icon(icon(model.icon)?)
            .icon_as_template(cfg!(target_os = "macos"))
            .tooltip(&model.tooltip)
            .menu(&render_menu(app, model)?)
            // macOS: a click opens the menu (menu bar convention); elsewhere it shows the window.
            .show_menu_on_left_click(cfg!(target_os = "macos"))
            .on_menu_event(move |app, event| {
                if let Some(action) = TrayAction::parse(event.id().as_ref()) {
                    on_action(app, action);
                }
            })
            .on_tray_icon_event(move |tray, event| {
                if cfg!(not(target_os = "macos"))
                    && let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                {
                    on_click(tray.app_handle(), TrayAction::Show);
                }
            })
            .build(app)?;
        Ok(AppTray {
            tray,
            icon: std::sync::Mutex::new(model.icon),
        })
    }

    /// Applies `model`. Must run on the main thread (see `AppState::refresh_tray`): all updates
    /// are then serialized in the order they were scheduled, and the tray calls below run
    /// directly instead of waiting for the main thread. No lock is held across them.
    pub(crate) fn update(&self, app: &AppHandle, model: &TrayMenuModel) -> tauri::Result<()> {
        let icon_changed = {
            let mut current = self
                .icon
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, model.icon) != model.icon
        };
        if icon_changed {
            if cfg!(target_os = "macos") {
                self.tray
                    .set_icon_with_as_template(Some(icon(model.icon)?), true)?;
            } else {
                self.tray.set_icon(Some(icon(model.icon)?))?;
            }
        }
        self.tray.set_tooltip(Some(&model.tooltip))?;
        self.tray.set_menu(Some(render_menu(app, model)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_core::types::AuthMode;

    fn profile(id: &str, name: &str) -> Profile {
        Profile {
            id: id.into(),
            name: name.into(),
            portal_url: "https://vpn.example.com".into(),
            username: None,
            auth_mode: AuthMode::Auto,
            preferred_gateway: None,
            save_password: false,
        }
    }

    #[test]
    fn menu_ids_round_trip() {
        for a in [
            TrayAction::Connect("p-1".into()),
            TrayAction::Disconnect,
            TrayAction::SelectProfile("p-2".into()),
            TrayAction::Show,
            TrayAction::Quit,
        ] {
            assert_eq!(TrayAction::parse(&a.menu_id()), Some(a));
        }
        for junk in [
            "",
            "status",
            "primary",
            "no-profiles",
            "connect:",
            "profile:",
            "profiles",
        ] {
            assert_eq!(TrayAction::parse(junk), None, "{junk}");
        }
    }

    #[test]
    fn idle_menu_connects_the_selected_profile() {
        let profiles = [profile("a", "Office"), profile("b", "Lab")];
        let m = build_model(
            &VpnState::new(VpnStatus::Disconnected),
            &profiles,
            Some("b"),
            Language::En,
        );
        assert_eq!(m.status_label, "Disconnected");
        assert_eq!(m.primary_label, "Connect");
        assert_eq!(m.primary_action, Some(TrayAction::Connect("b".into())));
        assert_eq!(
            m.profiles
                .iter()
                .map(|p| (p.checked, p.enabled))
                .collect::<Vec<_>>(),
            vec![(false, true), (true, true)]
        );
        assert_eq!(m.icon, IconState::Disconnected);
        assert_eq!(m.tooltip, "GP Connect: Disconnected");
    }

    #[test]
    fn unknown_or_missing_selection_falls_back_to_the_first_profile() {
        let profiles = [profile("a", "Office"), profile("b", "Lab")];
        let st = VpnState::new(VpnStatus::Error);
        for sel in [None, Some("gone")] {
            let m = build_model(&st, &profiles, sel, Language::Ru);
            assert_eq!(m.primary_action, Some(TrayAction::Connect("a".into())));
            assert!(m.profiles[0].checked);
        }
        let empty = build_model(&st, &[], None, Language::Ru);
        assert_eq!(empty.primary_action, None);
        assert!(empty.profiles.is_empty());
        assert_eq!(empty.no_profiles_label, "Нет профилей");
    }

    #[test]
    fn busy_menu_disconnects_and_locks_the_profile_choice() {
        let profiles = [profile("a", "Office")];
        let mut st = VpnState::new(VpnStatus::Connected);
        st.assigned_ip = Some("10.0.0.5".into());
        let m = build_model(&st, &profiles, Some("a"), Language::Uk);
        assert_eq!(m.primary_label, "Відключити");
        assert_eq!(m.primary_action, Some(TrayAction::Disconnect));
        assert!(!m.profiles[0].enabled);
        assert_eq!(m.icon, IconState::Connected);
        assert!(m.tooltip.ends_with("10.0.0.5"));

        st.status = VpnStatus::Disconnecting;
        let m = build_model(&st, &profiles, Some("a"), Language::En);
        assert_eq!(m.primary_label, "Disconnect");
        assert_eq!(m.primary_action, None, "disabled while disconnecting");
        assert_eq!(m.icon, IconState::Connecting);
    }

    #[test]
    fn icon_states() {
        assert_eq!(icon_state_for(VpnStatus::Error), IconState::Disconnected);
        assert_eq!(icon_state_for(VpnStatus::Reconnecting), IconState::Connecting);
        assert_eq!(icon_state_for(VpnStatus::Prelogin), IconState::Connecting);
    }

    #[test]
    fn tray_icons_are_valid_pngs() {
        for s in [
            IconState::Disconnected,
            IconState::Connecting,
            IconState::Connected,
        ] {
            assert!(icon_bytes(s).starts_with(b"\x89PNG\r\n\x1a\n"));
        }
    }
}
