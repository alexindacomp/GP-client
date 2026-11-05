//! Application state and wiring: stores, logger, openconnect discovery, the VPN engine and its
//! dependencies, main window, tray, event forwarding to the UI, settings side effects, startup
//! connect and orderly shutdown.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use gp_core::logging::{DEFAULT_CAPACITY, Logger};
use gp_core::openconnect::trust::strip_verbatim_prefix;
use gp_core::platform::Platform;
use gp_core::prelogin::{HttpPreloginClient, ReqwestTransport};
use gp_core::process::choose_elevation;
use gp_core::store::confirm_dialog::ConfirmDialog;
use gp_core::store::confirmed_settings::ConfirmedSettingsGuard;
use gp_core::store::profiles::ProfilesStore;
use gp_core::store::settings::{SettingsStore, WarningFn};
use gp_core::store::validation::SettingsPatch;
use gp_core::types::{AuthPrompt, ConnectOptions, Profile, Settings};
use gp_core::vpn::engine::EngineEvent;
use gp_core::vpn::{EngineDeps, EngineError, ProfileProvider, SettingsProvider, VpnEngine};
use tauri::{App, AppHandle, Emitter, Manager, RunEvent, Runtime, Theme, WindowEvent};
use tauri_plugin_autostart::ManagerExt as _;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::dialog::TauriConfirmDialog;
use crate::discovery::{AppOpenconnect, Discovery, trust_options};
use crate::migration::{ELECTRON_DIR_NAME, migrate_electron_data};
use crate::saml::{SamlSessions, SamlWindowAuthenticator};
use crate::secrets::KeyringSecretStore;
use crate::tray::{AppTray, TrayAction, TrayMenuModel, build_model};
use crate::window::{HIDDEN_ARG, MAIN, apply_backdrop, apply_theme_setting, create_main_window, show_main};

/// Event names of the UI contract (src/renderer/src/bridge/tauri.ts, `TAURI_EVENTS`).
pub(crate) const EV_VPN_STATE: &str = "gp:vpn:state";
pub(crate) const EV_VPN_PROMPT: &str = "gp:vpn:prompt";
pub(crate) const EV_LOG_LINE: &str = "gp:logs:line";
pub(crate) const EV_THEME_CHANGED: &str = "gp:system:themeChanged";

/// Schedules a tray refresh (installed by `setup` once the tray exists).
type TrayRefresh = Box<dyn Fn() + Send + Sync>;

/// Shared state of the app. Independent of the Tauri runtime, so the command layer can be tested
/// with `tauri::test::MockRuntime`.
pub(crate) struct AppState {
    pub(crate) logger: Arc<Logger>,
    pub(crate) settings: Arc<SettingsStore>,
    pub(crate) profiles: Arc<ProfilesStore>,
    pub(crate) guard: Arc<ConfirmedSettingsGuard>,
    pub(crate) dialog: Arc<dyn ConfirmDialog>,
    pub(crate) discovery: Arc<Discovery>,
    pub(crate) engine: VpnEngine,
    pub(crate) logs_dir: PathBuf,
    pub(crate) saml_data_root: PathBuf,
    /// Open SSO windows (closed before a profile's SSO data is deleted).
    pub(crate) saml_sessions: Arc<SamlSessions>,
    tray_refresh: OnceLock<TrayRefresh>,
    /// Set once quitting starts: the window close button stops hiding to the tray.
    quitting: Arc<AtomicBool>,
    shutdown_done: AtomicBool,
}

struct StoreProfiles(Arc<ProfilesStore>);

impl ProfileProvider for StoreProfiles {
    fn get_profile(&self, id: &str) -> Option<Profile> {
        self.0.get(id)
    }
    fn get_saved_password(&self, profile_id: &str) -> Option<String> {
        self.0.get_password(profile_id)
    }
}

struct StoreSettings(Arc<SettingsStore>);

impl SettingsProvider for StoreSettings {
    fn get_settings(&self) -> Settings {
        self.0.get()
    }
}

fn warning_fn(logger: &Arc<Logger>, source: &'static str) -> WarningFn {
    let logger = logger.clone();
    Arc::new(move |m: &str| logger.warn(source, m))
}

/// Windows elevated helper, installed next to the app executable (NSIS sidecar, see
/// tauri.windows.conf.json); not used elsewhere.
fn helper_path() -> std::io::Result<Option<PathBuf>> {
    if cfg!(windows) {
        let helper = std::env::current_exe()?.with_file_name(gp_elevate::HELPER_EXE);
        // Plain `C:\…` form (also what the UI and the logs show).
        Ok(Some(PathBuf::from(strip_verbatim_prefix(
            &helper.to_string_lossy(),
        ))))
    } else {
        Ok(None)
    }
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        logger: Arc<Logger>,
        settings: Arc<SettingsStore>,
        profiles: Arc<ProfilesStore>,
        guard: Arc<ConfirmedSettingsGuard>,
        dialog: Arc<dyn ConfirmDialog>,
        discovery: Arc<Discovery>,
        engine: VpnEngine,
        logs_dir: PathBuf,
        saml_data_root: PathBuf,
        saml_sessions: Arc<SamlSessions>,
    ) -> Self {
        AppState {
            logger,
            settings,
            profiles,
            guard,
            dialog,
            discovery,
            engine,
            logs_dir,
            saml_data_root,
            saml_sessions,
            tray_refresh: OnceLock::new(),
            quitting: Arc::new(AtomicBool::new(false)),
            shutdown_done: AtomicBool::new(false),
        }
    }

    /// Starts a connection and remembers the profile as the last used one.
    pub(crate) fn connect(&self, profile_id: &str, opts: ConnectOptions) -> Result<(), EngineError> {
        self.engine.connect(profile_id, opts)?;
        if self.settings.get().last_profile_id.as_deref() != Some(profile_id) {
            self.set_last_profile(Some(profile_id.to_string()));
        }
        Ok(())
    }

    pub(crate) fn set_last_profile(&self, id: Option<String>) {
        let patch = SettingsPatch {
            last_profile_id: Some(id),
            ..SettingsPatch::default()
        };
        if let Err(e) = self.settings.set(&patch) {
            self.logger
                .warn("settings", &format!("Cannot save the selected profile: {e}"));
        }
    }

    /// Tray model from the current engine state, settings and profiles.
    pub(crate) fn tray_model(&self) -> TrayMenuModel {
        let state = self.engine.get_state();
        let s = self.settings.get();
        let selected = state.profile_id.clone().or(s.last_profile_id);
        build_model(&state, &self.profiles.list(), selected.as_deref(), s.language)
    }

    /// Schedules a tray rebuild (menu, tooltip, icon). Never blocks: the rebuild runs on the main
    /// thread, in scheduling order, from the state current at that time.
    pub(crate) fn refresh_tray(&self) {
        if let Some(refresh) = self.tray_refresh.get() {
            refresh();
        }
    }

    /// Quit: stop openconnect, close the log, then exit. Idempotent.
    pub(crate) fn begin_shutdown<R: Runtime>(&self, app: &AppHandle<R>) {
        if self.quitting.swap(true, Ordering::SeqCst) {
            return;
        }
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let st = app.state::<AppState>();
            st.engine.shutdown().await;
            st.logger.info("app", "Bye");
            st.logger.close();
            st.shutdown_done.store(true, Ordering::SeqCst);
            app.exit(0);
        });
    }
}

fn on_tray_action(app: &AppHandle, action: TrayAction) {
    let Some(st) = app.try_state::<AppState>() else {
        return;
    };
    match action {
        TrayAction::Connect(id) => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let st = app.state::<AppState>();
                if let Err(e) = st.connect(&id, ConnectOptions::default()) {
                    st.logger.error("tray", &format!("Connect failed: {e}"));
                }
            });
        }
        TrayAction::Disconnect => {
            let engine = st.engine.clone();
            tauri::async_runtime::spawn(async move { engine.disconnect().await });
        }
        TrayAction::SelectProfile(id) => {
            st.set_last_profile(Some(id));
            st.refresh_tray();
        }
        TrayAction::Show => show_main(app),
        TrayAction::Quit => st.begin_shutdown(app),
    }
}

fn on_settings_changed(app: &AppHandle, next: &Settings, prev: &Settings) {
    let Some(st) = app.try_state::<AppState>() else {
        return;
    };
    if next.theme != prev.theme
        && let Some(w) = app.get_webview_window(MAIN)
    {
        apply_theme_setting(&w, next.theme);
    }
    if next.launch_at_login != prev.launch_at_login {
        let autostart = app.autolaunch();
        let res = if next.launch_at_login {
            autostart.enable()
        } else {
            autostart.disable()
        };
        if let Err(e) = res {
            st.logger
                .error("settings", &format!("Failed to update launch at login: {e}"));
        }
    }
    if next.openconnect_path != prev.openconnect_path {
        let discovery = st.discovery.clone();
        tauri::async_runtime::spawn(async move {
            discovery.find(true).await;
        });
    }
    if next.language != prev.language {
        st.refresh_tray();
        // An existing error message follows the new language.
        st.engine.relocalize();
    }
}

/// Re-sends the prompts that wait for an answer (after the UI was (re)loaded).
pub(crate) fn emit_pending_prompts<R: Runtime>(app: &AppHandle<R>, prompts: &[AuthPrompt]) {
    for p in prompts {
        let _ = app.emit_to(MAIN, EV_VPN_PROMPT, p);
    }
}

/// Engine events and log lines → the main window only (`gp:vpn:state`, `gp:vpn:prompt`,
/// `gp:logs:line`); state changes also refresh the tray, prompts bring the window up.
pub(crate) fn forward_events<R: Runtime>(
    app: &AppHandle<R>,
    mut events: UnboundedReceiver<EngineEvent>,
    logger: &Logger,
) {
    let events_app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                EngineEvent::State(state) => {
                    let _ = events_app.emit_to(MAIN, EV_VPN_STATE, &state);
                    if let Some(st) = events_app.try_state::<AppState>() {
                        st.refresh_tray();
                    }
                }
                EngineEvent::Prompt(prompt) => {
                    show_main(&events_app);
                    let _ = events_app.emit_to(MAIN, EV_VPN_PROMPT, &prompt);
                }
            }
        }
    });
    let log_app = app.clone();
    logger.on_line(move |line| {
        let _ = log_app.emit_to(MAIN, EV_LOG_LINE, line);
    });
}

/// `setup` hook: builds the state, the main window and the tray.
pub(crate) fn setup(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    let paths = app.path();
    let data_dir = paths.app_data_dir()?;
    let logs_dir = paths.app_log_dir()?;
    let saml_data_root = paths.app_local_data_dir()?.join("saml");

    let logger = Arc::new(Logger::new(Some(&logs_dir), DEFAULT_CAPACITY));
    let webview = tauri::webview_version().unwrap_or_else(|_| "unknown".into());
    logger.info(
        "app",
        &format!(
            "GP Connect {} on {} {}, Tauri {}, webview {webview}",
            app.package_info().version,
            std::env::consts::OS,
            std::env::consts::ARCH,
            tauri::VERSION,
        ),
    );

    // ---- one-time import of the Electron version's settings and profiles
    let mut imported_settings = false;
    if let Ok(config_dir) = paths.config_dir()
        && let Some(out) = migrate_electron_data(&config_dir.join(ELECTRON_DIR_NAME), &data_dir)
    {
        imported_settings = out.copied.contains(&"settings.json");
        if !out.copied.is_empty() {
            logger.info(
                "app",
                &format!(
                    "Imported {} from the previous (Electron) version",
                    out.copied.join(", ")
                ),
            );
        }
        for w in &out.warnings {
            logger.warn("app", w);
        }
        if out.dropped_passwords > 0 {
            logger.warn(
                "app",
                &format!(
                    "{} saved password(s) of the previous version cannot be imported; enter them once again",
                    out.dropped_passwords
                ),
            );
        }
    }

    // ---- stores
    let secrets = Arc::new(KeyringSecretStore::new(warning_fn(&logger, "secrets")));
    let settings_warn = warning_fn(&logger, "settings");
    let settings = Arc::new(SettingsStore::open(
        data_dir.join("settings.json"),
        settings_warn.as_ref(),
    ));
    let profiles = Arc::new(ProfilesStore::open(
        data_dir.join("profiles.json"),
        secrets.clone(),
        warning_fn(&logger, "profiles"),
    ));
    let guard = Arc::new(ConfirmedSettingsGuard::open(
        data_dir.join("confirmed-settings.json"),
        secrets,
        settings_warn,
    ));
    let dialog: Arc<dyn ConfirmDialog> = Arc::new(TauriConfirmDialog::new(handle.clone()));
    if imported_settings {
        // The Electron login item was registered under the old app; follow the imported value.
        let enabled = settings.get().launch_at_login;
        let autostart = app.autolaunch();
        let res = if enabled {
            autostart.enable()
        } else {
            autostart.disable()
        };
        match res {
            Ok(()) => logger.info(
                "app",
                &format!("Launch at login set to {enabled} (imported setting)"),
            ),
            Err(e) => logger.warn(
                "app",
                &format!("Cannot apply the imported launch-at-login setting: {e}"),
            ),
        }
    }

    // ---- openconnect + engine
    let platform = Platform::current();
    let bundled_bin_dir = paths
        .resource_dir()
        .ok()
        // Tauri canonicalizes the exe path: `\\?\C:\…` on Windows. The trust check accepts it, but
        // the UI (`openconnectPath`) and the logs should show the plain path.
        .map(|d| strip_verbatim_prefix(&d.join("bin").to_string_lossy()));
    let discovery = Arc::new(Discovery::new(
        platform,
        settings.clone(),
        bundled_bin_dir,
        logger.clone(),
    ));
    let transport = ReqwestTransport::new()?;
    let saml_sessions = Arc::new(SamlSessions::default());
    let deps = EngineDeps::new(
        platform,
        choose_elevation(platform, gp_elevate::is_root()),
        Arc::new(StoreProfiles(profiles.clone())),
        Arc::new(StoreSettings(settings.clone())),
        Arc::new(HttpPreloginClient::new(Arc::new(transport), platform)),
        Arc::new(SamlWindowAuthenticator::new(
            handle.clone(),
            logger.clone(),
            saml_data_root.clone(),
            saml_sessions.clone(),
        )),
        Arc::new(AppOpenconnect {
            discovery: discovery.clone(),
            settings: settings.clone(),
            guard: guard.clone(),
            dialog: dialog.clone(),
            logger: logger.clone(),
            elevated_trust: trust_options(platform),
        }),
        gp_elevate::platform_spawner(platform, logger.clone(), helper_path()?),
        logger.clone(),
    );
    let engine = VpnEngine::new(deps);

    let state = AppState::new(
        logger.clone(),
        settings.clone(),
        profiles.clone(),
        guard,
        dialog,
        discovery.clone(),
        engine.clone(),
        logs_dir,
        saml_data_root,
        saml_sessions,
    );
    let quitting = state.quitting.clone();
    app.manage(state);

    // ---- main window
    let prompt_engine = engine.clone();
    let prompt_app = handle.clone();
    let window = create_main_window(&handle, move || {
        // A reloaded UI must still be able to answer an open prompt.
        emit_pending_prompts(&prompt_app, &prompt_engine.get_pending_prompts());
    })?;
    apply_theme_setting(&window, settings.get().theme);
    {
        let w = window.clone();
        let app = handle.clone();
        window.on_window_event(move |event| match event {
            WindowEvent::CloseRequested { api, .. } if !quitting.load(Ordering::SeqCst) => {
                // Tray app: closing the window only hides it.
                api.prevent_close();
                let _ = w.hide();
            }
            WindowEvent::ThemeChanged(theme) => {
                let dark = *theme == Theme::Dark;
                apply_backdrop(&w, dark);
                let _ = app.emit_to(MAIN, EV_THEME_CHANGED, dark);
            }
            _ => {}
        });
    }
    if !std::env::args().any(|a| a == HIDDEN_ARG) {
        window.show()?;
        window.set_focus()?;
    }

    // ---- tray: every update runs on the main thread, in order, from the latest state
    let st = app.state::<AppState>();
    match AppTray::create(&handle, &st.tray_model(), on_tray_action) {
        Ok(tray) => {
            let tray = Arc::new(tray);
            let tray_app = handle.clone();
            let _ = st.tray_refresh.set(Box::new(move || {
                let (app, tray) = (tray_app.clone(), tray.clone());
                let _ = tray_app.run_on_main_thread(move || {
                    let Some(st) = app.try_state::<AppState>() else {
                        return;
                    };
                    if let Err(e) = tray.update(&app, &st.tray_model()) {
                        st.logger.warn("tray", &format!("Cannot update the tray: {e}"));
                    }
                });
            }));
        }
        Err(e) => logger.error("tray", &format!("Cannot create the tray icon: {e}")),
    }

    // ---- engine / logger / settings → UI and tray
    forward_events(&handle, engine.subscribe(), &logger);
    let settings_app = handle.clone();
    settings.on_change(move |next, prev| on_settings_changed(&settings_app, next, prev));

    // ---- startup connect (or warm the discovery cache)
    let s = settings.get();
    let startup_profile = s
        .last_profile_id
        .filter(|id| s.connect_on_startup && profiles.get(id).is_some());
    let startup_app = handle.clone();
    tauri::async_runtime::spawn(async move {
        let st = startup_app.state::<AppState>();
        match startup_profile {
            Some(id) => {
                if let Err(e) = st.connect(&id, ConnectOptions::default()) {
                    st.logger.error("app", &format!("Connect on startup failed: {e}"));
                }
            }
            None => {
                st.discovery.find(false).await;
            }
        }
    });
    Ok(())
}

/// Run-loop events: quitting always goes through the engine shutdown first.
pub(crate) fn on_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        RunEvent::ExitRequested { api, .. } => {
            if let Some(st) = app.try_state::<AppState>()
                && !st.shutdown_done.load(Ordering::SeqCst)
            {
                api.prevent_exit();
                st.begin_shutdown(app);
            }
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => show_main(app),
        _ => {}
    }
}

/// IPC end-to-end tests: a child module so they can build a real `AppState` (private fields).
#[cfg(test)]
mod ipc_tests;
