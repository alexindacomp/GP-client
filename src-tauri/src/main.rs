//! GP Connect — Tauri 2 application: commands/events mapped 1:1 to `GpApi` (src/shared/ipc.ts),
//! main window, SAML window, tray and plugins. See docs/ARCHITECTURE-TAURI.md, "App shell".

// No console window for release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod commands;
mod dialog;
mod discovery;
mod migration;
mod saml;
mod secrets;
mod tray;
mod window;

fn main() {
    let app = tauri::Builder::default()
        // Must be first: a second launch only shows the running instance's window.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            window::show_main(app);
        }))
        // Start at login in the tray (`--hidden`); macOS uses the default LaunchAgent launcher.
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .app_name("GP Connect")
                .args([window::HIDDEN_ARG])
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::profiles_list,
            commands::profiles_save,
            commands::profiles_remove,
            commands::vpn_connect,
            commands::vpn_disconnect,
            commands::vpn_get_state,
            commands::vpn_answer_prompt,
            commands::vpn_get_pending_prompts,
            commands::logs_get,
            commands::logs_open_folder,
            commands::settings_get,
            commands::settings_set,
            commands::system_info,
            commands::system_open_external,
        ])
        .setup(app_state::setup)
        .build(tauri::generate_context!());
    match app {
        Ok(app) => app.run(app_state::on_run_event),
        Err(e) => {
            // Nothing else can report it: the logger lives in the app state that failed to build.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("GP Connect failed to start: {e}");
            }
            std::process::exit(1);
        }
    }
}
