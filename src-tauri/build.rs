//! Declares the app commands so that they need an explicit permission: only the main window's
//! capability (capabilities/main.json) grants them; the SAML window gets none.

/// Must match `tauri::generate_handler![…]` in src/main.rs.
const COMMANDS: &[&str] = &[
    "profiles_list",
    "profiles_save",
    "profiles_remove",
    "vpn_connect",
    "vpn_disconnect",
    "vpn_get_state",
    "vpn_answer_prompt",
    "vpn_get_pending_prompts",
    "logs_get",
    "logs_open_folder",
    "settings_get",
    "settings_set",
    "system_info",
    "system_open_external",
];

/// Sidecar staged by scripts/prepare-helper.mjs (bundle.externalBin in tauri.windows.conf.json).
const WINDOWS_HELPER: &str = "binaries/gp-connect-helper-x86_64-pc-windows-msvc.exe";

/// Bundled OpenConnect staged by scripts/fetch-openconnect-win.mjs (bundle.resources in
/// tauri.windows.conf.json).
const WINDOWS_OPENCONNECT_DIR: &str = "resources/bin/win32";

fn main() {
    println!("cargo:rerun-if-changed={WINDOWS_HELPER}");
    println!("cargo:rerun-if-changed={WINDOWS_OPENCONNECT_DIR}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        assert!(
            std::path::Path::new(WINDOWS_HELPER).is_file(),
            "{WINDOWS_HELPER} is missing: run `npm run prepare:helper` first (builds gp-helper)"
        );
        let oc_dir = std::path::Path::new(WINDOWS_OPENCONNECT_DIR);
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            // A release installer without OpenConnect could never connect.
            assert!(
                oc_dir.join("openconnect.exe").is_file(),
                "{WINDOWS_OPENCONNECT_DIR}/openconnect.exe is missing: run `npm run fetch:openconnect:win` first"
            );
        } else if !oc_dir.is_dir() {
            // Debug/CI builds without the download: an empty resource dir (the app then looks for
            // a system-wide OpenConnect, as on the other platforms).
            std::fs::create_dir_all(oc_dir).expect("create the OpenConnect resource dir");
            std::fs::write(
                oc_dir.join("README.txt"),
                "Populated by `npm run fetch:openconnect:win` (official OpenConnect build).\n",
            )
            .expect("write the OpenConnect resource placeholder");
        }
    }
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri-build failed");
}
