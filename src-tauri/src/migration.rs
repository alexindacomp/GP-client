//! One-time import of the previous (Electron-based) version's settings and profiles.
//!
//! If the Electron profile directory exists and the Tauri data directory has no `settings.json`
//! yet, `settings.json` and `profiles.json` are copied (re-written atomically with 0600 by
//! `write_json_file`; files that already exist in the new location are never overwritten).
//! Passwords saved by Electron's safeStorage cannot be decrypted here: the profiles store drops
//! those entries and the user enters the password once again. `confirmed-settings.json` is not
//! copied either (its key was in safeStorage), so non-default elevation settings are confirmed
//! once more before the first elevated start.

use std::path::Path;

use gp_core::store::json_file::{read_json_file, write_json_file};
use gp_core::store::profiles::PASSWORD_MARKER;
use serde_json::Value;

/// Directory name of the Electron app's `userData` inside the OS config dir
/// (`%APPDATA%`, `~/Library/Application Support`, `$XDG_CONFIG_HOME`).
pub(crate) const ELECTRON_DIR_NAME: &str = "GP Connect";

const FILES: [&str; 2] = ["settings.json", "profiles.json"];

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MigrationOutcome {
    /// File names that were copied.
    pub(crate) copied: Vec<&'static str>,
    /// Problems (unreadable source, write error); the app continues with defaults.
    pub(crate) warnings: Vec<String>,
    /// Saved passwords of the Electron version that cannot be carried over.
    pub(crate) dropped_passwords: usize,
}

/// Copies the Electron data into `data_dir` when appropriate; `None` when there was nothing to do.
pub(crate) fn migrate_electron_data(legacy_dir: &Path, data_dir: &Path) -> Option<MigrationOutcome> {
    if !legacy_dir.is_dir() || data_dir.join("settings.json").exists() {
        return None;
    }
    let mut out = MigrationOutcome::default();
    for name in FILES {
        let (src, dest) = (legacy_dir.join(name), data_dir.join(name));
        if !src.is_file() || dest.exists() {
            continue;
        }
        let value = match read_json_file(&src) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => {
                out.warnings
                    .push(format!("Cannot read {name} of the previous version: {e}"));
                continue;
            }
        };
        if name == "profiles.json" {
            out.dropped_passwords = legacy_password_count(&value);
        }
        match write_json_file(&dest, &value) {
            Ok(()) => out.copied.push(name),
            Err(e) => out
                .warnings
                .push(format!("Cannot copy {name} of the previous version: {e}")),
        }
    }
    (!out.copied.is_empty() || !out.warnings.is_empty()).then_some(out)
}

/// Entries of `passwords` that hold an Electron safeStorage blob (not the keystore marker) and
/// belong to a profile that exists: the user is told how many passwords to re-enter.
fn legacy_password_count(profiles_file: &Value) -> usize {
    let ids: Vec<&str> = profiles_file
        .get("profiles")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| p.get("id")?.as_str()).collect())
        .unwrap_or_default();
    profiles_file
        .get("passwords")
        .and_then(Value::as_object)
        .map_or(0, |m| {
            m.iter()
                .filter(|(id, v)| {
                    ids.contains(&id.as_str())
                        && v.as_str().is_some_and(|s| !s.is_empty() && s != PASSWORD_MARKER)
                })
                .count()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn write(dir: &Path, name: &str, v: &Value) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), serde_json::to_string(v).unwrap()).unwrap();
    }

    fn read(dir: &Path, name: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap()).unwrap()
    }

    #[test]
    fn copies_settings_and_profiles_on_first_start_and_counts_legacy_passwords() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        let settings = json!({ "theme": "dark", "language": "en" });
        let profiles = json!({
            "version": 1,
            "profiles": [{ "id": "a" }, { "id": "b" }, { "id": "c" }],
            "passwords": { "a": "djEwAAAA", "b": "keyring", "c": "" }
        });
        write(&legacy, "settings.json", &settings);
        write(&legacy, "profiles.json", &profiles);
        write(&legacy, "confirmed-settings.json", &json!({ "version": 1 }));

        let out = migrate_electron_data(&legacy, &data).unwrap();
        assert_eq!(out.copied, vec!["settings.json", "profiles.json"]);
        assert!(out.warnings.is_empty());
        assert_eq!(out.dropped_passwords, 1);
        assert_eq!(read(&data, "settings.json"), settings);
        assert_eq!(read(&data, "profiles.json"), profiles);
        assert!(!data.join("confirmed-settings.json").exists());
    }

    #[test]
    fn does_nothing_without_legacy_dir_or_when_settings_already_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        assert_eq!(migrate_electron_data(&legacy, &data), None);

        write(&legacy, "settings.json", &json!({ "theme": "dark" }));
        write(&data, "settings.json", &json!({ "theme": "light" }));
        assert_eq!(migrate_electron_data(&legacy, &data), None);
        assert_eq!(read(&data, "settings.json"), json!({ "theme": "light" }));
    }

    #[test]
    fn never_overwrites_an_existing_profiles_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        write(&legacy, "settings.json", &json!({ "theme": "dark" }));
        write(&legacy, "profiles.json", &json!({ "profiles": ["old"] }));
        write(&data, "profiles.json", &json!({ "profiles": ["new"] }));

        let out = migrate_electron_data(&legacy, &data).unwrap();
        assert_eq!(out.copied, vec!["settings.json"]);
        assert_eq!(read(&data, "profiles.json"), json!({ "profiles": ["new"] }));
    }

    /// The imported files open in the real stores: settings and profiles survive, the Electron
    /// safeStorage passwords are dropped (and never reach the keystore), and a second start
    /// imports nothing even though the Electron directory is still there.
    #[test]
    fn imported_data_opens_in_the_stores_without_electron_passwords_and_is_imported_once() {
        use gp_core::store::profiles::ProfilesStore;
        use gp_core::store::secret_store::MemorySecretStore;
        use gp_core::store::settings::SettingsStore;
        use gp_core::types::{Language, Theme};
        use std::sync::{Arc, Mutex};

        const A: &str = "11111111-2222-4333-8444-555555555555";
        const B: &str = "22222222-3333-4444-8555-666666666666";
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        write(
            &legacy,
            "settings.json",
            &json!({ "theme": "dark", "language": "en", "autoReconnect": false, "lastProfileId": A }),
        );
        let profile = |id: &str, name: &str| {
            json!({ "id": id, "name": name, "portalUrl": "https://vpn.example.com", "authMode": "password",
                    "username": "alice", "savePassword": true })
        };
        write(
            &legacy,
            "profiles.json",
            &json!({
                "version": 1,
                "profiles": [profile(A, "Office"), profile(B, "Lab")],
                "passwords": { A: "djEwAAAAsafeStorageBlobA", B: "djEwAAAAsafeStorageBlobB" }
            }),
        );

        let out = migrate_electron_data(&legacy, &data).unwrap();
        assert_eq!(out.dropped_passwords, 2);

        let settings = SettingsStore::open(data.join("settings.json"), &|_: &str| {});
        let s = settings.get();
        assert_eq!(
            (
                s.theme,
                s.language,
                s.auto_reconnect,
                s.last_profile_id.as_deref()
            ),
            (Theme::Dark, Language::En, false, Some(A))
        );

        let warnings = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = warnings.clone();
        let secrets = Arc::new(MemorySecretStore::new());
        let profiles = ProfilesStore::open(
            data.join("profiles.json"),
            secrets.clone(),
            Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string())),
        );
        let names: Vec<String> = profiles.list().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["Office", "Lab"]);
        for id in [A, B] {
            assert!(!profiles.has_saved_password(id), "{id}");
            assert_eq!(profiles.get_password(id), None, "{id}");
        }
        assert!(
            secrets.snapshot().is_empty(),
            "an Electron blob reached the keystore"
        );
        let older = warnings
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.contains("older version"))
            .count();
        assert_eq!(older, 2, "{:?}", warnings.lock().unwrap());

        // Next start: the Electron directory still exists (even changed) but nothing is re-imported.
        write(&legacy, "settings.json", &json!({ "theme": "light" }));
        assert_eq!(migrate_electron_data(&legacy, &data), None);
        assert_eq!(read(&data, "settings.json")["theme"], "dark");
    }

    /// The warning tells the user how many passwords to re-enter: entries of profiles that no
    /// longer exist (the profiles store ignores them) must not be counted.
    #[test]
    fn counts_only_passwords_of_imported_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        write(&legacy, "settings.json", &json!({ "theme": "dark" }));
        write(
            &legacy,
            "profiles.json",
            &json!({
                "version": 1,
                "profiles": [{ "id": "11111111-2222-4333-8444-555555555555", "name": "A",
                               "portalUrl": "https://vpn.example.com", "authMode": "password", "savePassword": true }],
                "passwords": {
                    "11111111-2222-4333-8444-555555555555": "djEwAAAAblobA",
                    "99999999-2222-4333-8444-555555555555": "djEwAAAAorphan"
                }
            }),
        );
        let out = migrate_electron_data(&legacy, &data).unwrap();
        assert_eq!(out.dropped_passwords, 1);
    }

    #[test]
    fn reports_unreadable_files_and_continues() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, data) = (tmp.path().join("GP Connect"), tmp.path().join("new"));
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("settings.json"), "{ not json").unwrap();
        write(&legacy, "profiles.json", &json!({ "profiles": [] }));

        let out = migrate_electron_data(&legacy, &data).unwrap();
        assert_eq!(out.copied, vec!["profiles.json"]);
        assert_eq!(out.warnings.len(), 1);
        assert!(!data.join("settings.json").exists());
    }
}
