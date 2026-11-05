//! `settings.json`. Invalid values on disk are dropped
//! field by field; an unreadable file is moved aside and the defaults are used.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::{Map, Value};

use super::json_file::{quarantine_file, read_json_file, write_json_file};
use super::validation::{SettingsPatch, validate_settings_patch};
use crate::types::Settings;

pub type WarningFn = Arc<dyn Fn(&str) + Send + Sync>;
type SettingsListener = Arc<dyn Fn(&Settings, &Settings) + Send + Sync>;

pub struct SettingsStore {
    file: PathBuf,
    settings: Mutex<Settings>,
    listeners: Mutex<Vec<(u64, SettingsListener)>>,
    next_id: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Handle returned by [`SettingsStore::on_change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsListenerId(u64);

impl SettingsStore {
    pub fn open(file: impl Into<PathBuf>, on_warning: &(dyn Fn(&str) + Send + Sync)) -> Self {
        let file = file.into();
        let settings = load(&file, on_warning);
        SettingsStore {
            file,
            settings: Mutex::new(settings),
            listeners: Mutex::new(vec![]),
            next_id: Mutex::new(0),
        }
    }

    pub fn get(&self) -> Settings {
        lock(&self.settings).clone()
    }

    /// Applies an already validated patch, persists it, then notifies listeners with
    /// `(next, previous)`. On a write error nothing changes in memory.
    pub fn set(&self, patch: &SettingsPatch) -> std::io::Result<Settings> {
        let (prev, next) = {
            let mut cur = lock(&self.settings);
            let prev = cur.clone();
            let mut next = prev.clone();
            patch.apply_to(&mut next);
            write_json_file(&self.file, &next)?;
            cur.clone_from(&next);
            (prev, next)
        };
        let listeners: Vec<SettingsListener> = lock(&self.listeners).iter().map(|(_, l)| l.clone()).collect();
        for l in listeners {
            l(&next, &prev);
        }
        Ok(next)
    }

    pub fn on_change(&self, l: impl Fn(&Settings, &Settings) + Send + Sync + 'static) -> SettingsListenerId {
        let mut n = lock(&self.next_id);
        *n += 1;
        lock(&self.listeners).push((*n, Arc::new(l)));
        SettingsListenerId(*n)
    }

    pub fn off_change(&self, id: SettingsListenerId) {
        lock(&self.listeners).retain(|(n, _)| *n != id.0);
    }
}

fn load(file: &std::path::Path, warn: &(dyn Fn(&str) + Send + Sync)) -> Settings {
    let raw = match read_json_file(file) {
        Ok(v) => v,
        Err(e) => {
            let moved = quarantine_file(file);
            let kept = moved
                .map(|m| format!(", old file kept at {}", m.display()))
                .unwrap_or_default();
            warn(&format!(
                "settings.json is unreadable ({e}); using defaults{kept}"
            ));
            return Settings::default();
        }
    };
    let mut result = Settings::default();
    let Some(Value::Object(obj)) = raw else {
        return result;
    };
    for (k, v) in obj {
        let mut single = Map::new();
        single.insert(k.clone(), v);
        match validate_settings_patch(&Value::Object(single)) {
            Ok(p) => p.apply_to(&mut result),
            Err(e) => warn(&format!("Ignoring invalid setting \"{k}\": {e}")),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Language, Theme};
    use serde_json::json;
    use std::fs;

    struct Env {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        file: PathBuf,
        warnings: Arc<Mutex<Vec<String>>>,
    }

    fn env() -> Env {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_path_buf();
        Env {
            file: dir.join("settings.json"),
            dir,
            _dir: d,
            warnings: Arc::new(Mutex::new(vec![])),
        }
    }

    impl Env {
        fn open(&self) -> SettingsStore {
            let w = self.warnings.clone();
            SettingsStore::open(&self.file, &move |m: &str| w.lock().unwrap().push(m.to_string()))
        }
        fn write(&self, data: &str) {
            fs::write(&self.file, data).unwrap();
        }
        fn warnings(&self) -> Vec<String> {
            self.warnings.lock().unwrap().clone()
        }
    }

    #[allow(clippy::needless_pass_by_value)] // keeps the call sites as short as the TS ones
    fn patch(v: Value) -> SettingsPatch {
        validate_settings_patch(&v).unwrap()
    }

    #[test]
    fn defaults_without_a_file_and_persists_changes() {
        let e = env();
        let store = e.open();
        assert_eq!(store.get(), Settings::default());
        store
            .set(&patch(
                json!({"theme": "dark", "language": "en", "extraArgs": ["-v"]}),
            ))
            .unwrap();
        let expected = Settings {
            theme: Theme::Dark,
            language: Language::En,
            extra_args: vec!["-v".into()],
            ..Settings::default()
        };
        assert_eq!(e.open().get(), expected);
        assert!(e.warnings().is_empty());
    }

    #[test]
    fn a_cleared_optional_setting_is_removed_from_the_file() {
        let e = env();
        let store = e.open();
        store
            .set(&patch(json!({"openconnectPath": "/usr/sbin/openconnect"})))
            .unwrap();
        store.set(&patch(json!({"openconnectPath": null}))).unwrap();
        assert_eq!(e.open().get().openconnect_path, None);
        let on_disk: Value = serde_json::from_str(&fs::read_to_string(&e.file).unwrap()).unwrap();
        assert!(on_disk.get("openconnectPath").is_none());
    }

    #[test]
    fn notifies_listeners_with_next_and_previous_until_unsubscribed() {
        let e = env();
        let store = e.open();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let id = store.on_change(move |next, prev| s.lock().unwrap().push((next.theme, prev.theme)));
        store.set(&patch(json!({"theme": "light"}))).unwrap();
        store.off_change(id);
        store.set(&patch(json!({"theme": "dark"}))).unwrap();
        assert_eq!(*seen.lock().unwrap(), [(Theme::Light, Theme::System)]);
    }

    #[test]
    fn get_returns_a_copy() {
        let e = env();
        let store = e.open();
        let mut s = store.get();
        s.extra_args.push("--script=/tmp/evil".into());
        assert_eq!(store.get(), Settings::default());
    }

    #[test]
    fn a_failed_write_does_not_change_memory() {
        let e = env();
        let store = e.open();
        fs::create_dir(&e.file).unwrap();
        fs::write(e.file.join("x"), "x").unwrap();
        assert!(store.set(&patch(json!({"theme": "dark"}))).is_err());
        assert_eq!(store.get().theme, Theme::System);
    }

    #[test]
    fn unparseable_json_is_moved_aside_with_a_warning() {
        let e = env();
        e.write("{\"theme\": \"dark\",");
        assert_eq!(e.open().get(), Settings::default());
        let names: Vec<String> = fs::read_dir(&e.dir)
            .unwrap()
            .map(|x| x.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].starts_with("settings.json.corrupt-"));
        let w = e.warnings();
        assert!(
            w[0].starts_with("settings.json is unreadable (")
                && w[0].contains("using defaults, old file kept at")
        );
    }

    #[test]
    fn non_object_json_yields_the_defaults() {
        for raw in ["[]", "null", "\"dark\""] {
            let e = env();
            e.write(raw);
            assert_eq!(e.open().get(), Settings::default());
        }
    }

    #[test]
    fn drops_each_invalid_field_and_keeps_the_valid_ones() {
        let e = env();
        e.write(
            &json!({
                "theme": "dark",
                "language": "de",
                "autoReconnect": "yes",
                "openconnectPath": "/bin/sh",
                "hipScriptPath": "relative/hip.sh",
                "extraArgs": ["-v", "--script=/tmp/evil.sh"],
                "lastProfileId": "not-a-uuid",
                "connectOnStartup": true,
                "injected": "x",
                "__proto__": {"autoReconnect": false}
            })
            .to_string(),
        );
        let s = e.open().get();
        assert_eq!(
            s,
            Settings {
                theme: Theme::Dark,
                connect_on_startup: true,
                ..Settings::default()
            }
        );
        let w = e.warnings().join("\n");
        assert_eq!(e.warnings().len(), 8);
        for k in ["openconnectPath", "extraArgs", "injected", "__proto__"] {
            assert!(w.contains(&format!("Ignoring invalid setting \"{k}\"")), "{k}");
        }
    }

    #[test]
    fn keeps_valid_disk_values_for_elevation_settings() {
        let e = env();
        e.write(r#"{"openconnectPath": "/opt/oc/bin/openconnect", "extraArgs": ["--no-dtls"], "hipScriptPath": "/opt/hip.sh"}"#);
        let s = e.open().get();
        assert_eq!(s.openconnect_path.as_deref(), Some("/opt/oc/bin/openconnect"));
        assert_eq!(s.extra_args, ["--no-dtls"]);
        assert_eq!(s.hip_script_path.as_deref(), Some("/opt/hip.sh"));
    }
}
