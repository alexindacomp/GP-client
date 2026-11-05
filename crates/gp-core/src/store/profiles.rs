//! `profiles.json` + saved passwords in the OS keystore.
//!
//! The file lists the profiles and, per profile with a saved password, a marker (`"keyring"`);
//! the password itself lives only in the [`SecretStore`] under `profile-password:<id>`. A
//! password is used only while the marker is present, so a password that could not be replaced
//! (keystore unavailable) is never silently used later. Entries of the Electron version (base64
//! safeStorage blobs) cannot be decrypted and are dropped: the user enters the password once.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use serde_json::Value;

use super::json_file::{quarantine_file, read_json_file, write_json_file};
use super::secret_store::SecretStore;
use super::settings::WarningFn;
use super::validation::{ValidationError, validate_id, validate_profile_input};
use crate::types::{AuthMode, Profile, ProfileInput};

/// Value of a `passwords` entry whose password is stored in the OS keystore.
pub const PASSWORD_MARKER: &str = "keyring";

pub fn password_key(profile_id: &str) -> String {
    format!("profile-password:{profile_id}")
}

#[derive(Debug, Clone, Default, Serialize)]
struct ProfilesFile {
    version: u32,
    profiles: Vec<Profile>,
    passwords: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileStoreError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub struct ProfilesStore {
    file: PathBuf,
    secrets: Arc<dyn SecretStore>,
    on_warning: WarningFn,
    data: Mutex<ProfilesFile>,
}

impl ProfilesStore {
    pub fn open(file: impl Into<PathBuf>, secrets: Arc<dyn SecretStore>, on_warning: WarningFn) -> Self {
        let file = file.into();
        let data = load(&file, on_warning.as_ref());
        ProfilesStore {
            file,
            secrets,
            on_warning,
            data: Mutex::new(data),
        }
    }

    fn data(&self) -> MutexGuard<'_, ProfilesFile> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn list(&self) -> Vec<Profile> {
        self.data().profiles.clone()
    }

    pub fn get(&self, id: &str) -> Option<Profile> {
        self.data().profiles.iter().find(|p| p.id == id).cloned()
    }

    /// Creates (`input.id == None`) or updates a profile. The password is stored only when
    /// `save_password` is set and the keystore is available; turning `save_password` off (or
    /// switching to SAML) deletes a stored password. `password = None` keeps a stored one.
    pub fn save(&self, input: &ProfileInput, password: Option<&str>) -> Result<Profile, ProfileStoreError> {
        let mut data = self.data();
        let id = input
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let idx = data.profiles.iter().position(|p| p.id == id);
        if input.id.is_some() && idx.is_none() {
            return Err(ValidationError::new("Profile not found", Some("id"), Some("not_found")).into());
        }
        let profile = Profile {
            id: id.clone(),
            name: input.name.clone(),
            portal_url: input.portal_url.clone(),
            username: input.username.clone(),
            auth_mode: input.auth_mode,
            preferred_gateway: input.preferred_gateway.clone(),
            save_password: input.save_password,
        };

        let mut next = data.clone();
        let mut drop_secret = false;
        if !profile.save_password || profile.auth_mode == AuthMode::Saml {
            next.passwords.remove(&id);
            drop_secret = true;
        } else if let Some(pw) = password {
            if !self.secrets.available() {
                (self.on_warning)("OS secure storage is unavailable; the password was not saved");
                next.passwords.remove(&id);
                drop_secret = true;
            } else if let Err(e) = self.secrets.set(&password_key(&id), pw) {
                (self.on_warning)(&format!("Cannot save the password in OS secure storage: {e}"));
                next.passwords.remove(&id);
                drop_secret = true;
            } else {
                next.passwords.insert(id.clone(), PASSWORD_MARKER.into());
            }
        }
        match idx {
            Some(i) => next.profiles[i] = profile.clone(),
            None => next.profiles.push(profile.clone()),
        }
        write_json_file(&self.file, &next)?;
        *data = next;
        drop(data);
        if drop_secret {
            self.secrets.delete(&password_key(&id));
        }
        Ok(profile)
    }

    pub fn remove(&self, id: &str) -> std::io::Result<()> {
        let mut data = self.data();
        let mut next = data.clone();
        next.profiles.retain(|p| p.id != id);
        next.passwords.remove(id);
        write_json_file(&self.file, &next)?;
        *data = next;
        drop(data);
        self.secrets.delete(&password_key(id));
        Ok(())
    }

    pub fn has_saved_password(&self, id: &str) -> bool {
        self.data().passwords.contains_key(id)
    }

    /// The saved password; never exposed to the UI.
    pub fn get_password(&self, id: &str) -> Option<String> {
        if !self.has_saved_password(id) || !self.secrets.available() {
            return None;
        }
        let pw = self.secrets.get(&password_key(id));
        if pw.is_none() {
            (self.on_warning)(&format!(
                "Stored password for profile {id} cannot be read from OS secure storage"
            ));
        }
        pw
    }
}

fn load(file: &std::path::Path, warn: &(dyn Fn(&str) + Send + Sync)) -> ProfilesFile {
    let empty = ProfilesFile {
        version: 1,
        ..ProfilesFile::default()
    };
    let raw = match read_json_file(file) {
        Ok(v) => v,
        Err(e) => {
            let moved = quarantine_file(file)
                .map(|m| format!("; moved to {}", m.display()))
                .unwrap_or_default();
            warn(&format!("profiles.json is unreadable ({e}){moved}"));
            return empty;
        }
    };
    let Some(Value::Object(obj)) = raw else {
        return empty;
    };
    let mut profiles: Vec<Profile> = Vec::new();
    for p in obj
        .get("profiles")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let parsed = validate_profile_input(p).and_then(|v| {
            let id = validate_id(p.get("id").unwrap_or(&Value::Null))?;
            Ok(Profile {
                id,
                name: v.name,
                portal_url: v.portal_url,
                username: v.username,
                auth_mode: v.auth_mode,
                preferred_gateway: v.preferred_gateway,
                save_password: v.save_password,
            })
        });
        match parsed {
            Ok(profile) => profiles.push(profile),
            Err(e) => warn(&format!("Skipping invalid profile in profiles.json: {e}")),
        }
    }
    let mut passwords = BTreeMap::new();
    if let Some(Value::Object(pw)) = obj.get("passwords") {
        for (id, v) in pw {
            if !profiles.iter().any(|p| &p.id == id) {
                continue;
            }
            match v.as_str() {
                Some(PASSWORD_MARKER) => {
                    passwords.insert(id.clone(), PASSWORD_MARKER.to_string());
                }
                Some(_) => warn(&format!(
                    "Saved password for profile {id} is from an older version and cannot be used; enter it again"
                )),
                None => {}
            }
        }
    }
    ProfilesFile {
        version: 1,
        profiles,
        passwords,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::secret_store::MemorySecretStore;
    use std::fs;

    const ID_A: &str = "11111111-1111-4111-8111-111111111111";
    const ID_B: &str = "22222222-2222-4222-8222-222222222222";

    fn input() -> ProfileInput {
        ProfileInput {
            id: None,
            name: "Work".into(),
            portal_url: "https://vpn.example.com".into(),
            username: Some("alice".into()),
            auth_mode: AuthMode::Password,
            preferred_gateway: None,
            save_password: true,
        }
    }

    struct Env {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        file: PathBuf,
        secrets: Arc<MemorySecretStore>,
        warnings: Arc<Mutex<Vec<String>>>,
    }

    fn env() -> Env {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_path_buf();
        Env {
            file: dir.join("profiles.json"),
            dir,
            _dir: d,
            secrets: Arc::new(MemorySecretStore::new()),
            warnings: Arc::new(Mutex::new(vec![])),
        }
    }

    impl Env {
        fn open(&self) -> ProfilesStore {
            let w = self.warnings.clone();
            ProfilesStore::open(
                &self.file,
                self.secrets.clone(),
                Arc::new(move |m| w.lock().unwrap().push(m.into())),
            )
        }
        fn on_disk(&self) -> Value {
            serde_json::from_str(&fs::read_to_string(&self.file).unwrap()).unwrap()
        }
        fn raw(&self) -> String {
            fs::read_to_string(&self.file).unwrap()
        }
        fn warnings(&self) -> Vec<String> {
            self.warnings.lock().unwrap().clone()
        }
    }

    #[test]
    fn starts_empty_and_persists_created_profiles() {
        let e = env();
        let store = e.open();
        assert!(store.list().is_empty());
        let saved = store.save(&input(), Some("S3cret!")).unwrap();
        assert_eq!(saved.id.len(), 36);
        assert!(uuid::Uuid::parse_str(&saved.id).is_ok());
        assert_eq!(e.open().list(), std::slice::from_ref(&saved));
        assert_eq!(e.open().get_password(&saved.id).as_deref(), Some("S3cret!"));
    }

    #[test]
    fn updates_in_place_and_refuses_unknown_ids() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), None).unwrap();
        store
            .save(
                &ProfileInput {
                    id: Some(a.id.clone()),
                    name: "Renamed".into(),
                    username: None,
                    ..input()
                },
                None,
            )
            .unwrap();
        let listed = e.open().list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].name.as_str(), listed[0].username.as_deref()),
            ("Renamed", None)
        );
        let on_disk = &e.on_disk()["profiles"][0];
        assert!(on_disk.get("username").is_none());

        let err = store
            .save(
                &ProfileInput {
                    id: Some(ID_B.into()),
                    ..input()
                },
                None,
            )
            .unwrap_err();
        assert_eq!(err.to_string(), "[field:id][code:not_found] Profile not found");
        assert_eq!(e.open().list().len(), 1);
    }

    #[test]
    fn remove_deletes_the_profile_and_its_password() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), Some("S3cret!")).unwrap();
        let b = store
            .save(
                &ProfileInput {
                    name: "Other".into(),
                    ..input()
                },
                Some("Other-pw"),
            )
            .unwrap();
        store.remove(&a.id).unwrap();
        let reopened = e.open();
        assert_eq!(
            reopened.list().iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
            std::slice::from_ref(&b.id)
        );
        assert_eq!(reopened.get_password(&a.id), None);
        assert!(!e.secrets.snapshot().contains_key(&password_key(&a.id)));
        let keys: Vec<String> = e.on_disk()["passwords"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, [b.id]);
    }

    #[test]
    fn list_and_get_return_copies() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), None).unwrap();
        store.list()[0].name = "hacked".into();
        store.get(&a.id).unwrap().portal_url = "https://evil.example.com".into();
        let p = store.get(&a.id).unwrap();
        assert_eq!(
            (p.name.as_str(), p.portal_url.as_str()),
            ("Work", "https://vpn.example.com")
        );
    }

    #[test]
    fn the_password_never_reaches_the_file() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), Some("S3cret!")).unwrap();
        assert!(!e.raw().contains("S3cret!"));
        assert_eq!(e.on_disk()["passwords"][&a.id], PASSWORD_MARKER);
        assert_eq!(
            e.secrets.snapshot().get(&password_key(&a.id)).map(String::as_str),
            Some("S3cret!")
        );
        assert!(store.has_saved_password(&a.id));
    }

    #[test]
    fn editing_without_a_new_password_keeps_the_stored_one() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), Some("S3cret!")).unwrap();
        store
            .save(
                &ProfileInput {
                    id: Some(a.id.clone()),
                    name: "Renamed".into(),
                    ..input()
                },
                None,
            )
            .unwrap();
        assert_eq!(e.open().get_password(&a.id).as_deref(), Some("S3cret!"));
    }

    #[test]
    fn turning_save_password_off_or_switching_to_saml_deletes_it() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), Some("S3cret!")).unwrap();
        store
            .save(
                &ProfileInput {
                    id: Some(a.id.clone()),
                    save_password: false,
                    ..input()
                },
                None,
            )
            .unwrap();
        assert_eq!(store.get_password(&a.id), None);
        assert_eq!(e.on_disk()["passwords"], serde_json::json!({}));
        assert!(e.secrets.snapshot().is_empty());

        let s = store
            .save(
                &ProfileInput {
                    auth_mode: AuthMode::Saml,
                    ..input()
                },
                Some("S3cret!"),
            )
            .unwrap();
        assert!(!store.has_saved_password(&s.id));
        assert!(e.secrets.snapshot().is_empty());
    }

    #[test]
    fn keystore_unavailable_keeps_save_password_but_stores_nothing_and_warns() {
        let e = env();
        e.secrets.set_available(false);
        let store = e.open();
        let a = store.save(&input(), Some("S3cret!")).unwrap();
        assert!(a.save_password);
        assert!(!store.has_saved_password(&a.id));
        assert_eq!(store.get_password(&a.id), None);
        assert!(!e.raw().contains("S3cret!"));
        assert_eq!(
            e.warnings(),
            ["OS secure storage is unavailable; the password was not saved"]
        );
    }

    #[test]
    fn a_new_password_while_the_keystore_is_unavailable_drops_the_old_one() {
        let e = env();
        let store = e.open();
        let a = store.save(&input(), Some("Old-pass")).unwrap();
        e.secrets.set_available(false);
        store
            .save(
                &ProfileInput {
                    id: Some(a.id.clone()),
                    ..input()
                },
                Some("New-pass"),
            )
            .unwrap();
        e.secrets.set_available(true);
        // the old value may still sit in the keystore, but it is never used
        assert_eq!(store.get_password(&a.id), None);
        assert_eq!(e.open().get_password(&a.id), None);
    }

    #[test]
    fn does_not_read_while_the_keystore_is_unavailable() {
        let e = env();
        let a = e.open().save(&input(), Some("S3cret!")).unwrap();
        e.secrets.set_available(false);
        assert_eq!(e.open().get_password(&a.id), None);
        e.secrets.set_available(true);
        assert_eq!(e.open().get_password(&a.id).as_deref(), Some("S3cret!"));
    }

    #[test]
    fn a_missing_keystore_entry_yields_no_password_and_a_warning() {
        let e = env();
        let a = e.open().save(&input(), Some("S3cret!")).unwrap();
        e.secrets.delete(&password_key(&a.id));
        assert_eq!(e.open().get_password(&a.id), None);
        assert!(
            e.warnings()
                .join("\n")
                .contains("cannot be read from OS secure storage")
        );
    }

    #[test]
    fn unparseable_json_is_moved_aside_and_a_fresh_file_is_written_later() {
        let e = env();
        fs::write(&e.file, "{\"version\":1,\"profiles\":[{").unwrap();
        let store = e.open();
        assert!(store.list().is_empty());
        let names: Vec<String> = fs::read_dir(&e.dir)
            .unwrap()
            .map(|x| x.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].starts_with("profiles.json.corrupt-"));
        assert_eq!(
            fs::read_to_string(e.dir.join(&names[0])).unwrap(),
            "{\"version\":1,\"profiles\":[{"
        );
        let w = e.warnings();
        assert!(w[0].starts_with("profiles.json is unreadable (") && w[0].contains("; moved to "));
        store.save(&input(), None).unwrap();
        assert_eq!(e.open().list().len(), 1);
    }

    #[test]
    fn wrong_shaped_json_yields_no_profiles() {
        for raw in ["null", "\"text\"", "42", "[]"] {
            let e = env();
            fs::write(&e.file, raw).unwrap();
            assert!(e.open().list().is_empty(), "{raw}");
        }
    }

    #[test]
    fn drops_invalid_profiles_individually_and_normalises_valid_ones() {
        let e = env();
        let data = serde_json::json!({
            "version": 1,
            "profiles": [
                {"id": ID_A, "name": " Good ", "portalUrl": "VPN.example.com/global-protect", "authMode": "auto", "savePassword": false},
                {"id": ID_B, "name": "Http", "portalUrl": "http://vpn.example.com", "authMode": "auto", "savePassword": false},
                {"id": "../../x", "name": "BadId", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false},
                {"name": "NoId", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false},
                {"id": ID_B, "name": "Extra", "portalUrl": "vpn.example.com", "authMode": "auto", "savePassword": false, "cmd": "x"},
                "not an object"
            ],
            "passwords": {}
        });
        fs::write(&e.file, data.to_string()).unwrap();
        let list = e.open().list();
        assert_eq!(list.len(), 1);
        assert_eq!(
            (
                list[0].id.as_str(),
                list[0].name.as_str(),
                list[0].portal_url.as_str()
            ),
            (ID_A, "Good", "https://vpn.example.com")
        );
        let w = e.warnings();
        assert_eq!(w.len(), 5);
        assert!(
            w.iter()
                .all(|x| x.starts_with("Skipping invalid profile in profiles.json"))
        );
    }

    #[test]
    fn ignores_passwords_of_unknown_profiles_non_strings_and_old_electron_blobs() {
        let e = env();
        let data = serde_json::json!({
            "version": 1,
            "profiles": [
                {"id": ID_A, "name": "A", "portalUrl": "vpn.example.com", "authMode": "password", "savePassword": true},
                {"id": "33333333-3333-4333-8333-333333333333", "name": "C", "portalUrl": "vpn.example.com", "authMode": "password", "savePassword": true}
            ],
            "passwords": {ID_B: PASSWORD_MARKER, ID_A: {"x": 1}, "33333333-3333-4333-8333-333333333333": "djEwAAAA"}
        });
        fs::write(&e.file, data.to_string()).unwrap();
        let store = e.open();
        assert!(!store.has_saved_password(ID_A));
        assert!(!store.has_saved_password(ID_B));
        assert!(!store.has_saved_password("33333333-3333-4333-8333-333333333333"));
        assert!(e.warnings().iter().any(|w| w.contains("older version")));
        store
            .save(
                &ProfileInput {
                    id: Some(ID_A.into()),
                    ..input()
                },
                None,
            )
            .unwrap();
        assert_eq!(e.on_disk()["passwords"], serde_json::json!({}));
    }
}
