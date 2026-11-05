//! [`SecretStore`] on the OS keystore via the `keyring` crate: Windows Credential Manager, macOS
//! Keychain, Linux Secret Service. Holds saved profile passwords and the confirmed-settings HMAC
//! key. When no usable backend exists (e.g. Linux without a Secret Service), `available()` is
//! false and the stores keep working without persisting secrets.

use std::sync::OnceLock;

use gp_core::store::secret_store::{SecretStore, SecretStoreError};
use gp_core::store::settings::WarningFn;
use keyring::{Entry, Error};

/// Keystore service name of every entry (the key is the entry's user name).
const SERVICE: &str = "com.gpconnect.client";
/// Read once to find out whether the backend actually answers (never written).
const PROBE_KEY: &str = "availability-probe";

pub(crate) struct KeyringSecretStore {
    available: OnceLock<bool>,
    on_warning: WarningFn,
}

impl KeyringSecretStore {
    pub(crate) fn new(on_warning: WarningFn) -> Self {
        KeyringSecretStore {
            available: OnceLock::new(),
            on_warning,
        }
    }

    fn probe(&self) -> bool {
        if let Err(e) = Entry::store_status() {
            (self.on_warning)(&format!("OS secure storage is unavailable: {e}"));
            return false;
        }
        match Entry::new(SERVICE, PROBE_KEY).and_then(|e| e.get_password()) {
            Ok(_) | Err(Error::NoEntry) => true,
            Err(e) => {
                (self.on_warning)(&format!("OS secure storage is unavailable: {e}"));
                false
            }
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &str) -> Option<String> {
        if !self.available() {
            return None;
        }
        Entry::new(SERVICE, key).and_then(|e| e.get_password()).ok()
    }

    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        if !self.available() {
            return Err(SecretStoreError("OS secure storage is unavailable".into()));
        }
        Entry::new(SERVICE, key)
            .and_then(|e| e.set_password(value))
            .map_err(|e| SecretStoreError(e.to_string()))
    }

    fn delete(&self, key: &str) {
        if !self.available() {
            return;
        }
        match Entry::new(SERVICE, key).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(Error::NoEntry) => {}
            Err(e) => (self.on_warning)(&format!("Cannot delete a secret from OS secure storage: {e}")),
        }
    }

    fn available(&self) -> bool {
        *self.available.get_or_init(|| self.probe())
    }
}
