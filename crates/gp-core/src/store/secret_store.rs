//! OS keystore abstraction (implemented in the app with the `keyring` crate: Windows Credential
//! Manager, macOS Keychain, Linux Secret Service).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SecretStoreError(pub String);

pub trait SecretStore: Send + Sync {
    /// `None` when absent or unreadable (locked keyring, other OS user, …).
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError>;
    /// Best effort; never fails.
    fn delete(&self, key: &str);
    /// False when no real OS keystore is available (e.g. Linux without a Secret Service).
    fn available(&self) -> bool;
}

/// In-memory store whose availability can be switched (tests; also a safe fallback that keeps
/// nothing across restarts).
#[derive(Debug)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<String, String>>,
    available: AtomicBool,
}

impl Default for MemorySecretStore {
    fn default() -> Self {
        MemorySecretStore {
            values: Mutex::new(HashMap::new()),
            available: AtomicBool::new(true),
        }
    }
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Raw view for tests.
    pub fn snapshot(&self) -> HashMap<String, String> {
        self.map().clone()
    }

    /// Overwrites a value even while "unavailable" (tests: simulate tampering).
    pub fn force_set(&self, key: &str, value: &str) {
        self.map().insert(key.to_string(), value.to_string());
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Option<String> {
        if !self.available() {
            return None;
        }
        self.map().get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        if !self.available() {
            return Err(SecretStoreError("secure storage is unavailable".into()));
        }
        self.map().insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) {
        if self.available() {
            self.map().remove(key);
        }
    }

    fn available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }
}
