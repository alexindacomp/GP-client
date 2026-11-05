//! Persistent state: settings, profiles (+ saved passwords in the OS keystore), confirmation of
//! elevation-relevant settings, and validation of untrusted input.

pub mod confirm_dialog;
pub mod confirmed_settings;
pub mod json_file;
pub mod profiles;
pub mod secret_store;
pub mod sensitive_settings;
pub mod settings;
pub mod validation;
