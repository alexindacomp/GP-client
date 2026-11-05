//! GP Connect core: everything that is not GUI — portal prelogin, SAML result extraction,
//! openconnect discovery/trust/argv/output parsing, the VPN engine state machine, persistent
//! stores, logging with secret masking, and localized texts. No tauri / GUI dependencies, so
//! `cargo test` runs anywhere (incl. WSL without WebKitGTK).
//!
//! See docs/ARCHITECTURE-TAURI.md.

pub mod clock;
pub mod logging;
pub mod openconnect;
pub mod platform;
pub mod prelogin;
pub mod process;
pub mod saml;
pub mod store;
pub mod tray_labels;
pub mod types;
mod util;
pub mod validation;
pub mod vpn;

pub use platform::Platform;
pub use types::*;
pub use vpn::{VpnEngine, VpnError};
