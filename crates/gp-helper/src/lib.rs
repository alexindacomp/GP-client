//! `gp-connect-helper.exe`: the elevated Windows helper of GP Connect (replaces the PowerShell
//! bridge). Started by the app with UAC as `gp-connect-helper.exe --config <path> --sha256 <hex>`;
//! the wire protocol is `gp_elevate::helper_protocol`.
//!
//! Flow: read + verify + delete the launch config ([`config`]), connect to the app's named pipe and
//! authenticate, re-validate the request as administrator ([`validate`]: binary/script trust with
//! the native ACL probe, argv allowlist), start openconnect with piped stdio in a hidden console,
//! and relay I/O until it exits ([`relay`]).
//!
//! The logic is platform-independent and tested everywhere; only the pipe client, console Ctrl+C
//! and process flags are Windows-specific.

pub mod argv;
pub mod cli;
pub mod config;
pub mod env;
pub mod relay;
pub mod transcode;
pub mod validate;
#[cfg(windows)]
mod win;

use gp_elevate::helper_protocol::exit_code;

/// Runs the helper with the process arguments; returns the process exit code.
pub fn run() -> i32 {
    // Before anything else is loaded or read: safe DLL search, System32 as working directory.
    #[cfg(windows)]
    if win::harden_process().is_err() {
        return exit_code::INTERNAL;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let Ok(cli) = cli::parse_cli(&args) else {
        return exit_code::USAGE;
    };
    let cfg = match config::load(&cli.config, &cli.sha256) {
        Ok(c) => c,
        Err(config::ConfigError::Hash) => return exit_code::CONFIG_HASH,
        Err(config::ConfigError::Invalid(_)) => return exit_code::CONFIG_INVALID,
    };
    run_session(cfg)
}

#[cfg(windows)]
fn run_session(cfg: gp_elevate::helper_protocol::HelperConfig) -> i32 {
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(win::session(cfg)),
        Err(_) => exit_code::INTERNAL,
    }
}

/// The helper only exists for Windows; elsewhere it refuses to do anything.
#[cfg(not(windows))]
fn run_session(_cfg: gp_elevate::helper_protocol::HelperConfig) -> i32 {
    exit_code::INTERNAL
}
