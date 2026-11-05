//! Process boundary of the VPN engine. Implemented by gp-elevate (pkexec / osascript wrapper /
//! Windows helper client) and by fakes in tests.

use std::io;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::platform::Platform;
use crate::types::VpnErrorCode;
use crate::vpn::VpnError;

/// How openconnect gets the privileges it needs to create a tun device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Elevation {
    /// Already root (Unix) — run directly.
    None,
    /// Linux: `pkexec --disable-internal-agent <binary> …`.
    Pkexec,
    /// macOS: root wrapper started via `osascript … with administrator privileges`.
    Osascript,
    /// Windows: `gp-connect-helper.exe` started with UAC.
    Uac,
}

/// macOS always uses the system admin dialog: a passwordless `sudo` rule would let any process
/// of the user run openconnect (and its --script) as root.
pub fn choose_elevation(platform: Platform, is_root: bool) -> Elevation {
    match platform {
        Platform::Win32 => Elevation::Uac,
        _ if is_root => Elevation::None,
        Platform::Darwin => Elevation::Osascript,
        Platform::Linux => Elevation::Pkexec,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Verified real path of openconnect (see `OpenconnectProvider::verify_elevated_files`).
    pub binary: PathBuf,
    /// argv without the binary; never contains secrets (they go to stdin).
    pub args: Vec<String>,
    pub elevation: Elevation,
    /// Extra environment for the child (empty by default).
    pub env: Vec<(String, String)>,
}

/// The process could not be started (e.g. the admin dialog was dismissed → `PRIVILEGES_DENIED`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SpawnError {
    pub code: VpnErrorCode,
    pub message: String,
}

impl SpawnError {
    pub fn new(code: VpnErrorCode, message: impl Into<String>) -> Self {
        SpawnError {
            code,
            message: message.into(),
        }
    }
}

impl From<SpawnError> for VpnError {
    fn from(e: SpawnError) -> Self {
        VpnError::new(e.code, e.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// A chunk read from stdout or stderr. Bytes as read from the pipe: chunks may split lines and
/// even UTF-8 sequences; the engine reassembles both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub stream: OutputStream,
    pub data: Vec<u8>,
}

impl OutputChunk {
    pub fn stdout(data: impl Into<Vec<u8>>) -> Self {
        OutputChunk {
            stream: OutputStream::Stdout,
            data: data.into(),
        }
    }
    pub fn stderr(data: impl Into<Vec<u8>>) -> Self {
        OutputChunk {
            stream: OutputStream::Stderr,
            data: data.into(),
        }
    }
}

/// How the process ended (`code` or `signal`, like Node's exit event). pkexec: 126 = dialog
/// dismissed, 127 = not authorized.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitStatusInfo {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

/// A running (possibly elevated) openconnect process.
///
/// Contract for implementations:
/// * `output()` and `exited()` are called once each, right after `spawn`; output produced before
///   that must be buffered in the channel, not dropped.
/// * The output channel must deliver everything the process wrote before `exited()` resolves
///   (close the sender, or send the exit only after the last chunk).
/// * `stop()` sends the graceful signal (SIGINT / Ctrl+C) and returns without waiting for the
///   exit; `kill()` likewise for the forced termination. Both may fail (e.g. the `pkexec kill`
///   dialog was dismissed); the engine then keeps owning the process.
#[async_trait]
pub trait VpnProcess: Send {
    fn pid(&self) -> Option<u32>;
    /// Writes to stdin (secrets are only ever passed this way).
    async fn write(&mut self, data: &[u8]) -> io::Result<()>;
    /// stdout/stderr chunks.
    fn output(&mut self) -> mpsc::Receiver<OutputChunk>;
    /// Graceful stop (SIGINT / Ctrl+C, so openconnect runs its disconnect script).
    async fn stop(&mut self) -> io::Result<()>;
    /// Forced termination.
    async fn kill(&mut self) -> io::Result<()>;
    /// Resolves once with the exit status.
    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo>;
}

#[async_trait]
pub trait ProcessSpawner: Send + Sync {
    /// Starts the process; fails with [`SpawnError`] when it cannot be started.
    async fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_the_elevation_method_per_platform() {
        assert_eq!(choose_elevation(Platform::Win32, false), Elevation::Uac);
        assert_eq!(choose_elevation(Platform::Win32, true), Elevation::Uac);
        assert_eq!(choose_elevation(Platform::Linux, false), Elevation::Pkexec);
        assert_eq!(choose_elevation(Platform::Darwin, false), Elevation::Osascript);
        assert_eq!(choose_elevation(Platform::Linux, true), Elevation::None);
        assert_eq!(choose_elevation(Platform::Darwin, true), Elevation::None);
    }

    #[test]
    fn spawn_errors_keep_their_code() {
        let e: VpnError = SpawnError::new(VpnErrorCode::PrivilegesDenied, "UAC cancelled").into();
        assert_eq!(
            (e.code, e.message.as_str()),
            (VpnErrorCode::PrivilegesDenied, "UAC cancelled")
        );
    }
}
