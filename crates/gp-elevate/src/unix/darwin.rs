//! macOS: openconnect as root through the system administrator dialog (`osascript … with
//! administrator privileges`) and the root wrapper in [`crate::darwin_script`].
//!
//! Only plain POSIX calls are used, so this compiles (and is lint-checked) on every Unix; it is
//! only selected at runtime on macOS.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use gp_core::process::{ExitStatusInfo, OutputChunk, SpawnError, SpawnRequest, VpnProcess};
use gp_core::types::VpnErrorCode;
use rustix::fs::OFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

use super::{KillOutcome, probe_alive, real_uid};
use crate::channels::{Channels, Senders};
use crate::darwin_script::{
    build_osascript, is_cancelled, is_wrapper_dir, parse_pid_file, parse_status_file,
};
use crate::quote::StopSignal;

const OSASCRIPT: &str = "/usr/bin/osascript";
/// The admin dialog may stay open for a while.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const POLL: Duration = Duration::from_millis(500);
const READ_BUF: usize = 8192;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DarwinSpawner;

fn unknown(msg: impl Into<String>) -> SpawnError {
    SpawnError::new(VpnErrorCode::Unknown, msg)
}

/// O_RDWR on a FIFO never blocks and never sees EOF, so nothing hangs if the elevated side dies.
/// O_NOFOLLOW: never follow a symlink.
fn open_fifo(path: &Path) -> io::Result<File> {
    let flags = OFlags::NONBLOCK | OFlags::NOFOLLOW;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(flags.bits().cast_signed())
        .open(path)?;
    if !file.metadata()?.file_type().is_fifo() {
        return Err(io::Error::other(format!("{} is not a FIFO", path.display())));
    }
    Ok(file)
}

/// The directory printed by the wrapper must be root-owned and not writable by others.
fn check_dir(dir: &str) -> Result<(), SpawnError> {
    if !is_wrapper_dir(dir) {
        return Err(unknown("Elevated helper returned an unexpected result"));
    }
    let st = std::fs::symlink_metadata(dir)
        .map_err(|e| unknown(format!("Elevated helper directory is not accessible: {e}")))?;
    if !st.is_dir() || st.uid() != 0 || st.mode() & 0o022 != 0 {
        return Err(unknown("Elevated helper directory has unexpected ownership"));
    }
    Ok(())
}

async fn run_osascript(script: &str) -> Result<String, SpawnError> {
    let child = Command::new(OSASCRIPT)
        .arg("-e")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| unknown(format!("Failed to start {OSASCRIPT}: {e}")))?;
    let out = tokio::time::timeout(DIALOG_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| unknown("Administrator authorization timed out"))?
        .map_err(|e| unknown(format!("Administrator authorization failed: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let code = if is_cancelled(&text) {
        VpnErrorCode::PrivilegesDenied
    } else {
        VpnErrorCode::Unknown
    };
    let detail = if text.is_empty() {
        out.status.to_string()
    } else {
        text
    };
    Err(SpawnError::new(
        code,
        format!("Administrator authorization failed: {detail}"),
    ))
}

async fn read_pid(dir: &Path) -> Option<u32> {
    for _ in 0..40 {
        // Tiny files in a local root-owned directory: a blocking read is fine.
        if let Some(pid) = std::fs::read_to_string(dir.join("pid"))
            .ok()
            .as_deref()
            .and_then(parse_pid_file)
        {
            return Some(pid);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

impl DarwinSpawner {
    pub(crate) async fn spawn(&self, req: &SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let binary = req
            .binary
            .to_str()
            .ok_or_else(|| unknown("openconnect path is not valid UTF-8"))?;
        let script = build_osascript(real_uid(), binary, &req.args);
        let dir = run_osascript(&script).await?;
        check_dir(&dir)?;
        let dir = PathBuf::from(dir);

        let attach = async {
            let input = pipe::Sender::from_file(open_fifo(&dir.join("in"))?)?;
            let output = pipe::Receiver::from_file(open_fifo(&dir.join("out"))?)?;
            io::Result::Ok((input, output))
        };
        let (input, output) = attach
            .await
            .map_err(|e| unknown(format!("Failed to attach to elevated openconnect: {e}")))?;
        let pid = read_pid(&dir)
            .await
            .ok_or_else(|| unknown("Elevated openconnect did not start"))?;

        let (senders, channels) = Channels::new();
        let exited = Arc::new(AtomicBool::new(false));
        tokio::spawn(watch(pid, dir.clone(), output, senders, exited.clone()));
        Ok(Box::new(OsascriptProcess {
            pid,
            dir,
            input,
            exited,
            channels,
        }))
    }
}

/// Relays the output FIFO and polls the root pid; when it is gone, reads the status written by
/// the wrapper and reports the exit after the remaining output. The root-owned directory is
/// removed by the wrapper itself.
async fn watch(pid: u32, dir: PathBuf, mut output: pipe::Receiver, tx: Senders, exited: Arc<AtomicBool>) {
    let mut buf = vec![0u8; READ_BUF];
    let mut tick = tokio::time::interval(POLL);
    let mut output_open = true;
    loop {
        tokio::select! {
            r = output.read(&mut buf), if output_open => match r {
                Ok(n) if n > 0 => {
                    // openconnect runs with 2>&1 into the FIFO: everything arrives as stderr.
                    let _ = tx.output.send(OutputChunk::stderr(&buf[..n])).await;
                }
                _ => output_open = false,
            },
            _ = tick.tick() => {
                // Alive: either ours (unlikely for root) or EPERM (owned by root).
                if !matches!(probe_alive(pid), Ok(KillOutcome::Sent | KillOutcome::NotPermitted)) {
                    break;
                }
            }
        }
    }
    exited.store(true, Ordering::SeqCst);
    let mut code = None;
    for _ in 0..4 {
        code = std::fs::read_to_string(dir.join("status"))
            .ok()
            .as_deref()
            .and_then(parse_status_file);
        if code.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // Let the last output arrive (an O_RDWR FIFO never reports EOF).
    let drain = async {
        while output_open {
            match output.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    let _ = tx.output.send(OutputChunk::stderr(&buf[..n])).await;
                }
                _ => output_open = false,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(200), drain).await;
    drop(tx.output);
    let _ = tx.exit.send(ExitStatusInfo { code, signal: None });
}

struct OsascriptProcess {
    pid: u32,
    dir: PathBuf,
    input: pipe::Sender,
    exited: Arc<AtomicBool>,
    channels: Channels,
}

impl OsascriptProcess {
    fn control(&self, sig: StopSignal) -> io::Result<()> {
        if self.exited.load(Ordering::SeqCst) {
            return Ok(());
        }
        let flags = OFlags::NONBLOCK | OFlags::NOFOLLOW;
        let mut f = OpenOptions::new()
            .write(true)
            .custom_flags(flags.bits().cast_signed())
            .open(self.dir.join("ctl"))?;
        f.write_all(format!("{}\n", sig.name()).as_bytes())
    }
}

#[async_trait]
impl VpnProcess for OsascriptProcess {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.exited.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.input.write_all(data).await
    }

    fn output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.channels.take_output()
    }

    async fn stop(&mut self) -> io::Result<()> {
        self.control(StopSignal::Int)
    }

    async fn kill(&mut self) -> io::Result<()> {
        self.control(StopSignal::Kill)
    }

    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.channels.take_exit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unexpected_directories() {
        assert_eq!(check_dir("/tmp/evil").unwrap_err().code, VpnErrorCode::Unknown);
        // Matches the pattern but does not exist (or is not root-owned on the test machine).
        assert!(check_dir("/private/tmp/gp-connect.zzzzzzzz").is_err());
    }

    #[test]
    fn open_fifo_refuses_symlinks_and_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("regular");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_fifo(&file).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(open_fifo(&link).is_err());
    }

    #[tokio::test]
    async fn relays_fifo_output_and_reports_the_status_after_the_process_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("out");
        let st = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(st.success());
        let output = pipe::Receiver::from_file(open_fifo(&fifo).unwrap()).unwrap();
        let mut writer = pipe::Sender::from_file(open_fifo(&fifo).unwrap()).unwrap();
        // A pid that exited: spawn and reap a short-lived child.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        std::fs::write(dir.path().join("status"), "7\n").unwrap();
        writer.write_all(b"hello\n").await.unwrap();

        let (senders, mut channels) = Channels::new();
        let exited = Arc::new(AtomicBool::new(false));
        tokio::spawn(watch(
            pid,
            dir.path().to_path_buf(),
            output,
            senders,
            exited.clone(),
        ));
        let mut out = channels.take_output();
        let info = channels.take_exit().await.unwrap();
        assert_eq!(info.code, Some(7));
        assert_eq!(out.recv().await.unwrap(), OutputChunk::stderr("hello\n"));
        assert!(exited.load(Ordering::SeqCst));
    }
}
