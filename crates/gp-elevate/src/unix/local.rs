//! openconnect as a direct child process with piped stdio: already root, or through `pkexec`
//! (Linux).

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use gp_core::process::{ExitStatusInfo, OutputChunk, OutputStream, SpawnError, SpawnRequest, VpnProcess};
use gp_core::types::VpnErrorCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

use super::{KillOutcome, send_signal, signal_name};
use crate::channels::{Channels, Senders};
use crate::quote::{
    LocalMethod, StopSignal, WrappedCommand, pkexec_path, privileged_kill_command, wrap_command,
};

/// After the child exited, how long its pipes may stay open (inherited by a grandchild) before
/// the exit is reported anyway.
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(2);
/// Upper bound for the `pkexec kill` dialog.
const PRIVILEGED_KILL_TIMEOUT: Duration = Duration::from_secs(60);
const READ_BUF: usize = 8192;

#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalSpawner {
    pub(crate) method: LocalMethod,
}

fn spawn_error(method: LocalMethod, command: &str, e: &io::Error) -> SpawnError {
    let code = match (e.kind(), method) {
        (io::ErrorKind::NotFound, LocalMethod::Direct) => VpnErrorCode::OpenconnectNotFound,
        (io::ErrorKind::NotFound, LocalMethod::Pkexec) => VpnErrorCode::PrivilegesDenied,
        _ => VpnErrorCode::Unknown,
    };
    SpawnError::new(code, format!("Failed to start {command}: {e}"))
}

impl LocalSpawner {
    pub(crate) fn spawn(self, req: &SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let binary = req
            .binary
            .to_str()
            .ok_or_else(|| SpawnError::new(VpnErrorCode::Unknown, "openconnect path is not valid UTF-8"))?;
        let cmd = wrap_command(self.method, pkexec_path(), binary, &req.args);
        let mut child = Command::new(&cmd.command)
            .args(&cmd.args)
            .envs(req.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| spawn_error(self.method, &cmd.command, &e))?;
        let pid = child.id();
        let stdin = child.stdin.take();
        let (senders, channels) = Channels::new();
        let exited = Arc::new(AtomicBool::new(false));
        tokio::spawn(supervise(child, senders, exited.clone()));
        Ok(Box::new(LocalProcess {
            pid,
            method: self.method,
            stdin,
            exited,
            channels,
        }))
    }
}

async fn pump(mut r: impl AsyncRead + Unpin, stream: OutputStream, tx: mpsc::Sender<OutputChunk>) {
    let mut buf = vec![0u8; READ_BUF];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let chunk = OutputChunk {
                    stream,
                    data: buf[..n].to_vec(),
                };
                if tx.send(chunk).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn exit_info(status: ExitStatus) -> ExitStatusInfo {
    ExitStatusInfo {
        code: status.code(),
        signal: status.signal().map(signal_name),
    }
}

/// Owns the child: relays its output, then reports the exit after the last chunk.
async fn supervise(mut child: Child, tx: Senders, exited: Arc<AtomicBool>) {
    let readers: Vec<_> = [
        child
            .stdout
            .take()
            .map(|o| tokio::spawn(pump(o, OutputStream::Stdout, tx.output.clone()))),
        child
            .stderr
            .take()
            .map(|e| tokio::spawn(pump(e, OutputStream::Stderr, tx.output.clone()))),
    ]
    .into_iter()
    .flatten()
    .collect();
    drop(tx.output);
    let status = child.wait().await;
    exited.store(true, Ordering::SeqCst);
    let aborts: Vec<_> = readers
        .iter()
        .map(tokio::task::JoinHandle::abort_handle)
        .collect();
    let drained = async {
        for r in readers {
            let _ = r.await;
        }
    };
    if tokio::time::timeout(DRAIN_AFTER_EXIT, drained).await.is_err() {
        aborts.iter().for_each(tokio::task::AbortHandle::abort);
    }
    // A failed wait() leaves the status unknown; the engine treats it as an unexpected exit.
    let info = status.map(exit_info).unwrap_or_default();
    let _ = tx.exit.send(info);
}

async fn run_privileged(cmd: &WrappedCommand) -> io::Result<()> {
    let mut child = Command::new(&cmd.command)
        .args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(PRIVILEGED_KILL_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{} timed out", cmd.command)))??;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} {} failed ({status})",
            cmd.command,
            cmd.args.join(" ")
        )))
    }
}

struct LocalProcess {
    pid: Option<u32>,
    method: LocalMethod,
    stdin: Option<ChildStdin>,
    exited: Arc<AtomicBool>,
    channels: Channels,
}

impl LocalProcess {
    async fn signal(&self, sig: StopSignal) -> io::Result<()> {
        let Some(pid) = self.pid else { return Ok(()) };
        if self.exited.load(Ordering::SeqCst) {
            return Ok(());
        }
        match send_signal(pid, sig)? {
            KillOutcome::Sent | KillOutcome::NoSuchProcess => Ok(()),
            KillOutcome::NotPermitted if self.method == LocalMethod::Pkexec => {
                // The process runs as root (pkexec execs in place), so our uid may not signal it.
                let cmd = privileged_kill_command(pkexec_path(), i64::from(pid), sig).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid pid {pid}"))
                })?;
                run_privileged(&cmd).await
            }
            KillOutcome::NotPermitted => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }
}

#[async_trait]
impl VpnProcess for LocalProcess {
    fn pid(&self) -> Option<u32> {
        self.pid
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.exited.load(Ordering::SeqCst) {
            return Ok(());
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Ok(());
        };
        let r = async {
            stdin.write_all(data).await?;
            stdin.flush().await
        }
        .await;
        match r {
            // EPIPE after the process exited; the exit is reported separately.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            r => r,
        }
    }

    fn output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.channels.take_output()
    }

    async fn stop(&mut self) -> io::Result<()> {
        self.signal(StopSignal::Int).await
    }

    async fn kill(&mut self) -> io::Result<()> {
        self.signal(StopSignal::Kill).await
    }

    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.channels.take_exit()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use gp_core::process::Elevation;

    use super::*;

    fn req(binary: &str, args: &[&str]) -> SpawnRequest {
        SpawnRequest {
            binary: PathBuf::from(binary),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            elevation: Elevation::None,
            env: vec![("GP_TEST_VAR".into(), "from-env".into())],
        }
    }

    async fn collect(p: &mut Box<dyn VpnProcess>) -> (String, String, ExitStatusInfo) {
        let mut out = p.output();
        let exit = p.exited();
        let (mut so, mut se) = (Vec::new(), Vec::new());
        while let Some(c) = out.recv().await {
            match c.stream {
                OutputStream::Stdout => so.extend(c.data),
                OutputStream::Stderr => se.extend(c.data),
            }
        }
        let info = exit.await.unwrap();
        (
            String::from_utf8(so).unwrap(),
            String::from_utf8(se).unwrap(),
            info,
        )
    }

    #[tokio::test]
    async fn relays_stdin_stdout_stderr_env_and_the_exit_code() {
        let spawner = LocalSpawner {
            method: LocalMethod::Direct,
        };
        let mut p = spawner
            .spawn(&req(
                "/bin/sh",
                &["-c", "read l; echo \"out:$l:$GP_TEST_VAR\"; echo err >&2; exit 3"],
            ))
            .unwrap();
        assert!(p.pid().is_some());
        p.write(b"secret\n").await.unwrap();
        let (so, se, info) = collect(&mut p).await;
        assert_eq!(so, "out:secret:from-env\n");
        assert_eq!(se, "err\n");
        assert_eq!(
            info,
            ExitStatusInfo {
                code: Some(3),
                signal: None
            }
        );
        // Writing / stopping after the exit is a no-op.
        p.write(b"late").await.unwrap();
        p.stop().await.unwrap();
    }

    #[tokio::test]
    async fn stop_sends_sigint() {
        let spawner = LocalSpawner {
            method: LocalMethod::Direct,
        };
        let mut p = spawner.spawn(&req("/bin/sleep", &["30"])).unwrap();
        let out = p.output();
        let exit = p.exited();
        p.stop().await.unwrap();
        let info = tokio::time::timeout(Duration::from_secs(10), exit)
            .await
            .unwrap()
            .unwrap();
        drop(out);
        assert_eq!(info.signal.as_deref(), Some("SIGINT"));
        assert_eq!(info.code, None);
    }

    #[tokio::test]
    async fn kill_sends_sigkill() {
        let spawner = LocalSpawner {
            method: LocalMethod::Direct,
        };
        let mut p = spawner
            .spawn(&req("/bin/sh", &["-c", "trap '' INT; sleep 30"]))
            .unwrap();
        let exit = p.exited();
        p.kill().await.unwrap();
        let info = tokio::time::timeout(Duration::from_secs(10), exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.signal.as_deref(), Some("SIGKILL"));
    }

    #[tokio::test]
    async fn a_missing_binary_maps_to_the_right_error_code() {
        let direct = LocalSpawner {
            method: LocalMethod::Direct,
        };
        let err = direct.spawn(&req("/nonexistent/openconnect", &[])).err().unwrap();
        assert_eq!(err.code, VpnErrorCode::OpenconnectNotFound);
        assert!(err.message.contains("/nonexistent/openconnect"));
        let e = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(
            spawn_error(LocalMethod::Pkexec, "pkexec", &e).code,
            VpnErrorCode::PrivilegesDenied
        );
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(
            spawn_error(LocalMethod::Direct, "x", &e).code,
            VpnErrorCode::Unknown
        );
    }

    #[tokio::test]
    async fn reports_the_exit_even_if_a_grandchild_keeps_the_pipes_open() {
        let spawner = LocalSpawner {
            method: LocalMethod::Direct,
        };
        let mut p = spawner
            .spawn(&req("/bin/sh", &["-c", "sleep 5 & echo started"]))
            .unwrap();
        let _out = p.output();
        let exit = p.exited();
        let info = tokio::time::timeout(Duration::from_secs(20), exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.code, Some(0));
    }
}
