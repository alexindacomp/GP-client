//! App side of an authenticated helper connection: waits for the start result and exposes the
//! remote openconnect as a [`VpnProcess`]. Generic over the stream so it is tested on every OS
//! (the Windows spawner plugs in the named pipe).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use gp_core::process::{ExitStatusInfo, OutputChunk, SpawnError, VpnProcess};
use gp_core::types::VpnErrorCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::sync::{mpsc, oneshot};

use crate::channels::{Channels, Senders};
use crate::helper_protocol::{FatalCode, Frame, MAX_FRAME, read_frame, write_frame};

/// Time the helper gets after the hello to validate the request and start openconnect.
pub(crate) const START_TIMEOUT: Duration = Duration::from_secs(60);

fn unknown(msg: impl Into<String>) -> SpawnError {
    SpawnError::new(VpnErrorCode::Unknown, msg)
}

/// Waits for `P` (started) or `F` (refused/failed) on an authenticated stream.
pub(crate) async fn attach<S>(stream: S, start_timeout: Duration) -> Result<Box<dyn VpnProcess>, SpawnError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let first = tokio::time::timeout(start_timeout, read_frame(&mut reader))
        .await
        .map_err(|_| unknown("Timed out waiting for the elevated helper to start openconnect"))?
        .map_err(|e| unknown(format!("Elevated helper connection failed: {e}")))?;
    let pid = match first {
        Some(Frame::Pid(pid)) => pid,
        Some(Frame::Fatal(FatalCode::Refused, msg)) => {
            return Err(SpawnError::new(VpnErrorCode::PrivilegesDenied, msg));
        }
        Some(Frame::Fatal(FatalCode::SpawnFailed, msg)) => return Err(unknown(msg)),
        Some(_) => return Err(unknown("Elevated helper sent an unexpected message")),
        None => return Err(unknown("Elevated helper closed the connection")),
    };
    let (senders, channels) = Channels::new();
    let exited = Arc::new(AtomicBool::new(false));
    tokio::spawn(read_loop(reader, senders, exited.clone()));
    Ok(Box::new(HelperProcess {
        pid,
        writer: Box::new(writer),
        exited,
        channels,
    }))
}

async fn read_loop<S: AsyncRead>(mut reader: ReadHalf<S>, tx: Senders, exited: Arc<AtomicBool>) {
    let mut info = ExitStatusInfo::default();
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::Stdout(d))) => {
                let _ = tx.output.send(OutputChunk::stdout(d)).await;
            }
            Ok(Some(Frame::Stderr(d))) => {
                let _ = tx.output.send(OutputChunk::stderr(d)).await;
            }
            Ok(Some(Frame::Exit(code))) => {
                info.code = Some(code);
                break;
            }
            Ok(Some(_)) => {}
            // Pipe closed or broken without an exit frame: the helper is gone.
            Ok(None) | Err(_) => break,
        }
    }
    exited.store(true, Ordering::SeqCst);
    drop(tx.output);
    let _ = tx.exit.send(info);
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

struct HelperProcess {
    pid: u32,
    writer: Writer,
    exited: Arc<AtomicBool>,
    channels: Channels,
}

impl HelperProcess {
    async fn send(&mut self, frame: &Frame) -> io::Result<()> {
        if self.exited.load(Ordering::SeqCst) {
            return Ok(());
        }
        match write_frame(&mut self.writer, frame).await {
            // The helper went away; the exit is reported by the reader.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            r => r,
        }
    }
}

#[async_trait]
impl VpnProcess for HelperProcess {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(MAX_FRAME) {
            self.send(&Frame::Stdin(chunk.to_vec())).await?;
        }
        Ok(())
    }

    fn output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.channels.take_output()
    }

    async fn stop(&mut self) -> io::Result<()> {
        self.send(&Frame::Stop).await
    }

    async fn kill(&mut self) -> io::Result<()> {
        self.send(&Frame::Kill).await?;
        if !self.exited.load(Ordering::SeqCst) {
            // Closing the pipe makes the helper kill openconnect as well.
            let _ = self.writer.shutdown().await;
        }
        Ok(())
    }

    fn exited(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.channels.take_exit()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{DuplexStream, duplex};

    use super::*;

    async fn helper_side(frames: &[Frame]) -> (DuplexStream, DuplexStream) {
        let (app, mut helper) = duplex(64 * 1024);
        for f in frames {
            write_frame(&mut helper, f).await.unwrap();
        }
        (app, helper)
    }

    #[tokio::test]
    async fn maps_fatal_frames_to_spawn_errors() {
        let (app, _h) = helper_side(&[Frame::Fatal(FatalCode::Refused, "untrusted".into())]).await;
        let e = attach(app, START_TIMEOUT).await.err().unwrap();
        assert_eq!(
            (e.code, e.message.as_str()),
            (VpnErrorCode::PrivilegesDenied, "untrusted")
        );

        let (app, _h) = helper_side(&[Frame::Fatal(FatalCode::SpawnFailed, "boom".into())]).await;
        assert_eq!(
            attach(app, START_TIMEOUT).await.err().unwrap().code,
            VpnErrorCode::Unknown
        );

        let (app, h) = helper_side(&[]).await;
        drop(h);
        let e = attach(app, START_TIMEOUT).await.err().unwrap();
        assert!(e.message.contains("closed"));

        let (app, _h) = helper_side(&[Frame::Stdout(b"x".to_vec())]).await;
        assert!(attach(app, START_TIMEOUT).await.is_err());
    }

    #[tokio::test]
    async fn times_out_when_the_helper_says_nothing() {
        let (app, _h) = helper_side(&[]).await;
        let e = attach(app, Duration::from_millis(50)).await.err().unwrap();
        assert!(e.message.contains("Timed out"));
    }

    #[tokio::test]
    async fn relays_output_then_exit_and_sends_control_frames() {
        let (app, mut helper) = helper_side(&[
            Frame::Pid(4242),
            Frame::Stdout(b"hello ".to_vec()),
            Frame::Stderr(b"warn".to_vec()),
        ])
        .await;
        let mut p = attach(app, START_TIMEOUT).await.unwrap();
        assert_eq!(p.pid(), Some(4242));
        let mut out = p.output();
        let exit = p.exited();
        assert_eq!(out.recv().await.unwrap(), OutputChunk::stdout("hello "));
        assert_eq!(out.recv().await.unwrap(), OutputChunk::stderr("warn"));

        p.write(b"secret\n").await.unwrap();
        p.stop().await.unwrap();
        assert_eq!(
            read_frame(&mut helper).await.unwrap(),
            Some(Frame::Stdin(b"secret\n".to_vec()))
        );
        assert_eq!(read_frame(&mut helper).await.unwrap(), Some(Frame::Stop));

        write_frame(&mut helper, &Frame::Stdout(b"bye".to_vec()))
            .await
            .unwrap();
        write_frame(&mut helper, &Frame::Exit(0)).await.unwrap();
        assert_eq!(out.recv().await.unwrap(), OutputChunk::stdout("bye"));
        assert_eq!(out.recv().await, None);
        assert_eq!(
            exit.await.unwrap(),
            ExitStatusInfo {
                code: Some(0),
                signal: None
            }
        );
        // After the exit, control calls are no-ops.
        p.write(b"x").await.unwrap();
        p.kill().await.unwrap();
    }

    #[tokio::test]
    async fn kill_sends_k_and_closes_the_pipe() {
        let (app, mut helper) = helper_side(&[Frame::Pid(1)]).await;
        let mut p = attach(app, START_TIMEOUT).await.unwrap();
        let exit = p.exited();
        p.kill().await.unwrap();
        assert_eq!(read_frame(&mut helper).await.unwrap(), Some(Frame::Kill));
        assert_eq!(read_frame(&mut helper).await.unwrap(), None);
        drop(helper);
        assert_eq!(exit.await.unwrap(), ExitStatusInfo::default());
    }

    #[tokio::test]
    async fn splits_large_stdin_writes_into_frames() {
        let (app, mut helper) = helper_side(&[Frame::Pid(1)]).await;
        let mut p = attach(app, START_TIMEOUT).await.unwrap();
        let data = vec![7u8; MAX_FRAME + 10];
        let reader = tokio::spawn(async move {
            let a = read_frame(&mut helper).await.unwrap();
            let b = read_frame(&mut helper).await.unwrap();
            (a, b)
        });
        p.write(&data).await.unwrap();
        let (a, b) = reader.await.unwrap();
        assert_eq!(a, Some(Frame::Stdin(vec![7u8; MAX_FRAME])));
        assert_eq!(b, Some(Frame::Stdin(vec![7u8; 10])));
    }
}
