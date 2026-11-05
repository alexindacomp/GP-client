//! Relays one openconnect process over an authenticated pipe: `P` first, then stdout/stderr as
//! `O`/`E`, stdin from `I`, `S` = graceful stop (Ctrl+C), `K` = kill, and finally `X` with the
//! exit code after the last output. If the app closes the pipe, openconnect is killed so it never
//! outlives the app. Output is forwarded as UTF-8 ([`crate::transcode`]). Generic over the stream
//! so it is tested on every OS.

use std::io;
use std::time::Duration;

use gp_elevate::helper_protocol::{Frame, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::mpsc;

use crate::transcode::{Fallback, LineTranscoder};

/// After openconnect exited, how long its pipes may stay open (inherited by a script it started)
/// before the exit is reported anyway.
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(2);
const READ_BUF: usize = 8192;
/// An unterminated line (a prompt) is forwarded once the output was idle this long. Well below
/// the app's prompt debounce (150 ms).
const IDLE_FLUSH: Duration = Duration::from_millis(50);
/// stdin frames queued for openconnect. stdin only carries short answers (password, prompt
/// replies); a full backlog means openconnect stopped reading and would stall the relay.
const STDIN_BACKLOG: usize = 16;

/// Graceful stop of the process with the given pid (Ctrl+C on Windows).
pub type CtrlC = dyn Fn(u32) -> io::Result<()> + Sync;

async fn read_opt<R: AsyncRead + Unpin>(r: &mut Option<R>, buf: &mut [u8]) -> io::Result<usize> {
    match r {
        Some(r) => r.read(buf).await,
        None => std::future::pending().await,
    }
}

fn is_empty_output(f: &Frame) -> bool {
    matches!(f, Frame::Stdout(d) | Frame::Stderr(d) if d.is_empty())
}

/// Runs until openconnect exited and its output was relayed. Returns its exit code. Output lines
/// that are not UTF-8 are decoded with `fallback` (the console code page on Windows).
pub async fn relay<R, W>(
    reader: R,
    mut writer: W,
    mut child: Child,
    ctrl_c: &CtrlC,
    fallback: &Fallback,
) -> io::Result<Option<i32>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let pid = child.id().unwrap_or_default();
    // stdin is written by its own task, so a child that stops reading cannot block the relay.
    let (stdin_tx, stdin_task) = match child.stdin.take() {
        Some(mut s) => {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(STDIN_BACKLOG);
            let task = tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if s.write_all(&data).await.is_err() || s.flush().await.is_err() {
                        return;
                    }
                }
            });
            (Some(tx), Some(task))
        }
        None => (None, None),
    };
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    // Frames are read in their own task: `read_frame` is not cancel-safe.
    let (frame_tx, mut frames) = mpsc::channel::<Frame>(16);
    let reader_task = tokio::spawn(async move {
        let mut reader = reader;
        while let Ok(Some(f)) = read_frame(&mut reader).await {
            if frame_tx.send(f).await.is_err() {
                return;
            }
        }
    });

    let mut pipe_ok = write_frame(&mut writer, &Frame::Pid(pid)).await.is_ok();
    if !pipe_ok {
        let _ = child.start_kill();
    }
    let mut app_open = true;
    let mut exited: Option<Option<i32>> = None;
    let drain = tokio::time::sleep(Duration::MAX);
    tokio::pin!(drain);
    let idle = tokio::time::sleep(Duration::MAX);
    tokio::pin!(idle);
    let (mut out_buf, mut err_buf) = (vec![0u8; READ_BUF], vec![0u8; READ_BUF]);
    let (mut out_text, mut err_text) = (LineTranscoder::default(), LineTranscoder::default());

    while exited.is_none() || stdout.is_some() || stderr.is_some() {
        let mut output: Vec<Frame> = Vec::new();
        tokio::select! {
            r = read_opt(&mut stdout, &mut out_buf), if stdout.is_some() => match r {
                Ok(n) if n > 0 => {
                    output.push(Frame::Stdout(out_text.push(&out_buf[..n], fallback).into_bytes()));
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_FLUSH);
                }
                _ => {
                    stdout = None;
                    output.push(Frame::Stdout(out_text.flush(fallback).into_bytes()));
                }
            },
            r = read_opt(&mut stderr, &mut err_buf), if stderr.is_some() => match r {
                Ok(n) if n > 0 => {
                    output.push(Frame::Stderr(err_text.push(&err_buf[..n], fallback).into_bytes()));
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_FLUSH);
                }
                _ => {
                    stderr = None;
                    output.push(Frame::Stderr(err_text.flush(fallback).into_bytes()));
                }
            },
            () = &mut idle, if out_text.has_pending() || err_text.has_pending() => {
                output.push(Frame::Stdout(out_text.flush(fallback).into_bytes()));
                output.push(Frame::Stderr(err_text.flush(fallback).into_bytes()));
                idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(86_400));
            }
            f = frames.recv(), if app_open => match f {
                Some(Frame::Stdin(data)) => {
                    if let Some(tx) = &stdin_tx
                        && let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(data)
                    {
                        // openconnect does not read its stdin any more: end it rather than
                        // hang (a closed stdin task just drops the data).
                        let _ = child.start_kill();
                    }
                }
                Some(Frame::Stop) => {
                    let _ = ctrl_c(pid);
                }
                Some(Frame::Kill) => {
                    let _ = child.start_kill();
                }
                Some(_) => {}
                None => {
                    // The app is gone (closed or broken pipe): openconnect must not outlive it.
                    app_open = false;
                    let _ = child.start_kill();
                }
            },
            status = child.wait(), if exited.is_none() => {
                exited = Some(status.ok().and_then(|s| s.code()));
                drain.as_mut().reset(tokio::time::Instant::now() + DRAIN_AFTER_EXIT);
            }
            () = &mut drain, if exited.is_some() => break,
        }
        for frame in output {
            if is_empty_output(&frame) || !pipe_ok {
                continue;
            }
            if write_frame(&mut writer, &frame).await.is_err() {
                pipe_ok = false;
                let _ = child.start_kill();
            }
        }
    }
    // Stopped draining with a line still unterminated (pipes kept open by a script): send it.
    for frame in [
        Frame::Stdout(out_text.flush(fallback).into_bytes()),
        Frame::Stderr(err_text.flush(fallback).into_bytes()),
    ] {
        if pipe_ok && !is_empty_output(&frame) && write_frame(&mut writer, &frame).await.is_err() {
            pipe_ok = false;
        }
    }
    reader_task.abort();
    if let Some(t) = stdin_task {
        t.abort();
    }
    let code = exited.flatten();
    if pipe_ok {
        let _ = write_frame(&mut writer, &Frame::Exit(code.unwrap_or(-1))).await;
        let _ = writer.shutdown().await;
    }
    Ok(code)
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::process::Stdio;
    use std::sync::Mutex;

    use tokio::io::{DuplexStream, duplex};
    use tokio::process::Command;

    use super::*;

    fn sh(script: &str) -> Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[allow(clippy::unnecessary_wraps)] // must match `CtrlC`
    fn no_ctrl_c(_: u32) -> io::Result<()> {
        Ok(())
    }

    /// Starts the relay on one end of a duplex pair; returns the app's end.
    fn start(
        child: Child,
        ctrl_c: &'static CtrlC,
    ) -> (DuplexStream, tokio::task::JoinHandle<io::Result<Option<i32>>>) {
        let (app, helper) = duplex(64 * 1024);
        let (r, w) = tokio::io::split(helper);
        (
            app,
            tokio::spawn(async move { relay(r, w, child, ctrl_c, &crate::transcode::utf8_lossy).await }),
        )
    }

    async fn frames_until_exit(app: &mut DuplexStream) -> Vec<Frame> {
        let mut v = Vec::new();
        while let Some(f) = read_frame(app).await.unwrap() {
            let done = matches!(f, Frame::Exit(_));
            v.push(f);
            if done {
                break;
            }
        }
        v
    }

    #[tokio::test]
    async fn relays_pid_stdin_output_and_the_exit_code_last() {
        let (mut app, task) = start(sh("read l; echo \"got $l\"; echo oops >&2; exit 3"), &no_ctrl_c);
        let Some(Frame::Pid(pid)) = read_frame(&mut app).await.unwrap() else {
            panic!("no pid")
        };
        assert!(pid > 0);
        write_frame(&mut app, &Frame::Stdin(b"secret\n".to_vec()))
            .await
            .unwrap();
        let frames = frames_until_exit(&mut app).await;
        assert_eq!(frames.last(), Some(&Frame::Exit(3)));
        let out: Vec<u8> = frames
            .iter()
            .filter_map(|f| {
                if let Frame::Stdout(d) = f {
                    Some(d.clone())
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        let err: Vec<u8> = frames
            .iter()
            .filter_map(|f| {
                if let Frame::Stderr(d) = f {
                    Some(d.clone())
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        assert_eq!(out, b"got secret\n");
        assert_eq!(err, b"oops\n");
        assert_eq!(read_frame(&mut app).await.unwrap(), None);
        assert_eq!(task.await.unwrap().unwrap(), Some(3));
    }

    #[tokio::test]
    async fn stop_calls_ctrl_c_with_the_pid() {
        static SEEN: Mutex<Option<u32>> = Mutex::new(None);
        fn record(pid: u32) -> io::Result<()> {
            *SEEN.lock().unwrap() = Some(pid);
            std::process::Command::new("kill")
                .args(["-INT", &pid.to_string()])
                .status()?;
            Ok(())
        }
        let (mut app, task) = start(
            sh("trap 'echo bye; exit 0' INT; while :; do sleep 0.05; done"),
            &record,
        );
        let Some(Frame::Pid(pid)) = read_frame(&mut app).await.unwrap() else {
            panic!("no pid")
        };
        write_frame(&mut app, &Frame::Stop).await.unwrap();
        let frames = frames_until_exit(&mut app).await;
        assert_eq!(*SEEN.lock().unwrap(), Some(pid));
        assert!(frames.contains(&Frame::Stdout(b"bye\n".to_vec())), "{frames:?}");
        assert_eq!(frames.last(), Some(&Frame::Exit(0)));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn kill_frame_terminates_the_process() {
        let (mut app, task) = start(sh("trap '' INT; sleep 30"), &no_ctrl_c);
        assert!(matches!(read_frame(&mut app).await.unwrap(), Some(Frame::Pid(_))));
        write_frame(&mut app, &Frame::Kill).await.unwrap();
        let frames = tokio::time::timeout(Duration::from_secs(10), frames_until_exit(&mut app))
            .await
            .unwrap();
        // Killed by a signal on Unix: no exit code.
        assert_eq!(frames.last(), Some(&Frame::Exit(-1)));
        assert_eq!(task.await.unwrap().unwrap(), None);
    }

    #[tokio::test]
    async fn a_child_that_stops_reading_stdin_cannot_stall_the_relay() {
        let (app, task) = start(sh("trap '' INT; sleep 30"), &no_ctrl_c);
        let (mut r, mut w) = tokio::io::split(app);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::Pid(_))));
        // Far more than the OS pipe buffer plus the backlog; the writer runs on its own.
        tokio::spawn(async move {
            for _ in 0..64 {
                if write_frame(&mut w, &Frame::Stdin(vec![b'x'; 60_000]))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        let exit = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match read_frame(&mut r).await.unwrap() {
                    Some(Frame::Exit(c)) => return c,
                    Some(_) => {}
                    None => panic!("no exit frame"),
                }
            }
        })
        .await
        .expect("relay stalled");
        assert_eq!(exit, -1); // killed
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn closing_the_pipe_kills_openconnect() {
        let (app, task) = start(sh("sleep 30"), &no_ctrl_c);
        drop(app);
        let r = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.unwrap(), None);
    }

    #[tokio::test]
    async fn reports_the_exit_even_if_a_grandchild_keeps_stdout_open() {
        let (mut app, task) = start(sh("sleep 5 & exit 0"), &no_ctrl_c);
        let frames = tokio::time::timeout(Duration::from_secs(4), frames_until_exit(&mut app))
            .await
            .unwrap();
        assert_eq!(frames.last(), Some(&Frame::Exit(0)));
        task.await.unwrap().unwrap();
    }
}
