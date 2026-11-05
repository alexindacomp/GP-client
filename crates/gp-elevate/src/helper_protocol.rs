//! Wire protocol between the app and the elevated Windows helper `gp-connect-helper.exe`.
//!
//! Launch: the app creates the named pipe `\\.\pipe\gp-connect-<32 hex>`, writes a
//! [`HelperConfig`] JSON file (new file in a fresh directory under the user's %TEMP%) and starts
//! `gp-connect-helper.exe --config <path> --sha256 <hex>` with UAC. The pipe name and token never
//! appear on a command line. The helper verifies the hash, deletes the file, connects to the pipe
//! and authenticates with [`Frame::Hello`]; then it re-validates the request as administrator and
//! answers [`Frame::Pid`] (openconnect started) or [`Frame::Fatal`] (refused / failed).
//!
//! Frames: `tag: u8`, `len: u32 LE`, `len` payload bytes.
//! * helper → app: `H` token, `P` pid (u32 LE), `O` stdout bytes, `E` stderr bytes,
//!   `X` exit code (i32 LE, last frame), `F` fatal (1 code byte + UTF-8 message).
//! * app → helper: `I` stdin bytes, `S` graceful stop (Ctrl+C), `K` kill.
//!
//! Closing the pipe from the app side makes the helper kill openconnect, so it never outlives the
//! app.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

/// Pipe names are `gp-connect-` + 32 lower-case hex digits.
pub const PIPE_PREFIX: &str = "gp-connect-";
/// An idle or wrong client must not hold a pipe instance.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Pipe instances / concurrent unauthenticated clients: enough for a few stray clients without
/// letting anyone exhaust resources.
pub const MAX_CONNECTIONS: usize = 16;
/// Largest payload of any frame.
pub const MAX_FRAME: usize = 64 * 1024;
/// Largest hello payload.
pub const MAX_HELLO: usize = 256;
/// Largest config file the helper accepts.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Helper process exit codes (reported by the app when the helper dies before authenticating).
pub mod exit_code {
    /// Bad command line.
    pub const USAGE: i32 = 2;
    /// Config file hash mismatch.
    pub const CONFIG_HASH: i32 = 3;
    /// Config file unreadable, too large or malformed.
    pub const CONFIG_INVALID: i32 = 4;
    /// Could not connect to the app's pipe.
    pub const PIPE: i32 = 5;
    /// Request refused by the admin-side validation (sent as [`super::Frame::Fatal`] too).
    pub const REFUSED: i32 = 6;
    /// openconnect could not be started (sent as [`super::Frame::Fatal`] too).
    pub const SPAWN: i32 = 7;
    /// Async runtime could not be created / internal error.
    pub const INTERNAL: i32 = 8;

    /// Human-readable reason for a helper exit code.
    pub fn describe(code: i32) -> &'static str {
        match code {
            USAGE => "invalid command line",
            CONFIG_HASH => "launch configuration was modified",
            CONFIG_INVALID => "launch configuration is unreadable or invalid",
            PIPE => "could not connect back to GP Connect",
            REFUSED => "request refused",
            SPAWN => "openconnect could not be started",
            _ => "internal error",
        }
    }
}

/// Contents of the launch config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelperConfig {
    /// Pipe name without the `\\.\pipe\` prefix.
    pub pipe: String,
    /// One-time token (64 hex) the helper presents in its hello.
    pub token: String,
    /// openconnect binary (real path verified by the app).
    pub binary: String,
    /// openconnect argv without the binary.
    pub args: Vec<String>,
    /// HIP `--csd-wrapper` script, when configured (must match the argv).
    #[serde(default)]
    pub script: Option<String>,
    /// Process id of the app (the pipe server). The helper verifies it with
    /// `GetNamedPipeServerProcessId` before sending the token.
    pub server_pid: u32,
}

impl HelperConfig {
    /// Format checks on the fields that are not re-validated by the trust/argv checks.
    pub fn check_format(&self) -> Result<(), String> {
        if !is_valid_pipe_name(&self.pipe) {
            return Err("invalid pipe name".into());
        }
        if !is_hex(&self.token, 64) {
            return Err("invalid token".into());
        }
        if self.server_pid == 0 {
            return Err("invalid server pid".into());
        }
        Ok(())
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_valid_pipe_name(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX)
        .is_some_and(|rest| is_hex(rest, 32))
}

/// Lower-case SHA-256 hex digest.
pub fn is_valid_sha256(s: &str) -> bool {
    is_hex(s, 64)
}

/// `\\.\pipe\<name>`.
pub fn pipe_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `n` random bytes as hex (OS CSPRNG).
pub fn random_hex(n: usize) -> io::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| io::Error::other(format!("random generator failed: {e}")))?;
    Ok(hex(&buf))
}

/// Constant-time equality (the length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Why the helper refused or failed before openconnect ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalCode {
    /// Binary / script not admin-controlled, or argv not allowed.
    Refused = 1,
    /// openconnect could not be started.
    SpawnFailed = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello(Vec<u8>),
    Pid(u32),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    Fatal(FatalCode, String),
    Stdin(Vec<u8>),
    Stop,
    Kill,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

impl Frame {
    fn tag(&self) -> u8 {
        match self {
            Frame::Hello(_) => b'H',
            Frame::Pid(_) => b'P',
            Frame::Stdout(_) => b'O',
            Frame::Stderr(_) => b'E',
            Frame::Exit(_) => b'X',
            Frame::Fatal(..) => b'F',
            Frame::Stdin(_) => b'I',
            Frame::Stop => b'S',
            Frame::Kill => b'K',
        }
    }

    /// Serialized frame. Fails when the payload exceeds [`MAX_FRAME`].
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let payload: Vec<u8> = match self {
            Frame::Hello(b) | Frame::Stdout(b) | Frame::Stderr(b) | Frame::Stdin(b) => b.clone(),
            Frame::Pid(p) => p.to_le_bytes().to_vec(),
            Frame::Exit(c) => c.to_le_bytes().to_vec(),
            Frame::Fatal(code, msg) => {
                let mut v = vec![*code as u8];
                v.extend_from_slice(msg.as_bytes());
                v.truncate(MAX_FRAME);
                v
            }
            Frame::Stop | Frame::Kill => Vec::new(),
        };
        if payload.len() > MAX_FRAME {
            return Err(invalid("frame too large"));
        }
        let len = u32::try_from(payload.len()).map_err(|_| invalid("frame too large"))?;
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(self.tag());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    fn decode(tag: u8, payload: Vec<u8>) -> io::Result<Frame> {
        let fixed4 =
            |p: &[u8]| -> io::Result<[u8; 4]> { p.try_into().map_err(|_| invalid("bad frame length")) };
        let empty = |p: &[u8], f: Frame| {
            if p.is_empty() {
                Ok(f)
            } else {
                Err(invalid("bad frame length"))
            }
        };
        match tag {
            b'H' => Ok(Frame::Hello(payload)),
            b'P' => Ok(Frame::Pid(u32::from_le_bytes(fixed4(&payload)?))),
            b'O' => Ok(Frame::Stdout(payload)),
            b'E' => Ok(Frame::Stderr(payload)),
            b'X' => Ok(Frame::Exit(i32::from_le_bytes(fixed4(&payload)?))),
            b'F' => {
                let (&code, msg) = payload.split_first().ok_or_else(|| invalid("bad frame length"))?;
                let code = match code {
                    1 => FatalCode::Refused,
                    2 => FatalCode::SpawnFailed,
                    _ => return Err(invalid("unknown fatal code")),
                };
                Ok(Frame::Fatal(code, String::from_utf8_lossy(msg).into_owned()))
            }
            b'I' => Ok(Frame::Stdin(payload)),
            b'S' => empty(&payload, Frame::Stop),
            b'K' => empty(&payload, Frame::Kill),
            _ => Err(invalid(format!("unknown frame tag {tag:#04x}"))),
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, frame: &Frame) -> io::Result<()> {
    w.write_all(&frame.encode()?).await?;
    w.flush().await
}

async fn read_header<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> io::Result<Option<(u8, usize)>> {
    let mut tag = [0u8; 1];
    if r.read(&mut tag).await? == 0 {
        return Ok(None);
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_le_bytes(len)).map_err(|_| invalid("frame too large"))?;
    Ok(Some((tag[0], len)))
}

async fn read_payload<R: AsyncRead + Unpin + ?Sized>(r: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Next frame, or `None` on a clean EOF between frames. Not cancel-safe: read from a dedicated
/// task, not inside `select!`.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> io::Result<Option<Frame>> {
    let Some((tag, len)) = read_header(r).await? else {
        return Ok(None);
    };
    if len > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    let payload = read_payload(r, len).await?;
    Frame::decode(tag, payload).map(Some)
}

/// Why a client was dropped before authenticating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    Closed,
    NotHello,
    Oversized,
    WrongToken,
    Io(String),
}

/// Reads the first frame and checks it is a hello carrying `token` (constant-time compare).
pub async fn read_hello<R: AsyncRead + Unpin + ?Sized>(r: &mut R, token: &str) -> Result<(), HelloError> {
    let (tag, len) = read_header(r)
        .await
        .map_err(|e| HelloError::Io(e.to_string()))?
        .ok_or(HelloError::Closed)?;
    if tag != b'H' {
        return Err(HelloError::NotHello);
    }
    if len > MAX_HELLO {
        return Err(HelloError::Oversized);
    }
    let got = read_payload(r, len)
        .await
        .map_err(|e| HelloError::Io(e.to_string()))?;
    if ct_eq(&got, token.as_bytes()) {
        Ok(())
    } else {
        Err(HelloError::WrongToken)
    }
}

/// Waits for a connection from `incoming` that presents `token` within `hello_timeout` of being
/// accepted. Clients with a wrong token, an oversized or a late hello are dropped and waiting
/// continues; at most [`MAX_CONNECTIONS`] unauthenticated clients are handled at once. Returns
/// `None` when `incoming` closes without a winner. Once this returns, `incoming` is dropped, so
/// the acceptor stops and late clients are dropped. The overall deadline is the caller's.
pub async fn wait_for_client<S>(
    mut incoming: mpsc::Receiver<S>,
    token: &str,
    hello_timeout: Duration,
) -> Option<S>
where
    S: AsyncRead + Unpin + Send + 'static,
{
    let token: Arc<str> = Arc::from(token);
    let mut pending: JoinSet<Option<S>> = JoinSet::new();
    let mut open = true;
    loop {
        tokio::select! {
            conn = incoming.recv(), if open => match conn {
                Some(mut s) => {
                    if pending.len() >= MAX_CONNECTIONS {
                        continue; // dropped
                    }
                    let token = token.clone();
                    pending.spawn(async move {
                        match tokio::time::timeout(hello_timeout, read_hello(&mut s, &token)).await {
                            Ok(Ok(())) => Some(s),
                            _ => None,
                        }
                    });
                }
                None => open = false,
            },
            Some(done) = pending.join_next(), if !pending.is_empty() => {
                if let Ok(Some(s)) = done {
                    return Some(s); // dropping `pending` aborts the other handshakes
                }
            }
            else => return None,
        }
    }
}

/// Parameters for `gp-connect-helper.exe` (as passed to `ShellExecuteExW`).
pub fn helper_parameters(config_path: &str, sha256: &str) -> String {
    format!(
        "--config {} --sha256 {sha256}",
        crate::quote::quote_windows_arg(config_path)
    )
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn hello(s: &mut DuplexStream, token: &str) {
        write_frame(s, &Frame::Hello(token.as_bytes().to_vec()))
            .await
            .unwrap();
    }

    /// Resolves when the peer of `s` is gone.
    async fn closed(s: &mut DuplexStream) {
        let mut buf = [0u8; 16];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame::Hello(b"tok".to_vec()),
            Frame::Pid(4242),
            Frame::Stdout(b"out".to_vec()),
            Frame::Stderr(vec![]),
            Frame::Exit(-1_073_741_510),
            Frame::Fatal(FatalCode::Refused, "nope".into()),
            Frame::Fatal(FatalCode::SpawnFailed, String::new()),
            Frame::Stdin(b"secret\n".to_vec()),
            Frame::Stop,
            Frame::Kill,
        ];
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let mut buf = Vec::new();
            for f in &frames {
                write_frame(&mut buf, f).await.unwrap();
            }
            let mut r = buf.as_slice();
            for f in &frames {
                assert_eq!(read_frame(&mut r).await.unwrap().as_ref(), Some(f));
            }
            assert_eq!(read_frame(&mut r).await.unwrap(), None);
        });
    }

    #[tokio::test]
    async fn rejects_malformed_frames() {
        for bad in [
            &b"Z\0\0\0\0"[..],         // unknown tag
            &b"P\x02\0\0\0ab"[..],     // pid of the wrong size
            &b"S\x01\0\0\0x"[..],      // stop with payload
            &b"F\0\0\0\0"[..],         // fatal without code
            &b"O\xff\xff\xff\x7f"[..], // oversized
            &b"O\x05\0\0\0ab"[..],     // truncated
        ] {
            let mut r = bad;
            assert!(read_frame(&mut r).await.is_err(), "{bad:?}");
        }
        assert!(Frame::Stdout(vec![0; MAX_FRAME + 1]).encode().is_err());
    }

    #[test]
    fn validates_names_tokens_and_builds_the_helper_command_line() {
        assert!(is_valid_pipe_name("gp-connect-0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_pipe_name("gp-connect-0123456789ABCDEF0123456789abcdef"));
        assert!(!is_valid_pipe_name("gp-connect-0123"));
        assert!(!is_valid_pipe_name("other-0123456789abcdef0123456789abcdef"));
        assert!(is_valid_sha256(&sha256_hex(b"x")));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let name = format!("{PIPE_PREFIX}{}", random_hex(16).unwrap());
        assert!(is_valid_pipe_name(&name));
        assert_eq!(pipe_path("gp-connect-x"), r"\\.\pipe\gp-connect-x");
        assert_eq!(
            helper_parameters(r"C:\Users\A B\AppData\Local\Temp\gp-connect-1\helper.json", "ab"),
            r#"--config "C:\Users\A B\AppData\Local\Temp\gp-connect-1\helper.json" --sha256 ab"#
        );
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn config_rejects_unknown_fields_and_bad_formats() {
        let cfg = HelperConfig {
            pipe: format!("{PIPE_PREFIX}{}", "0".repeat(32)),
            token: TOKEN.into(),
            binary: r"C:\Program Files\OpenConnect\openconnect.exe".into(),
            args: vec!["--protocol=gp".into()],
            script: None,
            server_pid: 1234,
        };
        assert_eq!(cfg.check_format(), Ok(()));
        assert!(
            serde_json::to_string(&cfg)
                .unwrap()
                .contains("\"serverPid\":1234")
        );
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"pipe\":") && json.contains("\"script\":null"));
        assert_eq!(serde_json::from_str::<HelperConfig>(&json).unwrap(), cfg);
        assert!(serde_json::from_str::<HelperConfig>(&json.replace("\"script\"", "\"env\"")).is_err());
        let mut bad = cfg.clone();
        bad.token = "x".into();
        assert!(bad.check_format().is_err());
        let mut bad = cfg.clone();
        bad.pipe = "gp-connect-../../x".into();
        assert!(bad.check_format().is_err());
        let mut bad = cfg;
        bad.server_pid = 0;
        assert!(bad.check_format().is_err());
    }

    #[tokio::test]
    async fn drops_an_idle_client_after_the_hello_deadline_and_still_accepts_the_real_one() {
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let waiter =
            tokio::spawn(async move { wait_for_client(rx, TOKEN, Duration::from_millis(100)).await });
        let (mut idle, idle_server) = duplex(1024);
        tx.send(idle_server).await.unwrap();
        closed(&mut idle).await; // dropped by the deadline
        let (mut real, real_server) = duplex(1024);
        tx.send(real_server).await.unwrap();
        hello(&mut real, TOKEN).await;
        write_frame(&mut real, &Frame::Pid(7)).await.unwrap();
        let mut won = waiter.await.unwrap().expect("authenticated client");
        // Data after the hello stays in the stream.
        assert_eq!(read_frame(&mut won).await.unwrap(), Some(Frame::Pid(7)));
    }

    #[tokio::test]
    async fn drops_a_client_with_a_wrong_token_and_keeps_listening() {
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let waiter = tokio::spawn(async move { wait_for_client(rx, TOKEN, Duration::from_secs(1)).await });
        let (mut bad, bad_server) = duplex(1024);
        tx.send(bad_server).await.unwrap();
        hello(&mut bad, &"b".repeat(64)).await;
        closed(&mut bad).await;
        let (mut short, short_server) = duplex(1024);
        tx.send(short_server).await.unwrap();
        hello(&mut short, &TOKEN[..63]).await;
        closed(&mut short).await;
        let (mut real, real_server) = duplex(1024);
        tx.send(real_server).await.unwrap();
        hello(&mut real, TOKEN).await;
        assert!(waiter.await.unwrap().is_some());
    }

    #[tokio::test]
    async fn drops_oversized_hellos_and_late_clients_after_a_winner() {
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let waiter = tokio::spawn(async move { wait_for_client(rx, TOKEN, Duration::from_secs(1)).await });
        let (mut garbage, garbage_server) = duplex(1024);
        tx.send(garbage_server).await.unwrap();
        garbage.write_all(&[b'x'; 300]).await.unwrap();
        closed(&mut garbage).await;
        let (mut big, big_server) = duplex(1024);
        tx.send(big_server).await.unwrap();
        big.write_all(b"H\x2c\x01\0\0").await.unwrap(); // hello of 300 bytes
        closed(&mut big).await;
        let (mut real, real_server) = duplex(1024);
        tx.send(real_server).await.unwrap();
        hello(&mut real, TOKEN).await;
        assert!(waiter.await.unwrap().is_some());
        let (mut late, late_server) = duplex(1024);
        // The receiver is gone: the acceptor gets the connection back and drops it.
        let rejected = tx.send(late_server).await.unwrap_err();
        drop(rejected);
        closed(&mut late).await;
    }

    #[tokio::test]
    async fn limits_concurrent_unauthenticated_clients_and_ends_when_incoming_closes() {
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS * 2);
        let waiter = tokio::spawn(async move { wait_for_client(rx, TOKEN, Duration::from_secs(5)).await });
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let (c, s) = duplex(64);
            tx.send(s).await.unwrap();
            idle.push(c);
        }
        tokio::task::yield_now().await;
        let (mut extra, extra_server) = duplex(64);
        tx.send(extra_server).await.unwrap();
        closed(&mut extra).await; // over the limit → dropped at once
        drop(tx);
        drop(idle); // all idle clients disconnect → handshakes fail → no winner
        assert!(waiter.await.unwrap().is_none());
    }
}
