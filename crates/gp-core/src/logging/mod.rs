//! Application log: secret masking, an in-memory ring buffer of the
//! last N lines, a size-rotated log file and line listeners (for `gp:logs:line`).

mod mask;

pub use mask::{MASK, SecretRegistry, mask_secrets};

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::clock::{Clock, SystemClock, iso_timestamp};

pub const DEFAULT_CAPACITY: usize = 2000;
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
pub const LOG_FILE_NAME: &str = "gp-connect.log";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Fixed-capacity ring buffer of log lines.
#[derive(Debug)]
pub struct LogBuffer {
    lines: VecDeque<String>,
    capacity: usize,
}

impl LogBuffer {
    /// # Panics
    /// When `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "LogBuffer capacity must be a positive integer, got {capacity}"
        );
        LogBuffer {
            lines: VecDeque::with_capacity(capacity.min(4096)),
            capacity,
        }
    }

    pub fn push(&mut self, line: String) {
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn label(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO ",
            LogLevel::Warn => "WARN ",
            LogLevel::Error => "ERROR",
        }
    }
}

type Listener = Arc<dyn Fn(&str) + Send + Sync>;

struct FileSink {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
}

impl FileSink {
    fn open(dir: &Path) -> FileSink {
        let path = dir.join(LOG_FILE_NAME);
        let mut sink = FileSink {
            path,
            file: None,
            bytes: 0,
        };
        sink.reopen(dir);
        sink
    }

    fn reopen(&mut self, dir: &Path) {
        // Disk full / permissions: the in-memory log keeps working without a file.
        self.file = create_private_dir(dir)
            .ok()
            .and_then(|()| open_append_private(&self.path).ok());
        self.bytes = fs::metadata(&self.path).map_or(0, |m| m.len());
    }

    fn append(&mut self, line: &str) {
        let Some(f) = self.file.as_mut() else { return };
        let data = format!("{line}\n");
        if f.write_all(data.as_bytes()).is_err() {
            self.file = None;
            return;
        }
        self.bytes += data.len() as u64;
        if self.bytes >= MAX_FILE_BYTES {
            self.rotate();
        }
    }

    fn rotate(&mut self) {
        self.file = None;
        let mut rotated = self.path.clone().into_os_string();
        rotated.push(".1");
        // On failure we keep appending to the current file.
        let _ = fs::rename(&self.path, rotated);
        if let Some(dir) = self.path.parent().map(Path::to_path_buf) {
            self.reopen(&dir);
        }
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn open_append_private(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Masks secrets, keeps the last N lines in memory, appends to `<logs_dir>/gp-connect.log`
/// (rotated to `.1` at 5 MiB) and notifies listeners. Thread-safe; share it via `Arc`.
pub struct Logger {
    secrets: SecretRegistry,
    buffer: Mutex<LogBuffer>,
    listeners: Mutex<Vec<(u64, Listener)>>,
    next_listener: Mutex<u64>,
    file: Mutex<Option<FileSink>>,
    clock: Arc<dyn Clock>,
}

/// Handle returned by [`Logger::on_line`]; pass it to [`Logger::off_line`] to unsubscribe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerId(u64);

impl Logger {
    /// `logs_dir = None` keeps the log in memory only.
    pub fn new(logs_dir: Option<&Path>, capacity: usize) -> Self {
        Self::with_clock(logs_dir, capacity, Arc::new(SystemClock))
    }

    pub fn with_clock(logs_dir: Option<&Path>, capacity: usize, clock: Arc<dyn Clock>) -> Self {
        Logger {
            secrets: SecretRegistry::new(),
            buffer: Mutex::new(LogBuffer::new(capacity)),
            listeners: Mutex::new(Vec::new()),
            next_listener: Mutex::new(0),
            file: Mutex::new(logs_dir.map(FileSink::open)),
            clock,
        }
    }

    /// In-memory logger with the default capacity (tests, early startup).
    pub fn in_memory() -> Self {
        Self::new(None, DEFAULT_CAPACITY)
    }

    pub fn secrets(&self) -> &SecretRegistry {
        &self.secrets
    }

    pub fn file_path(&self) -> Option<PathBuf> {
        lock(&self.file).as_ref().map(|s| s.path.clone())
    }

    pub fn debug(&self, source: &str, msg: &str) {
        self.write(LogLevel::Debug, source, msg);
    }
    pub fn info(&self, source: &str, msg: &str) {
        self.write(LogLevel::Info, source, msg);
    }
    pub fn warn(&self, source: &str, msg: &str) {
        self.write(LogLevel::Warn, source, msg);
    }
    pub fn error(&self, source: &str, msg: &str) {
        self.write(LogLevel::Error, source, msg);
    }

    /// Writes one entry; multi-line messages become separate lines, blank lines are skipped.
    pub fn write(&self, level: LogLevel, source: &str, msg: &str) {
        let ts = iso_timestamp(self.clock.now_ms());
        for raw in msg.split('\n') {
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            if raw.trim().is_empty() {
                continue;
            }
            let line = format!("{ts} {} [{source}] {}", level.label(), self.secrets.mask(raw));
            lock(&self.buffer).push(line.clone());
            if let Some(sink) = lock(&self.file).as_mut() {
                sink.append(&line);
            }
            let listeners: Vec<Listener> = lock(&self.listeners).iter().map(|(_, l)| l.clone()).collect();
            for l in listeners {
                l(&line);
            }
        }
    }

    pub fn lines(&self) -> Vec<String> {
        lock(&self.buffer).snapshot()
    }

    /// Called for every line, on the logging thread. Listeners must not panic (release builds use
    /// `panic = "abort"`) and must not log themselves.
    pub fn on_line(&self, listener: impl Fn(&str) + Send + Sync + 'static) -> ListenerId {
        let mut n = lock(&self.next_listener);
        *n += 1;
        lock(&self.listeners).push((*n, Arc::new(listener)));
        ListenerId(*n)
    }

    pub fn off_line(&self, id: ListenerId) {
        lock(&self.listeners).retain(|(n, _)| *n != id.0);
    }

    /// Closes the log file (further lines stay in memory only).
    pub fn close(&self) {
        *lock(&self.file) = None;
    }
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger")
            .field("file", &self.file_path())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_buffer_keeps_only_the_last_n_lines() {
        let mut b = LogBuffer::new(3);
        for i in 1..=5 {
            b.push(format!("l{i}"));
        }
        assert_eq!(b.snapshot(), ["l3", "l4", "l5"]);
        assert_eq!(b.len(), 3);
    }

    #[test]
    #[should_panic(expected = "positive integer")]
    fn log_buffer_rejects_zero_capacity() {
        let _ = LogBuffer::new(0);
    }

    #[test]
    fn masks_registered_secrets_before_buffering_and_notifying() {
        let logger = Logger::new(None, 10);
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let s = seen.clone();
        logger.on_line(move |l| s.lock().unwrap().push(l.to_string()));
        logger.secrets().add("MyP@ssw0rd");
        logger.info("test", "sending MyP@ssw0rd\nprelogin-cookie=zzz");
        let lines = logger.lines();
        assert_eq!(lines.len(), 2);
        assert!(!lines.join("\n").contains("MyP@ssw0rd"));
        assert!(!lines.join("\n").contains("zzz"));
        assert_eq!(*seen.lock().unwrap(), lines);
    }

    #[test]
    fn caps_the_buffer_at_2000_lines_by_default() {
        let logger = Logger::in_memory();
        for i in 0..2100 {
            logger.info("t", &format!("line {i}"));
        }
        let lines = logger.lines();
        assert_eq!(lines.len(), 2000);
        assert!(lines[0].contains("line 100"));
    }

    #[test]
    fn line_format_has_iso_timestamp_level_and_source() {
        let logger = Logger::with_clock(None, 10, Arc::new(crate::clock::FixedClock(0)));
        logger.warn("vpn", "hello");
        logger.error("vpn", "bad\r\n\r\n");
        assert_eq!(
            logger.lines(),
            [
                "1970-01-01T00:00:00.000Z WARN  [vpn] hello",
                "1970-01-01T00:00:00.000Z ERROR [vpn] bad"
            ]
        );
    }

    #[test]
    fn listeners_get_every_line_until_unsubscribed() {
        let logger = Logger::in_memory();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let id = logger.on_line(move |l| sink.lock().unwrap().push(l.to_string()));
        logger.info("t", "one");
        logger.off_line(id);
        logger.info("t", "two");
        assert_eq!(logger.lines().len(), 2);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].ends_with("[t] one"));
    }

    #[test]
    fn writes_a_private_file_and_rotates_at_5_mib() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let logger = Logger::new(Some(&logs), 10);
        logger.secrets().add("hunter2-secret");
        logger.info("t", "first hunter2-secret");
        let file = logger.file_path().unwrap();
        let content = fs::read_to_string(&file).unwrap();
        assert!(content.contains("[t] first ***"));
        assert!(!content.contains("hunter2-secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&logs).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let big = "x".repeat(64 * 1024);
        for _ in 0..90 {
            logger.info("t", &big);
        }
        let rotated = logs.join(format!("{LOG_FILE_NAME}.1"));
        assert!(rotated.exists());
        assert!(fs::metadata(&rotated).unwrap().len() >= MAX_FILE_BYTES);
        assert!(fs::metadata(&file).unwrap().len() < MAX_FILE_BYTES);
        logger.close();
        logger.info("t", "after close");
        assert!(!fs::read_to_string(&file).unwrap().contains("after close"));
    }
}
