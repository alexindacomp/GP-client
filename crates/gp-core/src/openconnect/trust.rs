//! Trust check for files that will be executed with administrator/root rights (the openconnect
//! binary, the HIP `--csd-wrapper` script).
//!
//! Unix: the real path (symlinks resolved) and every parent directory must be owned by root and
//! not writable by group/others.
//! Windows: the real path must be inside a Program Files directory registered in HKLM (never
//! taken from environment variables; %SystemRoot% is NOT accepted, it contains user-writable
//! folders such as C:\Windows\Temp), and the owner and ACL of the file and every parent up to
//! that root must grant write access only to SYSTEM, Administrators or TrustedInstaller.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;

use super::windows_acl::{WindowsSecurityProbe, acl_problem, paths_up_to};
use crate::clock::{Clock, SystemClock};
use crate::platform::Platform;
use crate::types::{VpnErrorCode, VpnErrorHint};
use crate::util::{posix, win};
use crate::vpn::VpnError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustStat {
    pub uid: u32,
    pub mode: u32,
    pub is_file: bool,
    pub is_dir: bool,
}

/// Filesystem access used by the check (injected in tests).
#[async_trait]
pub trait TrustFs: Send + Sync {
    /// Canonical path with symlinks resolved (on Windows without the `\\?\` prefix).
    async fn realpath(&self, p: &str) -> io::Result<String>;
    async fn stat(&self, p: &str) -> io::Result<TrustStat>;
    /// Entry names of a directory (used by [`verify_windows_install_dir`]). The default fails,
    /// so an implementation that does not support listing fails that check closed.
    async fn read_dir(&self, p: &str) -> io::Result<Vec<String>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("cannot list {p}"),
        ))
    }
}

/// The real filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdTrustFs;

/// Simplifies a verbatim local drive path (`\\?\C:\x`, what `std::fs::canonicalize` and Tauri's
/// `current_exe`/`resource_dir` return on Windows) to `C:\x`. Every other `\\`-prefixed form —
/// `\\?\UNC\…`, `\\?\Volume{…}\…`, `\\?\GLOBALROOT\…`, `\\.\…`, `\\server\…` — is returned
/// unchanged, so the Windows trust check keeps rejecting it.
pub fn strip_verbatim_prefix(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            return rest.to_string();
        }
    }
    p.to_string()
}

#[async_trait]
impl TrustFs for StdTrustFs {
    async fn realpath(&self, p: &str) -> io::Result<String> {
        let path = p.to_string();
        let real = tokio::task::spawn_blocking(move || std::fs::canonicalize(path))
            .await
            .map_err(io::Error::other)??;
        Ok(strip_verbatim_prefix(&real.to_string_lossy()))
    }

    async fn stat(&self, p: &str) -> io::Result<TrustStat> {
        let path = p.to_string();
        let md = tokio::task::spawn_blocking(move || std::fs::metadata(path))
            .await
            .map_err(io::Error::other)??;
        #[cfg(unix)]
        let (uid, mode) = {
            use std::os::unix::fs::MetadataExt;
            (md.uid(), md.mode())
        };
        #[cfg(not(unix))]
        let (uid, mode) = (0, 0);
        Ok(TrustStat {
            uid,
            mode,
            is_file: md.is_file(),
            is_dir: md.is_dir(),
        })
    }

    async fn read_dir(&self, p: &str) -> io::Result<Vec<String>> {
        let path = p.to_string();
        tokio::task::spawn_blocking(move || {
            std::fs::read_dir(path)?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect()
        })
        .await
        .map_err(io::Error::other)?
    }
}

/// The file must not be run elevated. Converts into a `PRIVILEGES_DENIED` [`VpnError`] with the
/// `untrusted_binary` / `untrusted_homebrew` hint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct UntrustedPathError {
    pub file_path: String,
    pub reason: String,
    pub message: String,
    pub hint: VpnErrorHint,
}

impl UntrustedPathError {
    pub fn new(file_path: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let homebrew = file_path.contains("/opt/homebrew") || file_path.starts_with("/usr/local/");
        let advice = if homebrew {
            "Homebrew installs are user-writable; install OpenConnect with MacPorts (sudo port install openconnect)"
        } else {
            "install it to a location only administrators can modify"
        };
        UntrustedPathError {
            file_path: file_path.to_string(),
            message: format!("Refusing to run \"{file_path}\" with administrator rights: {reason}. {advice}"),
            reason,
            hint: if homebrew {
                VpnErrorHint::UntrustedHomebrew
            } else {
                VpnErrorHint::UntrustedBinary
            },
        }
    }
}

impl From<UntrustedPathError> for VpnError {
    fn from(e: UntrustedPathError) -> Self {
        VpnError::new(VpnErrorCode::PrivilegesDenied, e.message).with_hint(e.hint)
    }
}

#[derive(Clone)]
pub struct TrustOptions {
    pub platform: Platform,
    pub fs: Arc<dyn TrustFs>,
    /// Windows: registry/ACL probe. Without one, every Windows check fails closed.
    pub windows_probe: Option<Arc<dyn WindowsSecurityProbe>>,
}

impl TrustOptions {
    /// Real filesystem; `windows_probe` must be supplied on Windows.
    pub fn new(platform: Platform, windows_probe: Option<Arc<dyn WindowsSecurityProbe>>) -> Self {
        TrustOptions {
            platform,
            fs: Arc::new(StdTrustFs),
            windows_probe,
        }
    }
}

impl std::fmt::Debug for TrustOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustOptions")
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

const GROUP_OR_WORLD_WRITABLE: u32 = 0o022;

async fn verify_unix(file: &str, fs: &dyn TrustFs) -> Result<String, UntrustedPathError> {
    let unexpected = |e: io::Error| UntrustedPathError::new(file, e.to_string());
    let real = fs
        .realpath(file)
        .await
        .map_err(|_| UntrustedPathError::new(file, "file does not exist"))?;
    let st = fs.stat(&real).await.map_err(unexpected)?;
    if !st.is_file {
        return Err(UntrustedPathError::new(file, "not a regular file"));
    }
    let check = |p: &str, s: &TrustStat| {
        if s.uid != 0 {
            return Err(UntrustedPathError::new(file, format!("{p} is not owned by root")));
        }
        if s.mode & GROUP_OR_WORLD_WRITABLE != 0 {
            return Err(UntrustedPathError::new(
                file,
                format!("{p} is writable by group or others"),
            ));
        }
        Ok(())
    };
    check(&real, &st)?;
    let mut dir = posix::dirname(&real);
    loop {
        let ds = fs.stat(&dir).await.map_err(unexpected)?;
        if !ds.is_dir {
            return Err(UntrustedPathError::new(file, format!("{dir} is not a directory")));
        }
        check(&dir, &ds)?;
        let parent = posix::dirname(&dir);
        if parent == dir {
            break;
        }
        dir = parent;
    }
    Ok(real)
}

fn normalize_root(r: &str) -> String {
    win::normalize(r).trim_end_matches(['\\', '/']).to_string()
}

async fn verify_windows(
    file: &str,
    fs: &dyn TrustFs,
    probe: Option<&dyn WindowsSecurityProbe>,
) -> Result<String, UntrustedPathError> {
    // Local paths may arrive in verbatim form (e.g. derived from Tauri's resource dir).
    let local = strip_verbatim_prefix(file);
    let file = local.as_str();
    if !win::is_absolute(file) || file.starts_with(r"\\") || file.starts_with("//") {
        return Err(UntrustedPathError::new(
            file,
            "path must be a local absolute path",
        ));
    }
    let real = fs
        .realpath(file)
        .await
        .map_err(|_| UntrustedPathError::new(file, "file does not exist"))?;
    let real = win::normalize(&real);
    if real.starts_with(r"\\") {
        return Err(UntrustedPathError::new(file, "network paths are not allowed"));
    }
    let st = fs
        .stat(&real)
        .await
        .map_err(|e| UntrustedPathError::new(file, e.to_string()))?;
    if !st.is_file {
        return Err(UntrustedPathError::new(file, "not a regular file"));
    }
    let Some(probe) = probe else {
        return Err(UntrustedPathError::new(file, "ACL check is not available"));
    };
    let fail = |e: String| UntrustedPathError::new(file, e);

    // First call: registered Program Files roots (+ ACL of the file itself).
    let first = probe.probe(std::slice::from_ref(&real)).await.map_err(fail)?;
    let lower = real.to_lowercase();
    let root = first
        .program_files
        .iter()
        .filter(|r| win::is_absolute(r))
        .map(|r| normalize_root(r))
        .find(|r| lower.starts_with(&format!("{}\\", r.to_lowercase())));
    let Some(root) = root else {
        return Err(UntrustedPathError::new(
            file,
            "it must be installed under \"Program Files\" (admin-only folder)",
        ));
    };
    let chain = paths_up_to(&real, &root);
    let items = probe.probe(&chain).await.map_err(fail)?.items;
    if items.len() != chain.len() {
        return Err(UntrustedPathError::new(file, "could not read permissions"));
    }
    if let Some(problem) = items.iter().find_map(acl_problem) {
        return Err(UntrustedPathError::new(file, problem));
    }
    Ok(real)
}

/// Resolves `file` to its real path and verifies it is admin-controlled.
pub async fn verify_trusted_file(file: &str, opts: &TrustOptions) -> Result<String, UntrustedPathError> {
    match opts.platform {
        Platform::Win32 => verify_windows(file, opts.fs.as_ref(), opts.windows_probe.as_deref()).await,
        _ if !posix::is_absolute(file) => Err(UntrustedPathError::new(file, "path must be absolute")),
        _ => verify_unix(file, opts.fs.as_ref()).await,
    }
}

/// Files next to openconnect.exe that it loads or runs (DLLs, helper executables, the default
/// `vpnc-script-win.js`).
const WINDOWS_SIBLING_EXTENSIONS: [&str; 3] = [".dll", ".exe", ".js"];

/// Windows: the owner/ACL of every DLL, executable and script directly in the directory of the
/// (already verified, real-path) openconnect binary must be admin-only too — a writable
/// `vpnc-script-win.js` or `*.dll` next to a trusted exe would run as administrator. No-op on
/// other platforms (Unix directories are owned by root, so their entries cannot be replaced).
pub async fn verify_windows_install_dir(
    real_binary: &str,
    opts: &TrustOptions,
) -> Result<(), UntrustedPathError> {
    if opts.platform != Platform::Win32 {
        return Ok(());
    }
    let Some(probe) = opts.windows_probe.as_deref() else {
        return Err(UntrustedPathError::new(real_binary, "ACL check is not available"));
    };
    let dir = win::dirname(real_binary);
    let names = opts
        .fs
        .read_dir(&dir)
        .await
        .map_err(|e| UntrustedPathError::new(real_binary, format!("cannot list {dir}: {e}")))?;
    let mut files: Vec<String> = names
        .iter()
        .filter(|n| {
            let lower = n.to_lowercase();
            WINDOWS_SIBLING_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
        })
        .map(|n| win::join(&dir, n))
        .collect();
    files.sort();
    if files.is_empty() {
        return Ok(());
    }
    let items = probe
        .probe(&files)
        .await
        .map_err(|e| UntrustedPathError::new(real_binary, e))?
        .items;
    if items.len() != files.len() {
        return Err(UntrustedPathError::new(real_binary, "could not read permissions"));
    }
    if let Some(problem) = items.iter().find_map(acl_problem) {
        return Err(UntrustedPathError::new(real_binary, problem));
    }
    Ok(())
}

/// `true` when [`verify_trusted_file`] would accept the file.
pub async fn is_trusted_file(file: &str, opts: &TrustOptions) -> bool {
    verify_trusted_file(file, opts).await.is_ok()
}

/// Async yes/no trust decision (used by discovery).
#[async_trait]
pub trait TrustCheck: Send + Sync {
    async fn is_trusted(&self, file: &str) -> bool;
}

/// Uncached check.
#[async_trait]
impl TrustCheck for TrustOptions {
    async fn is_trusted(&self, file: &str) -> bool {
        is_trusted_file(file, self).await
    }
}

pub type MtimeFn = Arc<dyn Fn(&str) -> io::Result<i64> + Send + Sync>;

/// Modification time in ms of a real file.
pub fn std_mtime(p: &str) -> io::Result<i64> {
    let modified = std::fs::metadata(p)?.modified()?;
    let ms = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    Ok(i64::try_from(ms).unwrap_or(i64::MAX))
}

struct CacheEntry {
    key: String,
    ok: bool,
    at: i64,
}

/// Memoised [`is_trusted_file`] for discovery/UI (`system.info()` is called often; on Windows
/// each check reads ACLs). Keyed by path + mtime with a short TTL. Never use it for the check
/// right before elevation.
pub struct TrustCache {
    opts: TrustOptions,
    ttl_ms: i64,
    clock: Arc<dyn Clock>,
    mtime_of: MtimeFn,
    cache: Mutex<Vec<CacheEntry>>,
}

pub const TRUST_CACHE_TTL_MS: i64 = 30_000;
const TRUST_CACHE_MAX: usize = 64;

impl TrustCache {
    pub fn new(opts: TrustOptions) -> Self {
        Self::with(
            opts,
            TRUST_CACHE_TTL_MS,
            Arc::new(SystemClock),
            Arc::new(std_mtime),
        )
    }

    pub fn with(opts: TrustOptions, ttl_ms: i64, clock: Arc<dyn Clock>, mtime_of: MtimeFn) -> Self {
        TrustCache {
            opts,
            ttl_ms,
            clock,
            mtime_of,
            cache: Mutex::new(Vec::new()),
        }
    }

    pub async fn check(&self, file: &str) -> bool {
        let Ok(mtime) = (self.mtime_of)(file) else {
            return false;
        };
        let key = format!("{file}\0{mtime}");
        {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(hit) = cache.iter().find(|e| e.key == key)
                && self.clock.now_ms() - hit.at < self.ttl_ms
            {
                return hit.ok;
            }
        }
        let ok = is_trusted_file(file, &self.opts).await;
        let at = self.clock.now_ms();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = cache.iter_mut().find(|e| e.key == key) {
            e.ok = ok;
            e.at = at;
        } else {
            cache.push(CacheEntry { key, ok, at });
            if cache.len() > TRUST_CACHE_MAX {
                cache.remove(0);
            }
        }
        ok
    }
}

#[async_trait]
impl TrustCheck for TrustCache {
    async fn is_trusted(&self, file: &str) -> bool {
        self.check(file).await
    }
}

#[cfg(test)]
mod tests;
