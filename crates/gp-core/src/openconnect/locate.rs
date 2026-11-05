//! Finding the openconnect binary.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::trust::TrustCheck;
use crate::platform::Platform;
use crate::util::{posix, win};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpenconnectSource {
    Settings,
    Bundled,
    Path,
    WellKnown,
}

impl OpenconnectSource {
    pub fn as_str(self) -> &'static str {
        match self {
            OpenconnectSource::Settings => "settings",
            OpenconnectSource::Bundled => "bundled",
            OpenconnectSource::Path => "path",
            OpenconnectSource::WellKnown => "well-known",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedBinary {
    pub path: String,
    pub source: OpenconnectSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateResult {
    pub path: String,
    pub source: OpenconnectSource,
    /// False when the binary is not admin-controlled; connecting will be refused.
    pub trusted: bool,
}

pub type IsExecutableFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[derive(Clone, Default)]
pub struct LocateOptions {
    pub platform: Option<Platform>,
    /// User-configured path from settings (highest priority).
    pub configured_path: Option<String>,
    /// Directory with bundled binaries: `<resources>/bin` — `<platform>/openconnect[.exe]` inside.
    pub bundled_bin_dir: Option<String>,
    /// Value of the PATH environment variable.
    pub env_path: Option<String>,
    /// Overridable for tests; default: regular file (+ executable bit on Unix).
    pub is_executable: Option<IsExecutableFn>,
    /// Whether a candidate may be run with administrator rights. Trusted candidates win over
    /// untrusted ones regardless of order, so a binary planted in a user-writable PATH directory
    /// cannot shadow the system one. Default: everything is trusted.
    pub is_trusted: Option<Arc<dyn TrustCheck>>,
}

pub fn executable_name(platform: Platform) -> &'static str {
    if platform == Platform::Win32 {
        "openconnect.exe"
    } else {
        "openconnect"
    }
}

/// Directories where package managers install openconnect but that are often missing from PATH
/// of GUI apps (Finder/Dock launches get a minimal PATH; Ubuntu installs to /usr/sbin, which is
/// not in a regular user's PATH).
pub fn well_known_dirs(platform: Platform) -> &'static [&'static str] {
    match platform {
        Platform::Win32 => &[
            "C:\\Program Files\\OpenConnect",
            "C:\\Program Files\\OpenConnect-GUI",
            "C:\\Program Files (x86)\\OpenConnect",
            "C:\\Program Files (x86)\\OpenConnect-GUI",
        ],
        Platform::Darwin => &[
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/opt/local/bin",
            "/opt/local/sbin",
        ],
        Platform::Linux => &[
            "/usr/sbin",
            "/usr/bin",
            "/usr/local/sbin",
            "/usr/local/bin",
            "/sbin",
            "/bin",
        ],
    }
}

/// Regular file (and executable by us on Unix).
pub fn default_is_executable(p: &str) -> bool {
    let Ok(md) = std::fs::metadata(p) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Ordered candidate list: settings → bundled → PATH → well-known install dirs (deduplicated;
/// case-insensitively on Windows).
pub fn candidate_paths(opts: &LocateOptions) -> Vec<LocatedBinary> {
    let platform = opts.platform.unwrap_or_else(Platform::current);
    let exe = executable_name(platform);
    let is_win = platform == Platform::Win32;
    let is_abs = |p: &str| {
        if is_win {
            win::is_absolute(p)
        } else {
            posix::is_absolute(p)
        }
    };
    let join = |a: &str, b: &str| {
        if is_win {
            win::join(a, b)
        } else {
            posix::join(a, b)
        }
    };

    let mut out: Vec<LocatedBinary> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut add = |candidate: String, source: OpenconnectSource| {
        let key = if is_win {
            candidate.to_lowercase()
        } else {
            candidate.clone()
        };
        if !seen.contains(&key) {
            seen.push(key);
            out.push(LocatedBinary {
                path: candidate,
                source,
            });
        }
    };

    if let Some(c) = opts
        .configured_path
        .as_deref()
        .filter(|c| !c.is_empty() && is_abs(c))
    {
        add(c.to_string(), OpenconnectSource::Settings);
    }
    if let Some(dir) = opts.bundled_bin_dir.as_deref().filter(|d| !d.is_empty()) {
        add(
            join(&join(dir, platform.as_str()), exe),
            OpenconnectSource::Bundled,
        );
    }
    let sep = if is_win { ';' } else { ':' };
    for dir in opts.env_path.as_deref().unwrap_or("").split(sep) {
        let d = dir.trim();
        let d = d.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(d);
        if !d.is_empty() && is_abs(d) {
            add(join(d, exe), OpenconnectSource::Path);
        }
    }
    for dir in well_known_dirs(platform) {
        add(join(dir, exe), OpenconnectSource::WellKnown);
    }
    out
}

/// First executable candidate that passes the trust check; if none does, the first executable
/// one (reported as untrusted so the UI can explain why connecting is refused).
pub async fn locate_openconnect(opts: &LocateOptions) -> Option<LocateResult> {
    let default_exec: IsExecutableFn = Arc::new(default_is_executable);
    let is_executable = opts.is_executable.clone().unwrap_or(default_exec);
    let mut first_untrusted: Option<LocatedBinary> = None;
    for c in candidate_paths(opts) {
        if !is_executable(&c.path) {
            continue;
        }
        let trusted = match &opts.is_trusted {
            Some(t) => t.is_trusted(&c.path).await,
            None => true,
        };
        if trusted {
            return Some(LocateResult {
                path: c.path,
                source: c.source,
                trusted: true,
            });
        }
        first_untrusted.get_or_insert(c);
    }
    first_untrusted.map(|c| LocateResult {
        path: c.path,
        source: c.source,
        trusted: false,
    })
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    fn lb(path: &str, source: OpenconnectSource) -> LocatedBinary {
        LocatedBinary {
            path: path.into(),
            source,
        }
    }

    #[test]
    fn orders_candidates_settings_bundled_path_well_known() {
        let c = candidate_paths(&LocateOptions {
            platform: Some(Platform::Linux),
            configured_path: Some("/opt/oc/openconnect".into()),
            bundled_bin_dir: Some("/app/resources/bin".into()),
            env_path: Some("/usr/local/bin:relative/dir:/usr/bin".into()),
            ..Default::default()
        });
        assert_eq!(
            c[..4],
            [
                lb("/opt/oc/openconnect", OpenconnectSource::Settings),
                lb("/app/resources/bin/linux/openconnect", OpenconnectSource::Bundled),
                lb("/usr/local/bin/openconnect", OpenconnectSource::Path),
                lb("/usr/bin/openconnect", OpenconnectSource::Path),
            ]
        );
        assert!(c.contains(&lb("/usr/sbin/openconnect", OpenconnectSource::WellKnown)));
        assert_eq!(c.iter().filter(|x| x.path == "/usr/bin/openconnect").count(), 1);
    }

    #[test]
    fn uses_openconnect_exe_and_semicolons_on_windows() {
        let c = candidate_paths(&LocateOptions {
            platform: Some(Platform::Win32),
            env_path: Some("C:\\Tools;\"C:\\Quoted Dir\";c:\\program files\\openconnect".into()),
            ..Default::default()
        });
        assert_eq!(c[0], lb("C:\\Tools\\openconnect.exe", OpenconnectSource::Path));
        assert_eq!(
            c[1],
            lb("C:\\Quoted Dir\\openconnect.exe", OpenconnectSource::Path)
        );
        // case-insensitive dedupe against the well-known dir
        assert_eq!(
            c.iter()
                .filter(|x| x.path.to_lowercase() == "c:\\program files\\openconnect\\openconnect.exe")
                .count(),
            1
        );
    }

    fn exec_set(paths: &[&str]) -> IsExecutableFn {
        let set: Vec<String> = paths.iter().map(|s| (*s).to_string()).collect();
        Arc::new(move |p| set.iter().any(|s| s == p))
    }

    #[tokio::test]
    async fn returns_the_first_executable_candidate_or_none() {
        let found = locate_openconnect(&LocateOptions {
            platform: Some(Platform::Linux),
            configured_path: Some("/missing/openconnect".into()),
            env_path: Some("/usr/bin".into()),
            is_executable: Some(exec_set(&["/usr/sbin/openconnect"])),
            ..Default::default()
        })
        .await;
        assert_eq!(
            found,
            Some(LocateResult {
                path: "/usr/sbin/openconnect".into(),
                source: OpenconnectSource::WellKnown,
                trusted: true
            })
        );
        let none = locate_openconnect(&LocateOptions {
            platform: Some(Platform::Linux),
            env_path: Some(String::new()),
            is_executable: Some(Arc::new(|_| false)),
            ..Default::default()
        })
        .await;
        assert_eq!(none, None);
    }

    struct Prefix(&'static str);

    #[async_trait]
    impl TrustCheck for Prefix {
        async fn is_trusted(&self, file: &str) -> bool {
            file.starts_with(self.0)
        }
    }

    #[tokio::test]
    async fn prefers_a_trusted_binary_over_an_earlier_untrusted_path_hit() {
        let found = locate_openconnect(&LocateOptions {
            platform: Some(Platform::Linux),
            env_path: Some("/home/alice/bin:/usr/bin".into()),
            is_executable: Some(exec_set(&[
                "/home/alice/bin/openconnect",
                "/usr/sbin/openconnect",
            ])),
            is_trusted: Some(Arc::new(Prefix("/usr/"))),
            ..Default::default()
        })
        .await;
        assert_eq!(
            found,
            Some(LocateResult {
                path: "/usr/sbin/openconnect".into(),
                source: OpenconnectSource::WellKnown,
                trusted: true
            })
        );
    }

    #[tokio::test]
    async fn reports_an_untrusted_binary_when_nothing_trusted_exists() {
        let found = locate_openconnect(&LocateOptions {
            platform: Some(Platform::Darwin),
            env_path: Some("/opt/homebrew/bin".into()),
            is_executable: Some(exec_set(&["/opt/homebrew/bin/openconnect"])),
            is_trusted: Some(Arc::new(Prefix("/nothing"))),
            ..Default::default()
        })
        .await;
        assert_eq!(
            found,
            Some(LocateResult {
                path: "/opt/homebrew/bin/openconnect".into(),
                source: OpenconnectSource::Path,
                trusted: false
            })
        );
    }
}
