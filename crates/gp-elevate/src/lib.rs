//! Privilege elevation for GP Connect: implementations of
//! [`gp_core::process::ProcessSpawner`] for Linux (direct / `pkexec`), macOS (osascript root
//! wrapper) and Windows (client of the elevated helper `gp-connect-helper.exe`), plus the native
//! Windows ACL probe. See docs/ARCHITECTURE-TAURI.md, "Elevation".
//!
//! Public entry points: [`platform_spawner`], [`windows_security_probe`], [`is_root`]. The
//! helper wire protocol ([`helper_protocol`]) is shared with the gp-helper crate.

mod channels;
pub mod darwin_script;
#[cfg_attr(not(windows), allow(dead_code))] // used by the Windows spawner; tested everywhere
mod helper_client;
pub mod helper_protocol;
pub mod quote;
#[cfg(unix)]
mod unix;
pub mod win_security;
pub mod windows_acl;
#[cfg(windows)]
mod windows_spawner;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use gp_core::logging::Logger;
use gp_core::openconnect::windows_acl::WindowsSecurityProbe;
use gp_core::platform::Platform;
use gp_core::process::{Elevation, ProcessSpawner, SpawnError, SpawnRequest, VpnProcess};
use gp_core::types::VpnErrorCode;

/// File name of the Windows helper binary (installed next to the app executable).
pub const HELPER_EXE: &str = "gp-connect-helper.exe";

const LOG_SOURCE: &str = "elevate";

fn elevation_name(e: Elevation) -> &'static str {
    match e {
        Elevation::None => "none",
        Elevation::Pkexec => "pkexec",
        Elevation::Osascript => "osascript",
        Elevation::Uac => "uac",
    }
}

/// Whether `elevation` can be used on `platform` (the engine picks it with
/// `gp_core::process::choose_elevation`).
fn supported(platform: Platform, elevation: Elevation) -> bool {
    matches!(
        (platform, elevation),
        (Platform::Linux | Platform::Darwin, Elevation::None)
            | (Platform::Linux, Elevation::Pkexec)
            | (Platform::Darwin, Elevation::Osascript)
            | (Platform::Win32, Elevation::Uac)
    )
}

/// Dispatches each [`SpawnRequest`] on its `elevation`.
struct PlatformSpawner {
    platform: Platform,
    logger: Arc<Logger>,
    #[cfg_attr(not(windows), allow(dead_code))]
    helper_path: Option<PathBuf>,
}

#[async_trait]
impl ProcessSpawner for PlatformSpawner {
    async fn spawn(&self, req: SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let method = elevation_name(req.elevation);
        if !supported(self.platform, req.elevation) {
            return Err(SpawnError::new(
                VpnErrorCode::Unknown,
                format!("Elevation method {method} is not supported on {}", self.platform),
            ));
        }
        self.logger
            .info(LOG_SOURCE, &format!("Starting openconnect (elevation: {method})"));
        self.spawn_on_platform(&req).await
    }
}

impl PlatformSpawner {
    #[cfg(unix)]
    async fn spawn_on_platform(&self, req: &SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        use quote::LocalMethod;
        match req.elevation {
            Elevation::None => unix::local::LocalSpawner {
                method: LocalMethod::Direct,
            }
            .spawn(req),
            Elevation::Pkexec => unix::local::LocalSpawner {
                method: LocalMethod::Pkexec,
            }
            .spawn(req),
            Elevation::Osascript => unix::darwin::DarwinSpawner.spawn(req).await,
            Elevation::Uac => Err(not_built_for(req.elevation)),
        }
    }

    #[cfg(windows)]
    async fn spawn_on_platform(&self, req: &SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        match req.elevation {
            Elevation::Uac => {
                windows_spawner::UacSpawner {
                    helper: self.helper_path.clone(),
                    logger: self.logger.clone(),
                }
                .spawn(req)
                .await
            }
            other => Err(not_built_for(other)),
        }
    }
}

fn not_built_for(e: Elevation) -> SpawnError {
    SpawnError::new(
        VpnErrorCode::Unknown,
        format!(
            "Elevation method {} is not available in this build",
            elevation_name(e)
        ),
    )
}

/// Spawner for `platform`. `helper_path` is the full path of `gp-connect-helper.exe`
/// ([`HELPER_EXE`] next to the app executable); required on Windows, ignored elsewhere.
pub fn platform_spawner(
    platform: Platform,
    logger: Arc<Logger>,
    helper_path: Option<PathBuf>,
) -> Arc<dyn ProcessSpawner> {
    Arc::new(PlatformSpawner {
        platform,
        logger,
        helper_path,
    })
}

/// Native registry/ACL probe for `gp_core::openconnect::trust` on Windows. On other OSes every
/// probe fails, so Windows trust checks fail closed.
pub fn windows_security_probe() -> Arc<dyn WindowsSecurityProbe> {
    #[cfg(windows)]
    {
        Arc::new(windows_acl::native::NativeProbe)
    }
    #[cfg(not(windows))]
    {
        Arc::new(windows_acl::UnavailableProbe)
    }
}

/// Effective uid is 0 (always `false` on Windows, where elevation is per-launch UAC).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unix::is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_platform_appropriate_methods_are_supported() {
        assert!(supported(Platform::Linux, Elevation::Pkexec));
        assert!(supported(Platform::Linux, Elevation::None));
        assert!(supported(Platform::Darwin, Elevation::Osascript));
        assert!(supported(Platform::Win32, Elevation::Uac));
        assert!(!supported(Platform::Win32, Elevation::None));
        assert!(!supported(Platform::Linux, Elevation::Uac));
        assert!(!supported(Platform::Darwin, Elevation::Pkexec));
        assert!(!supported(Platform::Linux, Elevation::Osascript));
    }

    #[tokio::test]
    async fn rejects_a_method_that_does_not_fit_the_platform() {
        let s = platform_spawner(Platform::Linux, Arc::new(Logger::in_memory()), None);
        let e = s
            .spawn(SpawnRequest {
                binary: PathBuf::from("/usr/sbin/openconnect"),
                args: vec![],
                elevation: Elevation::Uac,
                env: vec![],
            })
            .await
            .err()
            .unwrap();
        assert!(e.message.contains("not supported on linux"), "{}", e.message);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spawns_directly_and_logs_the_method() {
        let logger = Arc::new(Logger::in_memory());
        let s = platform_spawner(Platform::current(), logger.clone(), None);
        let mut p = s
            .spawn(SpawnRequest {
                binary: PathBuf::from("/bin/sh"),
                args: vec!["-c".into(), "exit 4".into()],
                elevation: Elevation::None,
                env: vec![],
            })
            .await
            .unwrap();
        assert_eq!(p.exited().await.unwrap().code, Some(4));
        assert!(
            logger
                .lines()
                .iter()
                .any(|l| l.contains("Starting openconnect (elevation: none)"))
        );
    }

    /// End to end on a real Windows install: the real canonicalize (which yields `\\?\C:\…`), the
    /// native registry/ACL probe and the trust check together accept a TrustedInstaller-owned file
    /// under Program Files, given in plain or verbatim form (Tauri's resource dir is verbatim), and
    /// return the plain path.
    #[cfg(windows)]
    #[tokio::test]
    async fn trusts_a_real_program_files_binary_given_in_verbatim_form() {
        use gp_core::openconnect::trust::{TrustOptions, verify_trusted_file};

        let candidates = [
            r"C:\Program Files\Internet Explorer\iexplore.exe",
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe",
        ];
        let file = candidates
            .iter()
            .find(|p| std::path::Path::new(p).is_file())
            .expect("a stock Windows binary under Program Files");
        let opts = TrustOptions::new(Platform::Win32, Some(windows_security_probe()));
        for input in [(*file).to_string(), format!(r"\\?\{file}")] {
            let real = verify_trusted_file(&input, &opts)
                .await
                .unwrap_or_else(|e| panic!("{input}: {}", e.message));
            assert!(real.eq_ignore_ascii_case(file), "{input} → {real}");
        }
    }

    #[test]
    fn is_root_matches_the_effective_uid() {
        #[cfg(unix)]
        assert_eq!(is_root(), rustix::process::geteuid().is_root());
        #[cfg(windows)]
        assert!(!is_root());
    }
}
