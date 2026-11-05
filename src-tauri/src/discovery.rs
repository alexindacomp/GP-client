//! openconnect discovery (cached, logged only on change) and the engine's
//! [`OpenconnectProvider`]: discovery uses a short-lived trust cache, elevation always re-checks
//! uncached and first asks to confirm elevation settings that were changed outside the app.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use gp_core::logging::Logger;
use gp_core::openconnect::discovery_log::{DiscoveryReporter, DiscoveryResult};
use gp_core::openconnect::locate::{LocateOptions, locate_openconnect};
use gp_core::openconnect::trust::{
    TrustCache, TrustOptions, verify_trusted_file, verify_windows_install_dir,
};
use gp_core::openconnect::version::read_openconnect_version;
use gp_core::platform::Platform;
use gp_core::store::confirm_dialog::ConfirmDialog;
use gp_core::store::confirmed_settings::{ConfirmedSettingsGuard, ensure_settings_confirmed};
use gp_core::store::settings::SettingsStore;
use gp_core::vpn::{ElevatedFiles, OpenconnectProvider, VpnError};

const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Trust options for `platform` (Windows needs the native ACL probe; without it every Windows
/// check fails closed).
pub(crate) fn trust_options(platform: Platform) -> TrustOptions {
    let probe = (platform == Platform::Win32).then(gp_elevate::windows_security_probe);
    TrustOptions::new(platform, probe)
}

pub(crate) struct Discovery {
    platform: Platform,
    settings: Arc<SettingsStore>,
    /// `<resources>/bin` (bundled binaries live in `<platform>/` inside).
    bundled_bin_dir: Option<String>,
    trust: Arc<TrustCache>,
    /// Uncached options for the install-dir check (Windows: DLLs/scripts next to openconnect).
    trust_opts: TrustOptions,
    reporter: DiscoveryReporter,
    logger: Arc<Logger>,
    last: tokio::sync::Mutex<Option<DiscoveryResult>>,
}

impl Discovery {
    pub(crate) fn new(
        platform: Platform,
        settings: Arc<SettingsStore>,
        bundled_bin_dir: Option<String>,
        logger: Arc<Logger>,
    ) -> Self {
        Discovery {
            platform,
            settings,
            bundled_bin_dir,
            trust: Arc::new(TrustCache::new(trust_options(platform))),
            trust_opts: trust_options(platform),
            reporter: DiscoveryReporter::new(),
            logger,
            last: tokio::sync::Mutex::new(None),
        }
    }

    /// Cached result unless `refresh`; concurrent callers are serialized.
    pub(crate) async fn find(&self, refresh: bool) -> DiscoveryResult {
        let mut last = self.last.lock().await;
        if !refresh && let Some(r) = last.as_ref() {
            return r.clone();
        }
        let opts = LocateOptions {
            platform: Some(self.platform),
            configured_path: self.settings.get().openconnect_path,
            bundled_bin_dir: self.bundled_bin_dir.clone(),
            env_path: std::env::var("PATH").ok(),
            is_executable: None,
            is_trusted: Some(self.trust.clone()),
        };
        let mut found = locate_openconnect(&opts).await;
        // Windows: a trusted openconnect.exe is only usable if the DLLs/scripts loaded next to it
        // are admin-controlled too (the elevated helper re-checks this).
        if let Some(f) = found.as_mut().filter(|f| f.trusted) {
            f.trusted = verify_windows_install_dir(&f.path, &self.trust_opts)
                .await
                .is_ok();
        }
        let version = match &found {
            Some(f) => read_openconnect_version(&f.path, VERSION_TIMEOUT).await,
            None => None,
        };
        self.reporter
            .report_to(&self.logger, found.as_ref(), version.as_deref());
        let result = match found {
            Some(f) => DiscoveryResult {
                path: Some(f.path),
                version,
                trusted: Some(f.trusted),
            },
            None => DiscoveryResult::default(),
        };
        *last = Some(result.clone());
        result
    }
}

pub(crate) struct AppOpenconnect {
    pub(crate) discovery: Arc<Discovery>,
    pub(crate) settings: Arc<SettingsStore>,
    pub(crate) guard: Arc<ConfirmedSettingsGuard>,
    pub(crate) dialog: Arc<dyn ConfirmDialog>,
    pub(crate) logger: Arc<Logger>,
    /// Uncached checks right before elevation.
    pub(crate) elevated_trust: TrustOptions,
}

#[async_trait]
impl OpenconnectProvider for AppOpenconnect {
    async fn locate_openconnect(&self) -> Option<String> {
        self.discovery.find(true).await.path
    }

    async fn verify_elevated_files(&self, files: &ElevatedFiles) -> Result<ElevatedFiles, VpnError> {
        ensure_settings_confirmed(
            &self.settings.get(),
            &self.guard,
            self.dialog.as_ref(),
            &self.logger,
        )
        .await?;
        let binary = verify_trusted_file(&files.binary, &self.elevated_trust).await?;
        // Windows: DLLs/scripts next to openconnect.exe (no-op elsewhere; the helper re-checks).
        verify_windows_install_dir(&binary, &self.elevated_trust).await?;
        let hip_script_path = match &files.hip_script_path {
            Some(p) => Some(verify_trusted_file(p, &self.elevated_trust).await?),
            None => None,
        };
        Ok(ElevatedFiles {
            binary,
            hip_script_path,
        })
    }
}
