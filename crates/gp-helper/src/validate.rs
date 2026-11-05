//! What the helper checks as administrator before starting anything: the binary is openconnect
//! and admin-controlled, the HIP script (if any) is admin-controlled, and the argv has exactly the
//! allowed shape. The app checked all of this too, but the config file came from a user-writable
//! location, so nothing in it is trusted.

use gp_core::openconnect::trust::{TrustOptions, verify_trusted_file, verify_windows_install_dir};
use gp_core::validation::{is_allowed_windows_hip_script, is_openconnect_binary_path};
use gp_elevate::helper_protocol::HelperConfig;

use crate::argv::{CSD_WRAPPER, validate_openconnect_argv};

/// A validated launch: real paths only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub binary: String,
    pub args: Vec<String>,
}

pub async fn validate_request(cfg: &HelperConfig, trust: &TrustOptions) -> Result<Launch, String> {
    if !is_openconnect_binary_path(&cfg.binary) {
        return Err(format!(
            "Refusing to run \"{}\": only openconnect may be started",
            cfg.binary
        ));
    }
    let binary = verify_trusted_file(&cfg.binary, trust)
        .await
        .map_err(|e| e.message)?;
    if !is_openconnect_binary_path(&binary) {
        return Err(format!(
            "Refusing to run \"{binary}\": only openconnect may be started"
        ));
    }
    validate_openconnect_argv(&cfg.args, cfg.script.as_deref())?;
    // DLLs / vpnc-script-win.js next to openconnect.exe run as administrator too.
    verify_windows_install_dir(&binary, trust)
        .await
        .map_err(|e| e.message)?;
    let mut args = cfg.args.clone();
    if let Some(script) = &cfg.script {
        let real = verify_trusted_file(script, trust).await.map_err(|e| e.message)?;
        // The extension of the real target counts (a .js symlink must not point to a .ps1).
        if !is_allowed_windows_hip_script(&real) {
            return Err(format!(
                "Refusing to run \"{real}\": HIP script must be a .js, .cmd, .bat or .exe file"
            ));
        }
        // Run the verified real path, not whatever the given path resolves to later.
        if let Some(a) = args.iter_mut().find(|a| a.starts_with(CSD_WRAPPER)) {
            *a = format!("{CSD_WRAPPER}{real}");
        }
    }
    Ok(Launch { binary, args })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use async_trait::async_trait;
    use gp_core::openconnect::trust::{TrustFs, TrustStat};
    use gp_core::openconnect::windows_acl::{
        AceType, AclEntry, AclItem, SID_ADMINISTRATORS, WindowsProbeResult, WindowsSecurityProbe,
    };
    use gp_core::platform::Platform;
    use gp_elevate::helper_protocol::PIPE_PREFIX;

    use super::*;

    const OC: &str = r"C:\Program Files\OpenConnect\openconnect.exe";
    const HIP: &str = r"C:\Program Files\OpenConnect\hipreport.js";

    /// Everything exists; `link.js` resolves to the HIP script.
    struct FakeFs;

    #[async_trait]
    impl TrustFs for FakeFs {
        async fn realpath(&self, p: &str) -> io::Result<String> {
            Ok(if p.ends_with("link.js") {
                HIP.into()
            } else {
                p.into()
            })
        }
        async fn read_dir(&self, p: &str) -> io::Result<Vec<String>> {
            // `BadDll` ships a DLL that the probe reports as user-writable.
            let dll = if p.ends_with("BadDll") {
                "Users.dll"
            } else {
                "libgnutls.dll"
            };
            Ok(vec![
                "openconnect.exe".into(),
                dll.into(),
                "vpnc-script-win.js".into(),
            ])
        }
        async fn stat(&self, p: &str) -> io::Result<TrustStat> {
            let is_file = p.contains('.');
            Ok(TrustStat {
                uid: 0,
                mode: 0,
                is_file,
                is_dir: !is_file,
            })
        }
    }

    /// Program Files is admin-only; anything under `Users` is writable by Authenticated Users.
    struct FakeProbe;

    #[async_trait]
    impl WindowsSecurityProbe for FakeProbe {
        async fn probe(&self, paths: &[String]) -> Result<WindowsProbeResult, String> {
            Ok(WindowsProbeResult {
                program_files: vec![r"C:\Program Files".into()],
                items: paths
                    .iter()
                    .map(|p| AclItem {
                        path: p.clone(),
                        owner_sid: SID_ADMINISTRATORS.into(),
                        entries: vec![AclEntry {
                            sid: if p.contains("Users") {
                                "S-1-5-11"
                            } else {
                                SID_ADMINISTRATORS
                            }
                            .into(),
                            rights: 0x2,
                            ace_type: AceType::Allow,
                            inherit_only: false,
                        }],
                    })
                    .collect(),
            })
        }
    }

    fn trust() -> TrustOptions {
        TrustOptions {
            platform: Platform::Win32,
            fs: Arc::new(FakeFs),
            windows_probe: Some(Arc::new(FakeProbe)),
        }
    }

    fn cfg(binary: &str, script: Option<&str>) -> HelperConfig {
        let mut args: Vec<String> = ["--protocol=gp", "--os=win", "--passwd-on-stdin"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        if let Some(s) = script {
            args.push(format!("--csd-wrapper={s}"));
        }
        args.extend(["--".to_string(), "https://vpn.example.com".to_string()]);
        HelperConfig {
            pipe: format!("{PIPE_PREFIX}{}", "0".repeat(32)),
            token: "1".repeat(64),
            binary: binary.into(),
            args,
            script: script.map(str::to_string),
            server_pid: 42,
        }
    }

    #[tokio::test]
    async fn accepts_a_trusted_binary_and_script_and_uses_real_paths() {
        let link = r"C:\Program Files\OpenConnect\link.js";
        let l = validate_request(&cfg(OC, Some(link)), &trust()).await.unwrap();
        assert_eq!(l.binary, OC);
        assert!(l.args.contains(&format!("--csd-wrapper={HIP}")), "{:?}", l.args);
        assert!(validate_request(&cfg(OC, None), &trust()).await.is_ok());
    }

    #[tokio::test]
    async fn refuses_untrusted_or_foreign_binaries_and_scripts() {
        let user_oc = r"C:\Users\x\openconnect.exe";
        let e = validate_request(&cfg(user_oc, None), &trust()).await.unwrap_err();
        assert!(e.contains("Program Files"), "{e}");
        let e = validate_request(&cfg(r"C:\Program Files\OpenConnect\cmd.exe", None), &trust())
            .await
            .unwrap_err();
        assert!(e.contains("only openconnect"), "{e}");
        let e = validate_request(&cfg(OC, Some(r"C:\Program Files\Users\evil.js")), &trust())
            .await
            .unwrap_err();
        assert!(e.contains("writable by S-1-5-11"), "{e}");
        let e = validate_request(&cfg(r"C:\Program Files\BadDll\openconnect.exe", None), &trust())
            .await
            .unwrap_err();
        assert!(e.contains("Users.dll is writable by S-1-5-11"), "{e}");
        let e = validate_request(&cfg(OC, Some(r"C:\Program Files\OpenConnect\hip.ps1")), &trust())
            .await
            .unwrap_err();
        assert!(e.contains(".js"), "{e}");
        let mut c = cfg(OC, None);
        c.args.insert(3, "--script=C:\\evil.js".into());
        assert!(validate_request(&c, &trust()).await.is_err());
    }
}
