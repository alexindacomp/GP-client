//! Admin-side re-validation of the openconnect argv. The helper accepts exactly the shape that
//! `gp_core::openconnect::args::build_openconnect_args` produces for Windows:
//!
//! `--protocol=gp --os=win --passwd-on-stdin [--user=…] [--usergroup=portal:<cookie>]
//!  [--authgroup=…] [--csd-wrapper=<script>] <allowlisted extra args> -- https://<host[:port]>`
//!
//! Anything else (another option, a second server, a script that does not match the config) is
//! refused, so a forged launch config cannot turn the helper into a generic "run as admin" tool.

use gp_core::openconnect::args::validate_extra_args;
use gp_core::validation::{has_control_chars, is_allowed_windows_hip_script};
use url::Url;

const FIXED_PREFIX: [&str; 3] = ["--protocol=gp", "--os=win", "--passwd-on-stdin"];
const USERGROUPS: [&str; 2] = ["portal:prelogin-cookie", "portal:portal-userauthcookie"];
pub const CSD_WRAPPER: &str = "--csd-wrapper=";

fn safe_value(name: &str, v: &str) -> Result<(), String> {
    if v.is_empty() || has_control_chars(v) {
        return Err(format!("invalid value for {name}"));
    }
    Ok(())
}

/// `https://host[:port]` exactly as built by the app (no path, query, credentials).
fn check_server(server: &str) -> Result<(), String> {
    let bad = || format!("invalid server {server:?}");
    if has_control_chars(server) {
        return Err(bad());
    }
    let url = Url::parse(server).map_err(|_| bad())?;
    let host = url.host_str().filter(|h| !h.is_empty()).ok_or_else(bad)?;
    let rebuilt = match url.port() {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    };
    if url.scheme() != "https" || rebuilt != server {
        return Err(bad());
    }
    Ok(())
}

/// Validates `args`; `script` is the HIP script from the config, which must appear as the only
/// `--csd-wrapper=` value (or not at all when `None`).
pub fn validate_openconnect_argv(args: &[String], script: Option<&str>) -> Result<(), String> {
    let n = args.len();
    if n < FIXED_PREFIX.len() + 2 || args[n - 2] != "--" {
        return Err("unexpected openconnect arguments".into());
    }
    check_server(&args[n - 1])?;
    let head = &args[..n - 2];
    if head.iter().take(FIXED_PREFIX.len()).ne(FIXED_PREFIX.iter()) {
        return Err("unexpected openconnect arguments".into());
    }
    let mut i = FIXED_PREFIX.len();
    if let Some(v) = head.get(i).and_then(|a| a.strip_prefix("--user=")) {
        safe_value("--user", v)?;
        i += 1;
    }
    if let Some(v) = head.get(i).and_then(|a| a.strip_prefix("--usergroup=")) {
        if !USERGROUPS.contains(&v) {
            return Err("invalid value for --usergroup".into());
        }
        i += 1;
    }
    if let Some(v) = head.get(i).and_then(|a| a.strip_prefix("--authgroup=")) {
        safe_value("--authgroup", v)?;
        i += 1;
    }
    let wrapper = head.get(i).and_then(|a| a.strip_prefix(CSD_WRAPPER));
    match (wrapper, script) {
        (Some(w), Some(s)) if w == s => {
            if !is_allowed_windows_hip_script(s) {
                return Err("HIP script must be a .js, .cmd, .bat or .exe file".into());
            }
            i += 1;
        }
        (None, None) => {}
        _ => return Err("--csd-wrapper does not match the configured HIP script".into()),
    }
    let extra = &head[i..];
    let validated = validate_extra_args(extra).map_err(|e| e.message)?;
    if validated != extra {
        return Err("extra arguments must be normalized".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use gp_core::openconnect::args::{OpenconnectArgsInput, OpenconnectAuth, build_openconnect_args};
    use gp_core::platform::Platform;
    use gp_core::saml::SamlCookieName;

    use super::*;

    const SCRIPT: &str = r"C:\Program Files\OpenConnect\hipreport.js";

    fn s(a: &[&str]) -> Vec<String> {
        a.iter().map(|x| (*x).to_string()).collect()
    }

    fn built(
        username: Option<&str>,
        auth: OpenconnectAuth,
        gateway: Option<&str>,
        hip: Option<&str>,
        extra: &[String],
    ) -> Vec<String> {
        build_openconnect_args(&OpenconnectArgsInput {
            portal_url: "https://vpn.example.com:8443",
            platform: Platform::Win32,
            username,
            auth,
            gateway,
            hip_script_path: hip,
            extra_args: extra,
        })
        .unwrap()
    }

    #[test]
    fn accepts_everything_the_app_builds() {
        let extra = s(&[
            "--servercert=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "-v",
            "--no-dtls",
        ]);
        let saml = OpenconnectAuth::Saml {
            cookie_name: SamlCookieName::PreloginCookie,
        };
        for (args, script) in [
            (built(None, OpenconnectAuth::Password, None, None, &[]), None),
            (
                built(
                    Some("alice"),
                    OpenconnectAuth::Password,
                    Some("US East"),
                    None,
                    &extra,
                ),
                None,
            ),
            (
                built(Some("bob@example.com"), saml, Some("gw"), Some(SCRIPT), &extra),
                Some(SCRIPT),
            ),
            (built(None, saml, None, Some(SCRIPT), &[]), Some(SCRIPT)),
        ] {
            assert_eq!(validate_openconnect_argv(&args, script), Ok(()), "{args:?}");
        }
    }

    #[test]
    fn refuses_a_script_that_does_not_match_the_config() {
        let args = built(None, OpenconnectAuth::Password, None, Some(SCRIPT), &[]);
        assert!(validate_openconnect_argv(&args, None).is_err());
        assert!(validate_openconnect_argv(&args, Some(r"C:\Users\x\evil.js")).is_err());
        let args = built(None, OpenconnectAuth::Password, None, None, &[]);
        assert!(validate_openconnect_argv(&args, Some(SCRIPT)).is_err());
        // Extension allowlist, also when argv and config agree.
        let ps1 = r"C:\Program Files\OpenConnect\hip.ps1";
        let mut args = built(None, OpenconnectAuth::Password, None, None, &[]);
        args.insert(3, format!("--csd-wrapper={ps1}"));
        assert!(
            validate_openconnect_argv(&args, Some(ps1))
                .unwrap_err()
                .contains(".js")
        );
    }

    #[test]
    fn refuses_anything_outside_the_allowlist() {
        let base = |mid: &[&str], tail: &[&str]| {
            let mut v = s(&["--protocol=gp", "--os=win", "--passwd-on-stdin"]);
            v.extend(s(mid));
            v.extend(s(tail));
            v
        };
        let server = ["--", "https://vpn.example.com"];
        for bad in [
            base(&["--script=C:\\evil.js"], &server),
            base(&["--csd-wrapper=C:\\evil.js"], &server),
            base(&["--user=a", "--user=b"], &server),
            base(&["--authgroup=a\nb"], &server),
            base(&["--usergroup=gateway"], &server),
            base(&["-v", "--user=a"], &server),
            base(&[" -v"], &server),
            base(&[], &["--", "https://vpn.example.com/path"]),
            base(&[], &["--", "http://vpn.example.com"]),
            base(&[], &["--", "https://user@vpn.example.com"]),
            base(&[], &["--", "https://vpn.example.com?x=1"]),
            base(&[], &["https://vpn.example.com"]),
            base(&[], &["--", "https://a.example.com", "https://b.example.com"]),
            s(&[
                "--os=win",
                "--protocol=gp",
                "--passwd-on-stdin",
                "--",
                "https://vpn.example.com",
            ]),
            s(&[
                "--protocol=gp",
                "--os=linux-64",
                "--passwd-on-stdin",
                "--",
                "https://vpn.example.com",
            ]),
            s(&["--", "https://vpn.example.com"]),
            vec![],
        ] {
            assert!(validate_openconnect_argv(&bad, None).is_err(), "{bad:?}");
        }
    }
}
