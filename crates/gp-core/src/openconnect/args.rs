//! openconnect argv. Secrets (password / SAML cookie)
//! are never part of argv — they go to stdin (`--passwd-on-stdin`).

use url::Url;

use crate::platform::Platform;
use crate::saml::SamlCookieName;
use crate::validation::{
    ExtraArgErrorCode, MAX_EXTRA_ARG_LENGTH, MAX_EXTRA_ARGS, allowed_extra_options, check_extra_args,
    check_extra_args_value, extra_option_takes_value, has_control_chars, option_name,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenconnectAuth {
    Password,
    Saml { cookie_name: SamlCookieName },
}

#[derive(Debug, Clone)]
pub struct OpenconnectArgsInput<'a> {
    /// Normalised https portal URL.
    pub portal_url: &'a str,
    pub platform: Platform,
    pub username: Option<&'a str>,
    pub auth: OpenconnectAuth,
    /// Gateway name/address to select on the portal (`--authgroup`).
    pub gateway: Option<&'a str>,
    pub hip_script_path: Option<&'a str>,
    pub extra_args: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct InvalidArgumentError {
    pub message: String,
    pub code: ExtraArgErrorCode,
}

impl InvalidArgumentError {
    fn bad(message: impl Into<String>) -> Self {
        InvalidArgumentError {
            message: message.into(),
            code: ExtraArgErrorCode::BadValue,
        }
    }
}

fn describe(e: &crate::validation::ExtraArgError, is_list: bool) -> InvalidArgumentError {
    let name = option_name(&e.arg);
    let message = match e.code {
        ExtraArgErrorCode::TooMany => format!("At most {MAX_EXTRA_ARGS} extra arguments allowed"),
        ExtraArgErrorCode::TooLong => format!("Extra argument is too long (max {MAX_EXTRA_ARG_LENGTH})"),
        ExtraArgErrorCode::NotAllowed => {
            format!(
                "Option \"{name}\" is not allowed. Allowed: {}",
                allowed_extra_options().join(", ")
            )
        }
        ExtraArgErrorCode::NotNameValue if extra_option_takes_value(name) => {
            format!("Option {name} needs a value (use {name}=<value>)")
        }
        ExtraArgErrorCode::NotNameValue => format!("Option {name} does not take a value"),
        ExtraArgErrorCode::BadValue if is_list && !name.is_empty() => format!("Invalid value for {name}"),
        ExtraArgErrorCode::BadValue => "extraArgs must be an array of option strings".into(),
    };
    InvalidArgumentError {
        message,
        code: e.code,
    }
}

/// Validates extra arguments against the shared allowlist. Applied on IPC input, on settings
/// loaded from disk and again right before every spawn.
pub fn validate_extra_args<S: AsRef<str>>(args: &[S]) -> Result<Vec<String>, InvalidArgumentError> {
    check_extra_args(args).map_err(|e| describe(&e, true))
}

/// [`validate_extra_args`] for untrusted JSON.
pub fn validate_extra_args_value(args: &serde_json::Value) -> Result<Vec<String>, InvalidArgumentError> {
    check_extra_args_value(args).map_err(|e| describe(&e, args.is_array()))
}

/// `--os` value matching the `clientos` sent in prelogin (SAML cookies are bound to it).
pub fn openconnect_os(platform: Platform) -> &'static str {
    match platform {
        Platform::Win32 => "win",
        Platform::Darwin => "mac-intel",
        Platform::Linux => "linux-64",
    }
}

fn assert_safe_value(name: &str, value: &str) -> Result<(), InvalidArgumentError> {
    if value.is_empty() || has_control_chars(value) {
        return Err(InvalidArgumentError::bad(format!("Invalid value for {name}")));
    }
    Ok(())
}

/// Builds the openconnect argv (without the binary).
pub fn build_openconnect_args(input: &OpenconnectArgsInput<'_>) -> Result<Vec<String>, InvalidArgumentError> {
    let url = Url::parse(input.portal_url).map_err(|_| InvalidArgumentError::bad("Invalid portal URL"))?;
    if url.scheme() != "https" {
        return Err(InvalidArgumentError::bad("Only https portals are supported"));
    }
    let mut args = vec![
        "--protocol=gp".to_string(),
        format!("--os={}", openconnect_os(input.platform)),
        "--passwd-on-stdin".to_string(),
    ];
    if let Some(u) = input.username {
        assert_safe_value("username", u)?;
        args.push(format!("--user={u}"));
    }
    if let OpenconnectAuth::Saml { cookie_name } = input.auth {
        args.push(format!("--usergroup=portal:{}", cookie_name.as_str()));
    }
    if let Some(g) = input.gateway {
        assert_safe_value("gateway", g)?;
        args.push(format!("--authgroup={g}"));
    }
    if let Some(h) = input.hip_script_path {
        assert_safe_value("hipScriptPath", h)?;
        if input.platform == Platform::Win32 && !crate::validation::is_allowed_windows_hip_script(h) {
            return Err(InvalidArgumentError::bad(
                "HIP script must be a .js, .cmd, .bat or .exe file on Windows",
            ));
        }
        args.push(format!("--csd-wrapper={h}"));
    }
    args.extend(validate_extra_args(input.extra_args)?);
    // `--` guarantees the server is never parsed as an option.
    args.push("--".into());
    args.push(format!("https://{}", crate::validation::url_host(&url)));
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(portal: &str, platform: Platform, auth: OpenconnectAuth) -> OpenconnectArgsInput<'_> {
        OpenconnectArgsInput {
            portal_url: portal,
            platform,
            username: None,
            auth,
            gateway: None,
            hip_script_path: None,
            extra_args: &[],
        }
    }

    #[test]
    fn windows_hip_scripts_need_an_allowed_extension() {
        let mut i = input(
            "https://vpn.example.com",
            Platform::Win32,
            OpenconnectAuth::Password,
        );
        for ok in [
            "C:\\P\\hip.js",
            "C:\\P\\HIP.CMD",
            "C:\\P\\hip.bat",
            "C:\\P\\hip.exe",
        ] {
            i.hip_script_path = Some(ok);
            assert!(build_openconnect_args(&i).is_ok(), "{ok}");
        }
        for bad in [
            "C:\\P\\hip.ps1",
            "C:\\P\\hip.vbs",
            "C:\\P\\hip",
            "C:\\P\\hip.js.lnk",
        ] {
            i.hip_script_path = Some(bad);
            assert!(build_openconnect_args(&i).is_err(), "{bad}");
        }
        // Unix scripts keep working without an extension.
        let mut i = input(
            "https://vpn.example.com",
            Platform::Linux,
            OpenconnectAuth::Password,
        );
        i.hip_script_path = Some("/usr/libexec/openconnect/hipreport");
        assert!(build_openconnect_args(&i).is_ok());
    }

    #[test]
    fn builds_password_args_with_the_server_last() {
        let mut i = input(
            "https://vpn.example.com",
            Platform::Linux,
            OpenconnectAuth::Password,
        );
        i.username = Some("alice");
        assert_eq!(
            build_openconnect_args(&i).unwrap(),
            [
                "--protocol=gp",
                "--os=linux-64",
                "--passwd-on-stdin",
                "--user=alice",
                "--",
                "https://vpn.example.com"
            ]
        );
    }

    #[test]
    fn builds_saml_args_with_usergroup_gateway_hip_and_extra_args() {
        let extra = vec![
            "--servercert=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            "-v".into(),
        ];
        let i = OpenconnectArgsInput {
            portal_url: "https://vpn.example.com:8443",
            platform: Platform::Win32,
            username: Some("bob@example.com"),
            auth: OpenconnectAuth::Saml {
                cookie_name: SamlCookieName::PortalUserauthcookie,
            },
            gateway: Some("US East"),
            hip_script_path: Some("C:\\Program Files\\OpenConnect\\hipreport.js"),
            extra_args: &extra,
        };
        assert_eq!(
            build_openconnect_args(&i).unwrap(),
            [
                "--protocol=gp",
                "--os=win",
                "--passwd-on-stdin",
                "--user=bob@example.com",
                "--usergroup=portal:portal-userauthcookie",
                "--authgroup=US East",
                "--csd-wrapper=C:\\Program Files\\OpenConnect\\hipreport.js",
                "--servercert=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "-v",
                "--",
                "https://vpn.example.com:8443",
            ]
        );
    }

    #[test]
    fn never_contains_secrets_and_maps_the_os() {
        let i = input(
            "https://vpn.example.com",
            Platform::Darwin,
            OpenconnectAuth::Saml {
                cookie_name: SamlCookieName::PreloginCookie,
            },
        );
        let args = build_openconnect_args(&i).unwrap();
        assert!(!args.join(" ").contains("cookie=") && !args.join(" ").contains("passwd="));
        assert!(args.contains(&"--os=mac-intel".to_string()));
        assert_eq!(
            [Platform::Win32, Platform::Darwin, Platform::Linux].map(openconnect_os),
            ["win", "mac-intel", "linux-64"]
        );
    }

    #[test]
    fn rejects_non_https_portals_and_control_characters() {
        let i = input(
            "http://vpn.example.com",
            Platform::Linux,
            OpenconnectAuth::Password,
        );
        assert!(build_openconnect_args(&i).unwrap_err().message.contains("https"));
        let mut i = input(
            "https://vpn.example.com",
            Platform::Linux,
            OpenconnectAuth::Password,
        );
        i.username = Some("a\nb");
        assert!(
            build_openconnect_args(&i)
                .unwrap_err()
                .message
                .contains("username")
        );
        i.username = None;
        i.gateway = Some("");
        assert!(
            build_openconnect_args(&i)
                .unwrap_err()
                .message
                .contains("gateway")
        );
        let bad = vec!["--script=/tmp/x".to_string()];
        i.gateway = None;
        i.extra_args = &bad;
        assert_eq!(
            build_openconnect_args(&i).unwrap_err().code,
            ExtraArgErrorCode::NotAllowed
        );
    }

    #[test]
    fn allowlist_accepts_and_trims_valid_options() {
        let pin = "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let input = [
            " --no-dtls ".to_string(),
            format!("--servercert={pin}"),
            "-v".into(),
            "--mtu=1400".into(),
            "--dtls-ciphers=AES256-GCM-SHA384:PSK-NEGOTIATE".into(),
        ];
        assert_eq!(
            validate_extra_args(&input).unwrap(),
            [
                "--no-dtls",
                &format!("--servercert={pin}"),
                "-v",
                "--mtu=1400",
                "--dtls-ciphers=AES256-GCM-SHA384:PSK-NEGOTIATE"
            ]
        );
    }

    #[test]
    fn allowlist_rejects_dangerous_and_malformed_options() {
        for arg in [
            "--script=/tmp/evil.sh",
            "-s",
            "--script-tun",
            "--external-browser=/tmp/x",
            "--config=/tmp/oc.conf",
            "--csd-wrapper=/tmp/x",
            "--cafile=/tmp/ca.pem",
            "-c",
            "--certificate=/tmp/c.pem",
            "-k",
            "--sslkey=/tmp/k",
            "-D",
            "--syslog",
            "--pid-file=/etc/passwd",
            "--proxy=http://evil:8080",
            "--resolve=vpn.example.com:1.2.3.4",
            "--no-system-trust",
            "--servercert=sha1:0123",
            "--servercert=pin-sha256:short",
            "--allow-insecure-crypto",
            "--dump-http-traffic",
            "--protocol=anyconnect",
            "--user=root",
            "-uroot",
            "--passwd",
            "--no-d",
            "--",
            "-vs",
            "--mtu",
            "--mtu=abc",
            "--mtu=100",
            "--no-dtls=1",
            "positional",
        ] {
            assert!(validate_extra_args(&[arg]).is_err(), "{arg}");
        }
        for v in [json!([1]), json!("not-an-array"), json!(vec!["-v"; 33])] {
            assert!(validate_extra_args_value(&v).is_err(), "{v}");
        }
    }

    #[test]
    fn error_messages_explain_the_problem() {
        let msg = |a: &str| validate_extra_args(&[a]).unwrap_err().message;
        assert!(msg("--script=/x").starts_with("Option \"--script\" is not allowed. Allowed: -v, --verbose"));
        assert_eq!(msg("--mtu"), "Option --mtu needs a value (use --mtu=<value>)");
        assert_eq!(msg("--no-dtls=1"), "Option --no-dtls does not take a value");
        assert_eq!(msg("--mtu=1"), "Invalid value for --mtu");
        assert_eq!(
            validate_extra_args(&["-v"; 33]).unwrap_err().message,
            "At most 32 extra arguments allowed"
        );
        assert_eq!(
            validate_extra_args_value(&json!("x")).unwrap_err().message,
            "extraArgs must be an array of option strings"
        );
    }
}
