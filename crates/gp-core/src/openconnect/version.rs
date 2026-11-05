//! `openconnect --version`.

use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

static VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)OpenConnect version v?([0-9]+\.[0-9]+[^\s]*)").expect("valid regex"));

/// Extracts the version from `openconnect --version` output, e.g. "9.12" or "9.01-3".
pub fn parse_openconnect_version(output: &str) -> Option<String> {
    VERSION_RE.captures(output).map(|c| c[1].to_string())
}

/// Major version, `None` when unknown.
pub fn major_version(version: Option<&str>) -> Option<u32> {
    let v = version?;
    let (major, _) = v.split_once('.')?;
    (!major.is_empty() && major.bytes().all(|b| b.is_ascii_digit())).then(|| major.parse().ok())?
}

/// Runs `<binary> --version` (5 s timeout, 256 KiB output cap) and parses stdout + stderr.
pub async fn read_openconnect_version(binary: &str, timeout: Duration) -> Option<String> {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = tokio::time::timeout(timeout, cmd.output()).await.ok()?.ok()?;
    let take = |b: &[u8]| String::from_utf8_lossy(&b[..b.len().min(256 * 1024)]).into_owned();
    // openconnect --version exits 0 on success; on failure we still try to parse.
    parse_openconnect_version(&format!("{}\n{}", take(&out.stdout), take(&out.stderr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        for (out, version, major) in [
            (
                "OpenConnect version v9.12-188-gaebd3bd\nUsing GnuTLS 3.8.3.",
                "9.12-188-gaebd3bd",
                9,
            ),
            ("OpenConnect version v8.20", "8.20", 8),
            ("OpenConnect version 9.01", "9.01", 9),
        ] {
            let v = parse_openconnect_version(out);
            assert_eq!(v.as_deref(), Some(version));
            assert_eq!(major_version(v.as_deref()), Some(major));
        }
        assert_eq!(parse_openconnect_version("command not found"), None);
        assert_eq!(major_version(None), None);
        assert_eq!(major_version(Some("x.1")), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reads_the_version_from_a_binary_and_tolerates_missing_ones() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("openconnect");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'OpenConnect version v9.12' >&2\nexit 1\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let v = read_openconnect_version(script.to_str().unwrap(), Duration::from_secs(5)).await;
        assert_eq!(v.as_deref(), Some("9.12"));
        assert_eq!(
            read_openconnect_version("/nonexistent/openconnect", Duration::from_secs(5)).await,
            None
        );
    }
}
