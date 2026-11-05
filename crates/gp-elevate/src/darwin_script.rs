//! Pure part of the macOS elevation: the
//! root wrapper script, the AppleScript that runs it, and the checks on what it returns. Kept
//! platform-independent so it is tested on every OS.

use crate::quote::{apple_script_string, sh_quote};

/// Root-side wrapper. Root creates its own private directory (root-owned 0711, so the user cannot
/// plant symlinks in it), creates FIFOs for stdin/output/control owned by the user, starts
/// openconnect with stdio on those FIFOs, records pid and exit status, and listens on the
/// control FIFO for INT/TERM/KILL (sent only to the openconnect pid) so that the unprivileged
/// app can stop the root process without another password prompt. Prints the directory path and
/// returns immediately.
pub const WRAPPER_SCRIPT: &str = r#"UIDN="$1"; OC="$2"; shift 2
umask 077
D=$(/usr/bin/mktemp -d /private/tmp/gp-connect.XXXXXXXX) || exit 1
/usr/bin/mkfifo -m 600 "$D/in" "$D/out" "$D/ctl" || exit 1
/usr/sbin/chown "$UIDN" "$D/in" "$D/out" "$D/ctl" || exit 1
/bin/chmod 711 "$D" || exit 1
(
  exec 3<>"$D/ctl" </dev/null >/dev/null 2>&1
  "$OC" "$@" <"$D/in" >"$D/out" 2>&1 &
  pid=$!
  echo "$pid" >"$D/pid"; /bin/chmod 644 "$D/pid"
  ( while read -r cmd <&3; do case "$cmd" in INT|TERM|KILL) kill -s "$cmd" "$pid" 2>/dev/null ;; esac; done ) &
  watcher=$!
  wait "$pid"; echo "$?" >"$D/status"; /bin/chmod 644 "$D/status"
  kill "$watcher" 2>/dev/null
  sleep 15; /bin/rm -rf "$D"
) &
echo "$D""#;

/// Prefix of the directory created by `mktemp` in [`WRAPPER_SCRIPT`].
const DIR_PREFIX: &str = "/private/tmp/gp-connect.";

/// Builds the AppleScript that runs the wrapper with administrator privileges. The dialog text
/// names the binary that will run as root.
pub fn build_osascript(uid: u32, binary: &str, args: &[String]) -> String {
    let mut parts = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        sh_quote(WRAPPER_SCRIPT),
        "gp-connect".to_string(),
        sh_quote(&uid.to_string()),
        sh_quote(binary),
    ];
    parts.extend(args.iter().map(|a| sh_quote(a)));
    let shell_cmd = parts.join(" ");
    let prompt = format!("GP Connect needs administrator rights to run {binary} and create the VPN tunnel.");
    format!(
        "do shell script {} with prompt {} with administrator privileges",
        apple_script_string(&shell_cmd),
        apple_script_string(&prompt)
    )
}

/// `/private/tmp/gp-connect.XXXXXXXX` exactly (8 alphanumerics, as produced by `mktemp`).
pub fn is_wrapper_dir(s: &str) -> bool {
    s.strip_prefix(DIR_PREFIX)
        .is_some_and(|rest| rest.len() == 8 && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// osascript failed: was it the user dismissing the dialog (`-128` / "User canceled")?
pub fn is_cancelled(stderr: &str) -> bool {
    stderr.contains("-128") || stderr.to_lowercase().contains("cancel")
}

/// Contents of the `pid` file: digits, optionally followed by whitespace.
pub fn parse_pid_file(raw: &str) -> Option<u32> {
    let digits = raw.trim_end();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|p| *p > 1)
}

/// Contents of the `status` file (the exit code written by the wrapper).
pub fn parse_status_file(raw: &str) -> Option<i32> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_an_osascript_that_names_the_binary_and_quotes_every_argument() {
        let args = vec![
            "--user=o'brien".to_string(),
            "--authgroup=a \"b\" \\c".to_string(),
        ];
        let script = build_osascript(501, "/opt/local/sbin/openconnect", &args);
        assert!(script.starts_with("do shell script \"/bin/sh -c '"));
        assert!(script.ends_with(
            " with prompt \"GP Connect needs administrator rights to run /opt/local/sbin/openconnect and create the VPN tunnel.\" with administrator privileges"
        ));
        // sh-quoted, then AppleScript-escaped (\ → \\, " → \").
        assert!(script.contains(r#"gp-connect '501' '/opt/local/sbin/openconnect' '--user=o'\\''brien' '--authgroup=a \"b\" \\c'""#));
        // The wrapper itself is embedded with its quotes escaped for AppleScript.
        assert!(script.contains(r#"UIDN=\"$1\"; OC=\"$2\"; shift 2"#));
    }

    #[test]
    fn the_wrapper_only_forwards_int_term_kill_to_the_openconnect_pid() {
        assert!(
            WRAPPER_SCRIPT
                .contains(r#"case "$cmd" in INT|TERM|KILL) kill -s "$cmd" "$pid" 2>/dev/null ;; esac"#)
        );
        assert!(WRAPPER_SCRIPT.contains("/bin/chmod 711 \"$D\""));
        assert!(WRAPPER_SCRIPT.contains("/usr/bin/mkfifo -m 600"));
        assert!(WRAPPER_SCRIPT.contains("/usr/sbin/chown \"$UIDN\""));
        assert!(
            !WRAPPER_SCRIPT.contains('\''),
            "single quotes would break sh_quote embedding"
        );
    }

    #[test]
    fn accepts_only_the_mktemp_directory_pattern() {
        assert!(is_wrapper_dir("/private/tmp/gp-connect.Ab3dE6gH"));
        for bad in [
            "/private/tmp/gp-connect.Ab3dE6g",
            "/private/tmp/gp-connect.Ab3dE6gHi",
            "/private/tmp/gp-connect.Ab3dE6g/",
            "/private/tmp/gp-connect.../x/aa",
            "/tmp/gp-connect.Ab3dE6gH",
            "/private/tmp/gp-connect.Ab3dE6g-",
            "",
        ] {
            assert!(!is_wrapper_dir(bad), "{bad}");
        }
    }

    #[test]
    fn detects_a_dismissed_dialog() {
        assert!(is_cancelled("execution error: User canceled. (-128)"));
        assert!(is_cancelled("CANCELLED"));
        assert!(!is_cancelled("execution error: something else (-60005)"));
    }

    #[test]
    fn parses_pid_and_status_files() {
        assert_eq!(parse_pid_file("4242\n"), Some(4242));
        assert_eq!(parse_pid_file("4242"), Some(4242));
        assert_eq!(parse_pid_file(""), None);
        assert_eq!(parse_pid_file("1\n"), None);
        assert_eq!(parse_pid_file("-5"), None);
        assert_eq!(parse_pid_file("12 34"), None);
        assert_eq!(parse_status_file("0\n"), Some(0));
        assert_eq!(parse_status_file("130"), Some(130));
        assert_eq!(parse_status_file("x"), None);
        assert_eq!(parse_status_file(""), None);
    }
}
