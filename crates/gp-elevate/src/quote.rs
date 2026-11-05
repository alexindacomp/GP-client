//! Pure command-line helpers: pkexec wrapping, the
//! privileged kill command, and quoting for POSIX sh, AppleScript and Windows command lines.

use std::fmt;

/// Methods that keep stdio attached to a direct child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalMethod {
    /// Run the binary directly (already root / unprivileged test runs).
    Direct,
    /// `pkexec --disable-internal-agent <binary> …`.
    Pkexec,
}

impl fmt::Display for LocalMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LocalMethod::Direct => "none",
            LocalMethod::Pkexec => "pkexec",
        })
    }
}

/// Where pkexec is looked up, in order. Never resolved through `PATH` (a same-user attacker can
/// prepend a fake `pkexec` that captures the polkit password prompt).
pub const PKEXEC_CANDIDATES: [&str; 2] = ["/usr/bin/pkexec", "/bin/pkexec"];

/// First of [`PKEXEC_CANDIDATES`] for which `exists` holds; `/usr/bin/pkexec` if none does (the
/// spawn then fails with "not found").
pub fn pick_pkexec(exists: impl Fn(&str) -> bool) -> &'static str {
    PKEXEC_CANDIDATES
        .into_iter()
        .find(|p| exists(p))
        .unwrap_or(PKEXEC_CANDIDATES[0])
}

/// [`pick_pkexec`] on the real filesystem.
pub fn pkexec_path() -> &'static str {
    pick_pkexec(|p| std::path::Path::new(p).is_file())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedCommand {
    pub command: String,
    pub args: Vec<String>,
}

/// Command line for the methods that keep stdio attached; `pkexec` is its absolute path.
pub fn wrap_command(method: LocalMethod, pkexec: &str, binary: &str, args: &[String]) -> WrappedCommand {
    match method {
        LocalMethod::Direct => WrappedCommand {
            command: binary.to_string(),
            args: args.to_vec(),
        },
        // No textual agent: there is no TTY, the desktop polkit agent shows the dialog.
        LocalMethod::Pkexec => {
            let mut a = vec!["--disable-internal-agent".to_string(), binary.to_string()];
            a.extend(args.iter().cloned());
            WrappedCommand {
                command: pkexec.into(),
                args: a,
            }
        }
    }
}

/// Signals the app may send to the (root-owned) openconnect process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSignal {
    Int,
    Term,
    Kill,
}

impl StopSignal {
    pub fn name(self) -> &'static str {
        match self {
            StopSignal::Int => "INT",
            StopSignal::Term => "TERM",
            StopSignal::Kill => "KILL",
        }
    }
}

/// Command that sends `signal` to a root-owned `pid` through pkexec. `None` for pids that must
/// never be signalled (init, process groups, "all processes").
pub fn privileged_kill_command(pkexec: &str, pid: i64, signal: StopSignal) -> Option<WrappedCommand> {
    if pid <= 1 || pid > i64::from(i32::MAX) {
        return None;
    }
    Some(WrappedCommand {
        command: pkexec.into(),
        args: vec![
            "--disable-internal-agent".into(),
            "/bin/kill".into(),
            "-s".into(),
            signal.name().into(),
            pid.to_string(),
        ],
    })
}

/// POSIX shell single-quoting.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Quoting for a Windows command line as parsed by the MSVC runtime (CommandLineToArgvW rules).
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c.is_whitespace() || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Escapes a string for use inside an AppleScript double-quoted string literal.
pub fn apple_script_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "/usr/bin/pkexec";

    #[test]
    fn pkexec_is_always_an_absolute_system_path() {
        assert_eq!(pick_pkexec(|_| true), "/usr/bin/pkexec");
        assert_eq!(pick_pkexec(|p| p == "/bin/pkexec"), "/bin/pkexec");
        assert_eq!(pick_pkexec(|_| false), "/usr/bin/pkexec");
        assert!(pkexec_path().starts_with('/'));
    }

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn prefixes_pkexec_without_the_textual_agent() {
        assert_eq!(
            wrap_command(
                LocalMethod::Pkexec,
                PK,
                "/usr/sbin/openconnect",
                &strings(&["-v"])
            ),
            WrappedCommand {
                command: PK.into(),
                args: strings(&["--disable-internal-agent", "/usr/sbin/openconnect", "-v"]),
            }
        );
        assert_eq!(
            wrap_command(LocalMethod::Direct, PK, "/x", &strings(&["a"])),
            WrappedCommand {
                command: "/x".into(),
                args: strings(&["a"]),
            }
        );
    }

    #[test]
    fn builds_a_privileged_kill_and_validates_the_pid() {
        assert_eq!(
            privileged_kill_command(PK, 4242, StopSignal::Int),
            Some(WrappedCommand {
                command: PK.into(),
                args: strings(&["--disable-internal-agent", "/bin/kill", "-s", "INT", "4242"]),
            })
        );
        assert_eq!(privileged_kill_command(PK, 1, StopSignal::Kill), None);
        assert_eq!(privileged_kill_command(PK, 0, StopSignal::Kill), None);
        assert_eq!(privileged_kill_command(PK, -5, StopSignal::Kill), None);
        assert_eq!(privileged_kill_command(PK, 1 << 40, StopSignal::Kill), None);
    }

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("$(rm -rf ~) `x` \"y\""), "'$(rm -rf ~) `x` \"y\"'");
    }

    #[test]
    fn quote_windows_arg_follows_the_msvc_rules() {
        for (input, expected) in [
            ("simple", "simple"),
            ("with space", "\"with space\""),
            ("", "\"\""),
            ("say \"hi\"", r#""say \"hi\"""#),
            ("C:\\Program Files\\", r#""C:\Program Files\\""#),
            ("a\\\\\"b", r#""a\\\\\"b""#),
            ("tab\there", "\"tab\there\""),
        ] {
            assert_eq!(quote_windows_arg(input), expected, "{input:?}");
        }
    }

    #[test]
    fn apple_script_string_escapes_backslashes_and_quotes() {
        assert_eq!(apple_script_string("a \"b\" \\c"), r#""a \"b\" \\c""#);
    }
}
