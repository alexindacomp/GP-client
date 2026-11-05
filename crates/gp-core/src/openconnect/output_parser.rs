//! Parsing of openconnect stdout/stderr. Pure, and
//! stateful only where the output format requires it (gateway list).

use std::sync::LazyLock;

use regex::Regex;

use crate::types::{Gateway, VpnErrorCode};

#[derive(Debug, Clone, PartialEq)]
pub enum OcEvent {
    Connected { ip: String },
    Esp,
    Authenticated,
    GatewayList { count: usize },
    Gateway(Gateway),
    AuthFailed { message: String },
    Error { code: VpnErrorCode, message: String },
    SessionLost { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcPrompt {
    Select { label: String, options: Vec<String> },
    Secret { label: String },
    Text { label: String },
    CertConfirm,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

static CONNECTED_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?:Connected|Configured) as ([0-9a-fA-F.:]+?)(?:,|\s|$)"));
static ESP_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)ESP session established with server"));
static AUTHENTICATED_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)GlobalProtect login returned|Tunnel timeout \(rekey interval\)|Gateway address in config XML|Got CONNECT response: HTTP/1\.[01] 200",
    )
});
static GATEWAY_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^(\d+) gateway servers? available:?\s*$"));
static GATEWAY_ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s+(.+?)\s+\(([^()\s]+)\)(?:\s*\[(\d+(?:\.\d+)?)\])?\s*$"));
static AUTH_FAILED_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)Login failed|Invalid username or password|Authentication failed|Unexpected 512 result|auth(?:entication)? error|Invalid (?:user ?name|password|credentials)|password (?:is )?(?:incorrect|expired)",
    )
});
static SESSION_LOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)Session terminated by server|Server terminated connection|Unrecoverable I/O error; exiting|Reconnect failed|Session (?:has )?expired|Cookie was rejected by server",
    )
});
static PRIVILEGES_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)Operation not permitted|Permission denied|Access is denied|Not authorized|Request dismissed|a password is required|must be run as root|administrator privileges|User canceled|\(-128\)",
    )
});
static PRIVILEGES_CONTEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)tun|tap|wintun|adapter|device|route|pkexec|sudo|executing command|privilege|administrator|cancel|-128|authoriz|password is required|root",
    )
});
static TUNNEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)Failed to (?:bind|open|set up|create|configure)[^.]*\b(?:tun|tap|wintun|adapter|device)\b|Set up tun(?: device)? failed|Script '.*' returned error|vpnc-script.*(?:error|failed)|(?:Could not|Cannot|Unable to) (?:open|create|load) (?:the )?Wintun|No tun device",
    )
});
static TLS_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)certificate verify failed|failed verification|SSL connection failure|handshake failed|GnuTLS error|TLS (?:connection|handshake) (?:failed|error)|certificate (?:has )?expired|self[- ]signed certificate",
    )
});
static DNS_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)getaddrinfo failed for host|Name or service not known|Temporary failure in name resolution|No such host is known|nodename nor servname",
    )
});
static UNREACHABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)Failed to connect to host|Failed to open HTTPS connection|Connection refused|No route to host|Network is unreachable|Connection timed out|Failed to connect to .*:\d+",
    )
});
static BAD_OPTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)unrecognized option|invalid option|Unknown VPN protocol|option .* requires an argument")
});

/// Classifies one line of output.
pub fn parse_line(line: &str) -> Option<OcEvent> {
    let text = line.trim();
    if text.is_empty() {
        return None;
    }
    let error = |code| {
        Some(OcEvent::Error {
            code,
            message: text.to_string(),
        })
    };

    if let Some(c) = CONNECTED_RE.captures(text)
        && c[1].len() >= 2
    {
        return Some(OcEvent::Connected { ip: c[1].to_string() });
    }
    if ESP_RE.is_match(text) {
        return Some(OcEvent::Esp);
    }
    if AUTHENTICATED_RE.is_match(text) {
        return Some(OcEvent::Authenticated);
    }
    // Order matters: a tun "Operation not permitted" is a privilege problem.
    if PRIVILEGES_RE.is_match(text) && PRIVILEGES_CONTEXT_RE.is_match(text) {
        return error(VpnErrorCode::PrivilegesDenied);
    }
    if TUNNEL_RE.is_match(text) {
        return error(VpnErrorCode::TunnelFailed);
    }
    if TLS_RE.is_match(text) {
        return error(VpnErrorCode::TlsError);
    }
    if AUTH_FAILED_RE.is_match(text) {
        return Some(OcEvent::AuthFailed {
            message: text.to_string(),
        });
    }
    if SESSION_LOST_RE.is_match(text) {
        return Some(OcEvent::SessionLost {
            message: text.to_string(),
        });
    }
    if DNS_RE.is_match(text) || UNREACHABLE_RE.is_match(text) {
        return error(VpnErrorCode::PortalUnreachable);
    }
    if BAD_OPTION_RE.is_match(text) {
        return error(VpnErrorCode::Unknown);
    }
    None
}

/// Stateful wrapper: understands the multi-line gateway list.
#[derive(Debug, Default)]
pub struct OutputParser {
    gateways_expected: usize,
}

impl OutputParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&mut self, line: &str) -> Option<OcEvent> {
        if self.gateways_expected > 0 {
            if let Some(c) = GATEWAY_ENTRY_RE.captures(line) {
                self.gateways_expected -= 1;
                return Some(OcEvent::Gateway(Gateway {
                    name: c[1].trim().to_string(),
                    address: c[2].to_string(),
                    priority: c.get(3).and_then(|m| m.as_str().parse().ok()),
                }));
            }
            self.gateways_expected = 0;
        }
        if let Some(c) = GATEWAY_HEADER_RE.captures(line.trim())
            && let Ok(count) = c[1].parse::<usize>()
        {
            self.gateways_expected = count;
            return Some(OcEvent::GatewayList { count });
        }
        parse_line(line)
    }
}

static CERT_PROMPT_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)Enter 'yes' to accept, 'no' to abort; anything else to view:\s*$"));
static SELECT_PROMPT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^(.*?)\s*\[([^\]]+)\]:\s*$"));
static SECRET_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)pass(?:word|code|wd)?|challenge|token|otp|one[- ]time|\bpin\b|\bcode\b|response|verification|secret",
    )
});
static GENERIC_PROMPT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^([^\n]{1,200}?):\s*$"));
static WORDISH_RE: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z\x{0400}-\x{04FF}]"));
static TRAILING_COLON_RE: LazyLock<Regex> = LazyLock::new(|| re(r":\s*$"));

/// Recognises an interactive prompt in a trailing, newline-less fragment of output (openconnect
/// prints `Label:` without a newline and waits for stdin).
pub fn parse_prompt(fragment: &str) -> Option<OcPrompt> {
    let cleaned = fragment.replace('\r', "");
    let text = cleaned.rsplit('\n').next().unwrap_or("").trim();
    if text.is_empty() {
        return None;
    }
    if CERT_PROMPT_RE.is_match(text) {
        return Some(OcPrompt::CertConfirm);
    }
    if let Some(c) = SELECT_PROMPT_RE.captures(text) {
        let options: Vec<String> = c[2]
            .split('|')
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .map(String::from)
            .collect();
        if !options.is_empty() {
            let label = TRAILING_COLON_RE.replace(&c[1], "").trim().to_string();
            return Some(OcPrompt::Select { label, options });
        }
    }
    let c = GENERIC_PROMPT_RE.captures(text)?;
    let label = c[1].trim().to_string();
    // Timestamps/addresses like "10:20" are not prompts; require a word-ish label.
    if label.is_empty() || !WORDISH_RE.is_match(&label) {
        return None;
    }
    Some(if SECRET_LABEL_RE.is_match(&label) {
        OcPrompt::Secret { label }
    } else {
        OcPrompt::Text { label }
    })
}

/// Splits a text stream into lines while remembering the trailing fragment.
///
/// Accepts LF, CRLF and lone CR (openconnect.exe on Windows and the UAC bridge may emit CRLF).
/// A CR at the very end of the received data is kept pending: it may be the first half of a CRLF
/// split across two reads, or the end of a prompt such as "Password:\r" — either way the fragment
/// must stay a partial line so prompt detection still sees it.
#[derive(Debug, Default)]
pub struct LineSplitter {
    pending: String,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &str) -> Vec<String> {
        let data = std::mem::take(&mut self.pending) + chunk;
        let mut lines = Vec::new();
        let mut current = String::new();
        let mut chars = data.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\n' => lines.push(std::mem::take(&mut current)),
                '\r' => match chars.peek() {
                    Some('\n') => {
                        chars.next();
                        lines.push(std::mem::take(&mut current));
                    }
                    // A lone CR splits lines only when something follows it in this data.
                    Some(_) => lines.push(std::mem::take(&mut current)),
                    None => current.push('\r'),
                },
                c => current.push(c),
            }
        }
        self.pending = current;
        lines
    }

    /// The current newline-less tail (e.g. an interactive prompt).
    pub fn partial(&self) -> &str {
        &self.pending
    }

    /// Returns and clears the tail.
    pub fn take_partial(&mut self) -> String {
        std::mem::take(&mut self.pending)
    }

    /// Remaining text at end of stream (a dangling CR is dropped).
    pub fn flush(&mut self) -> Vec<String> {
        let p = self.take_partial();
        let p = p.strip_suffix('\r').unwrap_or(&p);
        if p.is_empty() {
            Vec::new()
        } else {
            vec![p.to_string()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/../../fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn gw(name: &str, address: &str, priority: Option<f64>) -> Gateway {
        Gateway {
            name: name.into(),
            address: address.into(),
            priority,
        }
    }

    fn session_events() -> Vec<OcEvent> {
        let mut p = OutputParser::new();
        fixture("openconnect-gp-session.txt")
            .split('\n')
            .filter_map(|l| p.parse(l))
            .collect()
    }

    #[test]
    fn full_session_reports_the_gateway_list() {
        let ev = session_events();
        let lists: Vec<_> = ev
            .iter()
            .filter(|e| matches!(e, OcEvent::GatewayList { .. }))
            .collect();
        assert_eq!(lists, [&OcEvent::GatewayList { count: 2 }]);
        let gws: Vec<_> = ev
            .iter()
            .filter(|e| matches!(e, OcEvent::Gateway(_)))
            .cloned()
            .collect();
        assert_eq!(
            gws,
            [
                OcEvent::Gateway(gw("Europe", "gw-eu.example.com", Some(1.0))),
                OcEvent::Gateway(gw("US East", "gw-us.example.com", Some(2.0)))
            ]
        );
    }

    #[test]
    fn full_session_reports_authentication_ip_and_esp_in_order_without_errors() {
        let ev: Vec<_> = session_events()
            .into_iter()
            .filter(|e| !matches!(e, OcEvent::Gateway(_) | OcEvent::GatewayList { .. }))
            .collect();
        assert_eq!(
            ev,
            [
                OcEvent::Authenticated,
                OcEvent::Authenticated,
                OcEvent::Connected {
                    ip: "10.8.0.42".into()
                },
                OcEvent::Esp
            ]
        );
    }

    #[test]
    fn gateway_entries_without_priority_and_end_of_list() {
        let mut p = OutputParser::new();
        p.parse("1 gateway server available:");
        assert_eq!(
            p.parse("  Only (only.example.com)"),
            Some(OcEvent::Gateway(gw("Only", "only.example.com", None)))
        );
        assert_eq!(p.parse("  Other (x.example.com)"), None);
    }

    #[test]
    fn parse_line_connected_and_esp() {
        for (line, ev) in [
            (
                "Connected as 10.0.0.5, using SSL, with ESP in progress",
                OcEvent::Connected {
                    ip: "10.0.0.5".into(),
                },
            ),
            (
                "Connected as fd00::5, using SSL",
                OcEvent::Connected { ip: "fd00::5".into() },
            ),
            (
                "Configured as 192.168.10.2, with SSL connected and ESP in progress",
                OcEvent::Connected {
                    ip: "192.168.10.2".into(),
                },
            ),
            ("ESP session established with server", OcEvent::Esp),
        ] {
            assert_eq!(parse_line(line), Some(ev), "{line}");
        }
    }

    #[test]
    fn parse_line_auth_failures() {
        for line in [
            "Login failed.",
            "Invalid username or password",
            "Unexpected 512 result from server",
            "Authentication failed",
        ] {
            assert!(
                matches!(parse_line(line), Some(OcEvent::AuthFailed { .. })),
                "{line}"
            );
        }
    }

    #[test]
    fn parse_line_error_codes() {
        use VpnErrorCode as C;
        for (line, code) in [
            (
                "getaddrinfo failed for host 'vpn.example.com': Name or service not known",
                C::PortalUnreachable,
            ),
            ("Failed to connect to host vpn.example.com", C::PortalUnreachable),
            (
                "Failed to open HTTPS connection to vpn.example.com",
                C::PortalUnreachable,
            ),
            ("Server certificate verify failed: signer not found", C::TlsError),
            (
                "SSL connection failure: The TLS connection was non-properly terminated.",
                C::TlsError,
            ),
            (
                "Failed to bind local tun device (TUNSETIFF): Operation not permitted",
                C::PrivilegesDenied,
            ),
            (
                "Error executing command as another user: Not authorized",
                C::PrivilegesDenied,
            ),
            (
                "Error executing command as another user: Request dismissed",
                C::PrivilegesDenied,
            ),
            ("sudo: a password is required", C::PrivilegesDenied),
            (
                "Failed to create Wintun adapter: Access is denied.",
                C::PrivilegesDenied,
            ),
            (
                "Script '/usr/share/vpnc-scripts/vpnc-script' returned error 1",
                C::TunnelFailed,
            ),
            ("Set up tun device failed", C::TunnelFailed),
            ("openconnect: unrecognized option '--bogus'", C::Unknown),
        ] {
            assert_eq!(
                parse_line(line),
                Some(OcEvent::Error {
                    code,
                    message: line.into()
                }),
                "{line}"
            );
        }
    }

    #[test]
    fn parse_line_session_lost_and_informational_lines() {
        for line in [
            "Session terminated by server; exiting.",
            "Unrecoverable I/O error; exiting.",
            "Cookie was rejected by server; exiting.",
        ] {
            assert!(
                matches!(parse_line(line), Some(OcEvent::SessionLost { .. })),
                "{line}"
            );
        }
        for line in [
            "User cancelled (SIGINT/SIGTERM); exiting.",
            "POST https://vpn.example.com/ssl-vpn/login.esp",
            "Connected to 203.0.113.10:443",
            "Using Wintun device \"GP Connect\"",
            "Idle timeout is 180 minutes.",
            "",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }

    #[test]
    fn parse_prompt_kinds() {
        assert_eq!(
            parse_prompt("GATEWAY: [Europe|US East]:"),
            Some(OcPrompt::Select {
                label: "GATEWAY".into(),
                options: vec!["Europe".into(), "US East".into()]
            })
        );
        for p in ["Password:", "Challenge: ", "Enter passcode:", "Token code:"] {
            assert!(matches!(parse_prompt(p), Some(OcPrompt::Secret { .. })), "{p}");
        }
        assert_eq!(
            parse_prompt("Username:"),
            Some(OcPrompt::Text {
                label: "Username".into()
            })
        );
        assert_eq!(
            parse_prompt("Enter the code\nResponse:"),
            Some(OcPrompt::Secret {
                label: "Response".into()
            })
        );
        assert_eq!(
            parse_prompt("Enter 'yes' to accept, 'no' to abort; anything else to view: "),
            Some(OcPrompt::CertConfirm)
        );
        for p in [
            "",
            "Connected as 10.0.0.1",
            "10:20:",
            "POST https://vpn.example.com/x",
        ] {
            assert_eq!(parse_prompt(p), None, "{p}");
        }
        // Cyrillic labels are prompts too (the secret heuristic is English-only, as in TS).
        assert_eq!(
            parse_prompt("Пароль:"),
            Some(OcPrompt::Text {
                label: "Пароль".into()
            })
        );
    }

    #[test]
    fn line_splitter_joins_chunks_and_keeps_the_trailing_fragment() {
        let mut s = LineSplitter::new();
        assert!(s.push("Conn").is_empty());
        assert_eq!(s.push("ected as 1.2.3.4\r\nESP"), ["Connected as 1.2.3.4"]);
        assert_eq!(s.push(" ok\nPassword:"), ["ESP ok"]);
        assert_eq!(s.partial(), "Password:");
        assert_eq!(s.take_partial(), "Password:");
        assert_eq!(s.partial(), "");
        s.push("tail");
        assert_eq!(s.flush(), ["tail"]);
    }

    #[test]
    fn line_splitter_crlf_split_across_chunks() {
        let mut s = LineSplitter::new();
        assert!(s.push("Connected as 1.2.3.4\r").is_empty());
        assert_eq!(s.partial(), "Connected as 1.2.3.4\r");
        assert_eq!(
            s.push("\nESP session established with server\r\n"),
            ["Connected as 1.2.3.4", "ESP session established with server"]
        );
        assert_eq!(s.partial(), "");
    }

    #[test]
    fn line_splitter_lone_cr() {
        let mut s = LineSplitter::new();
        assert_eq!(
            s.push("progress 10%\rprogress 20%\n"),
            ["progress 10%", "progress 20%"]
        );
        let mut s = LineSplitter::new();
        assert_eq!(s.push("Enter code\r\nPassword:\r"), ["Enter code"]);
        assert_eq!(
            parse_prompt(s.partial()),
            Some(OcPrompt::Secret {
                label: "Password".into()
            })
        );
        assert_eq!(s.take_partial(), "Password:\r");
        let mut s = LineSplitter::new();
        s.push("Session terminated by server; exiting.\r");
        assert_eq!(s.flush(), ["Session terminated by server; exiting."]);
        let mut s = LineSplitter::new();
        let lines: Vec<String> = s
            .push("a\r\r\nb\r\n")
            .into_iter()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines, ["a", "b"]);
    }

    #[test]
    fn prompts_and_lines_with_cr_classify_like_lf() {
        assert_eq!(
            parse_prompt("GATEWAY: [Europe|US East]:\r"),
            Some(OcPrompt::Select {
                label: "GATEWAY".into(),
                options: vec!["Europe".into(), "US East".into()]
            })
        );
        assert_eq!(
            parse_prompt("Username:\r"),
            Some(OcPrompt::Text {
                label: "Username".into()
            })
        );
        assert_eq!(
            parse_prompt("Enter 'yes' to accept, 'no' to abort; anything else to view: \r"),
            Some(OcPrompt::CertConfirm)
        );
        let mut p = OutputParser::new();
        assert_eq!(
            p.parse("2 gateway servers available:\r"),
            Some(OcEvent::GatewayList { count: 2 })
        );
        assert_eq!(
            p.parse("  Europe (gw-eu.example.com) [1]\r"),
            Some(OcEvent::Gateway(gw("Europe", "gw-eu.example.com", Some(1.0))))
        );
        assert_eq!(
            parse_line("Connected as 10.0.0.5, using SSL\r"),
            Some(OcEvent::Connected {
                ip: "10.0.0.5".into()
            })
        );
    }
}
