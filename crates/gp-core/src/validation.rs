//! Port of `src/shared/validation.ts`: the pure rules shared by the backend (authoritative)
//! and the renderer. Both implementations are checked against `fixtures/validation-cases.json`.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::util::{is_js_space, js_len, js_trim};

/// `CONTROL_CHARS_RE`: U+0000–U+001F and U+007F.
pub fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}

// ------------------------------------------------------------------ portal URL

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalUrlErrorCode {
    Empty,
    TooLong,
    Invalid,
    NotHttps,
    Credentials,
}

impl PortalUrlErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            PortalUrlErrorCode::Empty => "empty",
            PortalUrlErrorCode::TooLong => "too_long",
            PortalUrlErrorCode::Invalid => "invalid",
            PortalUrlErrorCode::NotHttps => "not_https",
            PortalUrlErrorCode::Credentials => "credentials",
        }
    }

    /// English message.
    pub fn message(self) -> &'static str {
        match self {
            PortalUrlErrorCode::Empty | PortalUrlErrorCode::TooLong | PortalUrlErrorCode::Invalid => {
                "Invalid portal URL"
            }
            PortalUrlErrorCode::NotHttps => "Only https:// portals are supported",
            PortalUrlErrorCode::Credentials => "Portal URL must not contain credentials",
        }
    }
}

static SCHEME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z][a-z0-9+.\-]*://").expect("valid regex"));

/// `host` of a WHATWG URL: hostname plus `:port` when the port is not the scheme default.
pub(crate) fn url_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

/// Normalises user input into an https portal base URL (`https://host[:port]`).
/// A bare host is accepted; any other scheme, credentials or garbage is not.
pub fn normalize_portal_url(input: &str) -> Result<String, PortalUrlErrorCode> {
    let trimmed = js_trim(input);
    if trimmed.is_empty() {
        return Err(PortalUrlErrorCode::Empty);
    }
    if js_len(trimmed) > 2048 {
        return Err(PortalUrlErrorCode::TooLong);
    }
    if trimmed.chars().any(is_js_space) || has_control_chars(trimmed) {
        return Err(PortalUrlErrorCode::Invalid);
    }
    let with_scheme = if SCHEME_RE.is_match(trimmed) {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = Url::parse(&with_scheme).map_err(|_| PortalUrlErrorCode::Invalid)?;
    if url.scheme() != "https" {
        return Err(PortalUrlErrorCode::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PortalUrlErrorCode::Credentials);
    }
    if url.host_str().is_none_or(str::is_empty) || url.port() == Some(0) {
        return Err(PortalUrlErrorCode::Invalid);
    }
    Ok(format!("https://{}", url_host(&url)))
}

// ------------------------------------------------------------------ extra openconnect args

pub const MAX_EXTRA_ARGS: usize = 32;
pub const MAX_EXTRA_ARG_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy)]
enum ValueRule {
    /// Flag without value.
    Flag,
    Pin,
    Range(u32, u32),
    Ciphers,
}

/// Allowlist of extra openconnect options. openconnect runs as root, so only options that
/// cannot load files, run commands, redirect traffic or weaken TLS trust are accepted. Names
/// must match exactly (no getopt prefixes/bundles).
const EXTRA_OPTIONS: &[(&str, ValueRule)] = &[
    ("-v", ValueRule::Flag),
    ("--verbose", ValueRule::Flag),
    ("-q", ValueRule::Flag),
    ("--quiet", ValueRule::Flag),
    ("--timestamp", ValueRule::Flag),
    ("--no-dtls", ValueRule::Flag),
    ("--disable-ipv6", ValueRule::Flag),
    ("--servercert", ValueRule::Pin),
    ("--mtu", ValueRule::Range(576, 9000)),
    ("--base-mtu", ValueRule::Range(576, 9000)),
    ("--reconnect-timeout", ValueRule::Range(0, 86_400)),
    ("--force-dpd", ValueRule::Range(1, 3600)),
    ("--dtls-ciphers", ValueRule::Ciphers),
    ("--dtls12-ciphers", ValueRule::Ciphers),
];

static PIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^pin-sha256:[A-Za-z0-9+/]{43}=$").expect("valid regex"));
static CIPHERS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9:+!._\-]{1,256}$").expect("valid regex"));

fn rule_of(name: &str) -> Option<ValueRule> {
    EXTRA_OPTIONS.iter().find(|(n, _)| *n == name).map(|(_, r)| *r)
}

fn value_ok(rule: ValueRule, v: &str) -> bool {
    match rule {
        ValueRule::Flag => false,
        ValueRule::Pin => PIN_RE.is_match(v),
        ValueRule::Ciphers => CIPHERS_RE.is_match(v),
        ValueRule::Range(min, max) => {
            (1..=6).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_digit())
                && v.parse::<u32>().is_ok_and(|n| (min..=max).contains(&n))
        }
    }
}

/// Names of the options accepted in extra arguments.
pub fn allowed_extra_options() -> Vec<&'static str> {
    EXTRA_OPTIONS.iter().map(|(n, _)| *n).collect()
}

/// Whether the allowlisted option takes a `=value`.
pub fn extra_option_takes_value(name: &str) -> bool {
    rule_of(name).is_some_and(|r| !matches!(r, ValueRule::Flag))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtraArgErrorCode {
    NotAllowed,
    BadValue,
    TooMany,
    TooLong,
    NotNameValue,
}

impl ExtraArgErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExtraArgErrorCode::NotAllowed => "not_allowed",
            ExtraArgErrorCode::BadValue => "bad_value",
            ExtraArgErrorCode::TooMany => "too_many",
            ExtraArgErrorCode::TooLong => "too_long",
            ExtraArgErrorCode::NotNameValue => "not_name_value",
        }
    }
}

/// A rejected extra argument: the code and the offending (trimmed) argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraArgError {
    pub code: ExtraArgErrorCode,
    pub arg: String,
}

fn split_option(arg: &str) -> (&str, Option<&str>) {
    match arg.find('=') {
        Some(i) => (&arg[..i], Some(&arg[i + 1..])),
        None => (arg, None),
    }
}

/// Option name of an argument (`--mtu=1400` → `--mtu`).
pub fn option_name(arg: &str) -> &str {
    split_option(arg).0
}

/// Checks one (already trimmed) argument.
pub fn check_extra_arg(arg: &str) -> Result<(), ExtraArgError> {
    let err = |code| {
        Err(ExtraArgError {
            code,
            arg: arg.to_string(),
        })
    };
    if arg.is_empty() || has_control_chars(arg) {
        return err(ExtraArgErrorCode::BadValue);
    }
    if js_len(arg) > MAX_EXTRA_ARG_LENGTH {
        return err(ExtraArgErrorCode::TooLong);
    }
    let (name, value) = split_option(arg);
    let Some(rule) = rule_of(name) else {
        return err(ExtraArgErrorCode::NotAllowed);
    };
    match (rule, value) {
        (ValueRule::Flag, None) => Ok(()),
        (ValueRule::Flag, Some(_)) | (_, None) => err(ExtraArgErrorCode::NotNameValue),
        (rule, Some(v)) if value_ok(rule, v) => Ok(()),
        _ => err(ExtraArgErrorCode::BadValue),
    }
}

/// Validates the whole list; returns trimmed arguments on success.
pub fn check_extra_args<S: AsRef<str>>(args: &[S]) -> Result<Vec<String>, ExtraArgError> {
    if args.len() > MAX_EXTRA_ARGS {
        return Err(ExtraArgError {
            code: ExtraArgErrorCode::TooMany,
            arg: String::new(),
        });
    }
    let mut out = Vec::with_capacity(args.len());
    for a in args {
        let arg = js_trim(a.as_ref());
        check_extra_arg(arg)?;
        out.push(arg.to_string());
    }
    Ok(out)
}

/// `String(v)` in JavaScript for a JSON value (used to report non-string input).
pub(crate) fn js_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|i| if i.is_null() { String::new() } else { js_string(i) })
            .collect::<Vec<_>>()
            .join(","),
        serde_json::Value::Object(_) => "[object Object]".into(),
        other => other.to_string(),
    }
}

/// [`check_extra_args`] for untrusted JSON input (IPC payloads, files on disk).
pub fn check_extra_args_value(args: &serde_json::Value) -> Result<Vec<String>, ExtraArgError> {
    let Some(items) = args.as_array() else {
        return Err(ExtraArgError {
            code: ExtraArgErrorCode::BadValue,
            arg: js_string(args),
        });
    };
    if items.len() > MAX_EXTRA_ARGS {
        return Err(ExtraArgError {
            code: ExtraArgErrorCode::TooMany,
            arg: String::new(),
        });
    }
    let mut strings = Vec::with_capacity(items.len());
    for item in items {
        match item.as_str() {
            Some(s) => strings.push(s),
            None => {
                return Err(ExtraArgError {
                    code: ExtraArgErrorCode::BadValue,
                    arg: js_string(item),
                });
            }
        }
    }
    check_extra_args(&strings)
}

// ------------------------------------------------------------------ paths

/// Absolute path on Windows (`C:\…`, `C:/…`, UNC) or POSIX (`/…`).
pub fn is_absolute_path(p: &str) -> bool {
    let b = p.as_bytes();
    p.starts_with('/')
        || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with("\\\\")
}

/// The configured binary must be openconnect itself (`openconnect` / `openconnect.exe`).
pub fn is_openconnect_binary_path(p: &str) -> bool {
    let base = p.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    base == "openconnect" || base == "openconnect.exe"
}

/// Windows: extensions a HIP `--csd-wrapper` script may have (run as administrator, so no
/// arbitrary file types such as `.ps1`, `.vbs` or `.lnk`).
pub const WINDOWS_HIP_SCRIPT_EXTENSIONS: [&str; 4] = [".js", ".cmd", ".bat", ".exe"];

/// Whether `p` has one of [`WINDOWS_HIP_SCRIPT_EXTENSIONS`] (case-insensitive).
pub fn is_allowed_windows_hip_script(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    WINDOWS_HIP_SCRIPT_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

// ------------------------------------------------------------------ IPC error markers

/// Machine-readable error info carried in front of the English message:
/// `[field:<name>][code:<code>] message` (see `parseIpcError` in src/shared/validation.ts).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcErrorInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

impl fmt::Display for IpcErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_ipc_error(
            self.field.as_deref(),
            self.code.as_deref(),
            &self.message,
        ))
    }
}

/// `formatIpcError`.
pub fn format_ipc_error(field: Option<&str>, code: Option<&str>, message: &str) -> String {
    let field = field
        .filter(|f| !f.is_empty())
        .map(|f| format!("[field:{f}]"))
        .unwrap_or_default();
    let code = code
        .filter(|c| !c.is_empty())
        .map(|c| format!("[code:{c}]"))
        .unwrap_or_default();
    if field.is_empty() && code.is_empty() {
        message.to_string()
    } else {
        format!("{field}{code} {message}")
    }
}

static ELECTRON_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Error invoking remote method '[^']*': (?:\w*Error: )?").expect("valid regex")
});
static FIELD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[field:([A-Za-z0-9_.\-]+)\]").expect("valid regex"));
static CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[code:([A-Za-z0-9_.\-]+)\]").expect("valid regex"));
static MARKERS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\[(?:field|code):[A-Za-z0-9_.\-]+\])+\s*").expect("valid regex"));

/// `parseIpcError` for a message string.
pub fn parse_ipc_error(raw: &str) -> IpcErrorInfo {
    let text = ELECTRON_PREFIX_RE.replace(raw, "");
    let field = FIELD_RE.captures(&text).map(|c| c[1].to_string());
    let code = CODE_RE.captures(&text).map(|c| c[1].to_string());
    let message = MARKERS_RE.replace(&text, "").into_owned();
    IpcErrorInfo { field, code, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// `deny_unknown_fields`: a vector group added to the JSON must get a runner here too
    /// (src/shared/validation.cases.test.ts has the same guard).
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Cases {
        #[serde(rename = "$comment")]
        _comment: Value,
        portal_url: Vec<Value>,
        extra_arg: Vec<Value>,
        extra_args: Vec<Value>,
        absolute_path: Vec<Value>,
        openconnect_binary_path: Vec<Value>,
        control_chars: Vec<Value>,
        ipc_error: IpcCases,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IpcCases {
        format: Vec<Value>,
        parse: Vec<Value>,
    }

    fn cases() -> Cases {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/validation-cases.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("validation-cases.json")).unwrap()
    }

    /// A string, or `{repeat, times, prefix, suffix}`.
    fn text(v: &Value) -> String {
        if let Some(s) = v.as_str() {
            return s.to_string();
        }
        let times = usize::try_from(v["times"].as_u64().unwrap()).unwrap();
        format!(
            "{}{}{}",
            v["prefix"].as_str().unwrap_or(""),
            v["repeat"].as_str().unwrap().repeat(times),
            v["suffix"].as_str().unwrap_or("")
        )
    }

    /// An args value, or `{repeatItem, times}` → array.
    fn args(v: &Value) -> Value {
        if let Some(item) = v.get("repeatItem") {
            let times = usize::try_from(v["times"].as_u64().unwrap()).unwrap();
            return Value::Array(vec![item.clone(); times]);
        }
        v.clone()
    }

    #[test]
    fn validation_cases_portal_url() {
        let cases = cases().portal_url;
        assert!(cases.len() > 40);
        for c in cases {
            let input = text(&c["input"]);
            let got = normalize_portal_url(&input);
            if c["ok"].as_bool().unwrap() {
                assert_eq!(got.as_deref(), Ok(c["url"].as_str().unwrap()), "input {input:?}");
            } else {
                assert_eq!(
                    got.map_err(PortalUrlErrorCode::as_str),
                    Err(c["code"].as_str().unwrap()),
                    "input {input:?}"
                );
            }
        }
    }

    #[test]
    fn validation_cases_extra_arg() {
        let cases = cases().extra_arg;
        assert!(cases.len() > 50);
        for c in cases {
            let arg = text(&c["arg"]);
            let got = check_extra_arg(&arg).map_err(|e| (e.code.as_str(), e.arg));
            if c["ok"].as_bool().unwrap() {
                assert_eq!(got, Ok(()), "arg {arg:?}");
            } else {
                assert_eq!(
                    got,
                    Err((c["code"].as_str().unwrap(), arg.clone())),
                    "arg {arg:?}"
                );
            }
        }
    }

    #[test]
    fn validation_cases_extra_args() {
        for c in cases().extra_args {
            let input = args(&c["args"]);
            let got = check_extra_args_value(&input).map_err(|e| (e.code.as_str().to_string(), e.arg));
            if c["ok"].as_bool().unwrap() {
                let want: Vec<String> = serde_json::from_value(args(&c["result"])).unwrap();
                assert_eq!(got, Ok(want), "args {input}");
            } else {
                let want = (
                    c["code"].as_str().unwrap().to_string(),
                    c["arg"].as_str().unwrap().to_string(),
                );
                assert_eq!(got, Err(want), "args {input}");
            }
        }
    }

    #[test]
    fn validation_cases_paths_and_control_chars() {
        let c = cases();
        for v in c.absolute_path {
            let p = v["path"].as_str().unwrap();
            assert_eq!(is_absolute_path(p), v["absolute"].as_bool().unwrap(), "{p:?}");
        }
        for v in c.openconnect_binary_path {
            let p = v["path"].as_str().unwrap();
            assert_eq!(is_openconnect_binary_path(p), v["ok"].as_bool().unwrap(), "{p:?}");
        }
        for v in c.control_chars {
            let t = v["text"].as_str().unwrap();
            assert_eq!(has_control_chars(t), v["match"].as_bool().unwrap(), "{t:?}");
        }
    }

    #[test]
    fn validation_cases_ipc_error() {
        let c = cases().ipc_error;
        for v in c.format {
            let got = format_ipc_error(
                v["field"].as_str(),
                v["code"].as_str(),
                v["message"].as_str().unwrap(),
            );
            assert_eq!(got, v["text"].as_str().unwrap());
        }
        for v in c.parse {
            let want: IpcErrorInfo = serde_json::from_value(v["expected"].clone()).unwrap();
            assert_eq!(parse_ipc_error(v["text"].as_str().unwrap()), want);
        }
    }

    #[test]
    fn exposes_the_allowlist_names() {
        let names = allowed_extra_options();
        assert!(names.contains(&"--no-dtls"));
        assert!(!names.contains(&"--script"));
        assert!(extra_option_takes_value("--mtu"));
        assert!(!extra_option_takes_value("-v"));
        assert!(!extra_option_takes_value("--script"));
    }

    #[test]
    fn non_string_items_are_reported_like_js_string() {
        assert_eq!(js_string(&json!(null)), "null");
        assert_eq!(js_string(&json!(1)), "1");
        assert_eq!(js_string(&json!(true)), "true");
        assert_eq!(js_string(&json!({"a": 1})), "[object Object]");
    }

    #[test]
    fn portal_url_is_idempotent() {
        for input in ["пример.рф", "[2001:db8::1]:8443", "VPN.example.com:443/x"] {
            let first = normalize_portal_url(input).unwrap();
            assert_eq!(normalize_portal_url(&first).unwrap(), first);
        }
    }
}
