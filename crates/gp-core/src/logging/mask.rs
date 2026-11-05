//! Secret masking for log lines. Everything that reaches the
//! log buffer, the log file or the UI goes through [`mask_secrets`].

use std::sync::{LazyLock, Mutex};

use regex::{Captures, Regex};

use crate::util::{encode_uri_component, js_len};

pub const MASK: &str = "***";

/// Secrets at least this long are masked wherever they occur (substring match). Shorter secrets
/// (1–3 chars, e.g. a PIN or a short password) are masked only as whole tokens, otherwise every
/// "a" or "12" inside other words/IPs would vanish.
const MIN_SECRET_LENGTH: usize = 4;

const SECRET_KEYS: &[&str] = &[
    "prelogin-cookie",
    "portal-userauthcookie",
    "portal-prelogonuserauthcookie",
    "authcookie",
    "passwd",
    "password",
    "passcode",
    "cookie",
    "token",
    "secret",
    "samlresponse",
    "saml-request",
    "otp",
];

/// `<prelogin-cookie>value</prelogin-cookie>` — one regex per key (no backreferences in `regex`).
static XML_TAG_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    SECRET_KEYS
        .iter()
        .map(|k| {
            let k = regex::escape(k);
            Regex::new(&format!("(?i)<({k})>[^<]*</{k}>")).expect("valid regex")
        })
        .collect()
});

/// `Cookie: a=b; c=d`, `Set-Cookie: ...`, `Authorization: Bearer x` — mask the whole header value.
static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(set-cookie|cookie|authorization|proxy-authorization)(\s*:\s*)(\S.*)$")
        .expect("valid regex")
});

/// `key=value`, `key: value`, `--cookie=value`, `COOKIE='value'`.
static KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = SECRET_KEYS.join("|");
    Regex::new(&format!(
        r#"(?i)(^|[\s&?;,"'(<\-])({keys})(\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s&;,"'<>)]+)"#
    ))
    .expect("valid regex")
});

/// Characters allowed right before a short secret (besides start of line).
fn token_before(c: char) -> bool {
    c.is_whitespace() || "\"'=,;([<".contains(c)
}

/// What may follow a short secret: end, whitespace, a quote, `,;)]>&`, or sentence punctuation
/// (`.:!?`) that is itself followed by whitespace/end.
fn token_after(rest: &str) -> bool {
    let mut it = rest.chars();
    match it.next() {
        None => true,
        Some(c) if c.is_whitespace() || "\"',;)]>&".contains(c) => true,
        Some('.' | ':' | '!' | '?') => it.next().is_none_or(char::is_whitespace),
        Some(_) => false,
    }
}

/// Whole-token replacement of a short secret (see `maskShortToken`).
fn mask_short_token(line: &str, secret: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut last_end = 0; // end of the previous match in `line`
    let mut copied = 0;
    let mut search = 0;
    while let Some(off) = line[search..].find(secret) {
        let i = search + off;
        let end = i + secret.len();
        let before_ok = if i == 0 {
            true
        } else {
            // The preceding character is consumed by the JS regex, so it must not belong to the
            // previous match.
            let prev = line[..i].chars().next_back().expect("i > 0");
            i - prev.len_utf8() >= last_end && token_before(prev)
        };
        if before_ok && token_after(&line[end..]) {
            out.push_str(&line[copied..i]);
            out.push_str(MASK);
            copied = end;
            last_end = end;
            search = end;
        } else {
            search = i + line[i..].chars().next().map_or(1, char::len_utf8);
        }
        if search > line.len() {
            break;
        }
    }
    out.push_str(&line[copied..]);
    out
}

/// Masks known secret values (also URL-encoded) and well-known secret fields.
pub fn mask_secrets<S: AsRef<str>>(line: &str, known_secrets: &[S]) -> String {
    let mut out = line.to_string();

    let mut long: Vec<&str> = known_secrets
        .iter()
        .map(AsRef::as_ref)
        .filter(|s| js_len(s) >= MIN_SECRET_LENGTH)
        .collect();
    long.sort_by_key(|s| std::cmp::Reverse(js_len(s)));
    for secret in long {
        out = out.replace(secret, MASK);
        // Cookies are often URL-encoded in HTTP traces.
        let encoded = encode_uri_component(secret);
        if encoded != secret {
            out = out.replace(&encoded, MASK);
        }
    }

    let mut short: Vec<&str> = known_secrets
        .iter()
        .map(AsRef::as_ref)
        .filter(|s| !s.is_empty() && js_len(s) < MIN_SECRET_LENGTH)
        .collect();
    short.sort_by_key(|s| std::cmp::Reverse(js_len(s)));
    for secret in short {
        out = mask_short_token(&out, secret);
    }

    for re in XML_TAG_RES.iter() {
        out = re
            .replace_all(&out, |c: &Captures<'_>| format!("<{0}>{MASK}</{0}>", &c[1]))
            .into_owned();
    }
    out = HEADER_RE
        .replace_all(&out, |c: &Captures<'_>| format!("{}{}{MASK}", &c[1], &c[2]))
        .into_owned();
    out = KV_RE
        .replace_all(&out, |c: &Captures<'_>| {
            let value = &c[4];
            // "Password:" prompt without a value, or a value that is already masked.
            if value == MASK || value.is_empty() {
                c[0].to_string()
            } else {
                format!("{}{}{}{MASK}", &c[1], &c[2], &c[3])
            }
        })
        .into_owned();
    out
}

/// Registry of runtime secrets (passwords, cookies) to be masked by value. Thread-safe.
#[derive(Debug, Default)]
pub struct SecretRegistry {
    secrets: Mutex<Vec<String>>,
}

impl SecretRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn list(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Short secrets are kept too; [`mask_secrets`] masks them as whole tokens only.
    pub fn add(&self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let mut l = self.list();
        if !l.iter().any(|s| s == secret) {
            l.push(secret.to_string());
        }
    }

    pub fn delete(&self, secret: &str) {
        self.list().retain(|s| s != secret);
    }

    pub fn contains(&self, secret: &str) -> bool {
        self.list().iter().any(|s| s == secret)
    }

    pub fn mask(&self, line: &str) -> String {
        let secrets = self.list().clone();
        mask_secrets(line, &secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: &[&str] = &[];

    #[test]
    fn masks_well_known_fields() {
        let cases = [
            ("prelogin-cookie=abc123&user=x", "prelogin-cookie=***&user=x"),
            ("portal-userauthcookie: QWERTY", "portal-userauthcookie: ***"),
            (
                "POST body: user=bob&passwd=hunter2&ok=1",
                "POST body: user=bob&passwd=***&ok=1",
            ),
            (
                "<prelogin-cookie>XYZ</prelogin-cookie>",
                "<prelogin-cookie>***</prelogin-cookie>",
            ),
            ("Cookie: SESSION=1; other=2", "Cookie: ***"),
            ("Set-Cookie: a=b; HttpOnly", "Set-Cookie: ***"),
            ("Authorization: Bearer abc.def", "Authorization: ***"),
            ("COOKIE='authcookie=1&portal=2'", "COOKIE=***"),
            (
                "openconnect --cookie=secretvalue https://x",
                "openconnect --cookie=*** https://x",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(mask_secrets(input, NONE), expected, "{input}");
        }
    }

    #[test]
    fn keeps_prompts_and_labels_intact() {
        for s in [
            "Password:",
            "<password-label>Password</password-label>",
            "Connected as 10.0.0.1, using SSL",
        ] {
            assert_eq!(mask_secrets(s, NONE), s);
        }
    }

    #[test]
    fn masks_known_secret_values_anywhere_including_url_encoded() {
        let secrets = ["s3cr3t+pass/word", "COOKIEVALUE"];
        assert_eq!(
            mask_secrets("echo s3cr3t+pass/word and COOKIEVALUE", &secrets),
            "echo *** and ***"
        );
        assert_eq!(mask_secrets("q=s3cr3t%2Bpass%2Fword", &secrets), "q=***");
    }

    #[test]
    fn does_not_mask_very_short_values_inside_words() {
        assert_eq!(mask_secrets("abc", &["ab"]), "abc");
    }

    #[test]
    fn registry_adds_and_removes_secrets() {
        let r = SecretRegistry::new();
        r.add("topsecret");
        assert_eq!(r.mask("x topsecret y"), "x *** y");
        r.delete("topsecret");
        assert_eq!(r.mask("x topsecret y"), "x topsecret y");
        r.add("42");
        assert_eq!(r.mask("PIN 42 rejected"), "PIN *** rejected");
    }

    #[test]
    fn short_secrets_are_masked_as_whole_tokens_only() {
        let masked = [
            ("Login failed for abc", "Login failed for ***", "abc"),
            ("Login failed for abc.", "Login failed for ***.", "abc"),
            ("user=bob&pin=12&x", "user=bob&pin=***&x", "12"),
            ("\"abc\" rejected", "\"***\" rejected", "abc"),
            ("abc abc", "*** ***", "abc"),
            ("(abc)", "(***)", "abc"),
        ];
        for (line, expected, secret) in masked {
            assert_eq!(mask_secrets(line, &[secret]), expected, "{line}");
        }
        let kept = [
            ("abcdef", "abc"),
            ("Connected as 10.0.12.1", "12"),
            ("xabc", "abc"),
            ("abc-def", "abc"),
            ("Login failed", "a"),
            ("https://abc.example.com/x", "abc"),
        ];
        for (line, secret) in kept {
            assert_eq!(mask_secrets(line, &[secret]), line, "{line}");
        }
    }

    #[test]
    fn short_token_handles_adjacent_and_unicode_text() {
        assert_eq!(mask_secrets("abc,abc", &["abc"]), "***,***");
        assert_eq!(mask_secrets("ж abc ж", &["abc"]), "ж *** ж");
        assert_eq!(mask_secrets("aaa", &["a"]), "aaa");
        assert_eq!(
            mask_secrets("sudo: a password is required", &["a"]),
            "sudo: *** password is required"
        );
    }
}
