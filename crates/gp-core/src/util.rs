//! Small helpers that reproduce JavaScript semantics the TS implementation relies on
//! (string length in UTF-16 units, `String.prototype.trim`, `encodeURIComponent`) and
//! `path.posix` / `path.win32` operations used on paths of the *target* platform.

/// `s.length` in JavaScript (UTF-16 code units).
pub(crate) fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JavaScript whitespace for `trim()` and `/\s/`: Unicode White_Space plus U+FEFF.
pub(crate) fn is_js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// `s.trim()` in JavaScript.
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// First `max` UTF-16 units of `s` (never splits a character).
pub(crate) fn js_truncate(s: &str, max: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > max {
            return &s[..i];
        }
    }
    s
}

/// `encodeURIComponent`.
pub(crate) fn encode_uri_component(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

pub(crate) mod posix {
    /// `path.posix.isAbsolute`.
    pub(crate) fn is_absolute(p: &str) -> bool {
        p.starts_with('/')
    }

    /// `path.posix.normalize` (keeps a trailing slash, `.` for empty).
    pub(crate) fn normalize(p: &str) -> String {
        if p.is_empty() {
            return ".".into();
        }
        let absolute = p.starts_with('/');
        let trailing = p.ends_with('/');
        let mut parts: Vec<&str> = Vec::new();
        for seg in p.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    if parts.last().is_some_and(|l| *l != "..") {
                        parts.pop();
                    } else if !absolute {
                        parts.push("..");
                    }
                }
                s => parts.push(s),
            }
        }
        let mut out = parts.join("/");
        if absolute {
            out.insert(0, '/');
        }
        if out.is_empty() {
            return ".".into();
        }
        if trailing && !out.ends_with('/') {
            out.push('/');
        }
        out
    }

    /// `path.posix.join(a, b)`.
    pub(crate) fn join(a: &str, b: &str) -> String {
        normalize(&format!("{a}/{b}"))
    }

    /// `path.posix.dirname`.
    pub(crate) fn dirname(p: &str) -> String {
        let trimmed = p.trim_end_matches('/');
        if trimmed.is_empty() {
            return if p.starts_with('/') {
                "/".into()
            } else {
                ".".into()
            };
        }
        match trimmed.rfind('/') {
            None => ".".into(),
            Some(0) => "/".into(),
            Some(i) => trimmed[..i].trim_end_matches('/').to_string(),
        }
    }
}

pub(crate) mod win {
    fn is_sep(c: char) -> bool {
        c == '\\' || c == '/'
    }

    fn has_drive(p: &str) -> bool {
        let b = p.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    }

    /// `path.win32.isAbsolute`.
    pub(crate) fn is_absolute(p: &str) -> bool {
        p.starts_with(is_sep) || (has_drive(p) && p[2..].starts_with(is_sep))
    }

    /// Splits into (root, rest): `C:\`, `\\server\share\`, `\`, `C:` or ``.
    fn split_root(p: &str) -> (String, &str) {
        let chars: Vec<char> = p.chars().take(2).collect();
        if chars.len() == 2 && is_sep(chars[0]) && is_sep(chars[1]) {
            // UNC: \\server\share
            let rest = &p[2..];
            let mut it = rest.splitn(3, is_sep);
            let server = it.next().unwrap_or("");
            let share = it.next().unwrap_or("");
            let tail = it.next().unwrap_or("");
            return (format!("\\\\{server}\\{share}\\"), tail);
        }
        if has_drive(p) {
            let drive = &p[..2];
            if p[2..].starts_with(is_sep) {
                return (format!("{drive}\\"), &p[3..]);
            }
            return (drive.to_string(), &p[2..]);
        }
        if p.starts_with(is_sep) {
            return ("\\".into(), &p[1..]);
        }
        (String::new(), p)
    }

    /// `path.win32.normalize` for the path shapes used here (drive, UNC, rooted, relative).
    pub(crate) fn normalize(p: &str) -> String {
        if p.is_empty() {
            return ".".into();
        }
        let trailing = p.ends_with(is_sep);
        let (root, rest) = split_root(p);
        let rooted = root.ends_with('\\');
        let mut parts: Vec<&str> = Vec::new();
        for seg in rest.split(is_sep) {
            match seg {
                "" | "." => {}
                ".." => {
                    if parts.last().is_some_and(|l| *l != "..") {
                        parts.pop();
                    } else if !rooted {
                        parts.push("..");
                    }
                }
                s => parts.push(s),
            }
        }
        let body = parts.join("\\");
        let mut out = format!("{root}{body}");
        if out.is_empty() {
            return ".".into();
        }
        if trailing && !body.is_empty() {
            out.push('\\');
        }
        out
    }

    /// `path.win32.join(a, b)`.
    pub(crate) fn join(a: &str, b: &str) -> String {
        normalize(&format!("{a}\\{b}"))
    }

    /// `path.win32.dirname` (root stays root).
    pub(crate) fn dirname(p: &str) -> String {
        let (root, rest) = split_root(p);
        let rest = rest.trim_end_matches(is_sep);
        match rest.rfind(is_sep) {
            Some(i) => format!("{root}{}", rest[..i].trim_end_matches(is_sep)),
            None if root.is_empty() => ".".into(),
            None => root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_string_helpers() {
        assert_eq!(js_len("a😀"), 3);
        assert_eq!(js_trim("\u{feff} x \n"), "x");
        assert_eq!(js_truncate("abc😀d", 4), "abc");
        assert_eq!(js_truncate("abc😀d", 5), "abc😀");
        assert_eq!(encode_uri_component("s3cr3t+pass/word"), "s3cr3t%2Bpass%2Fword");
        assert_eq!(encode_uri_component("a b@ü"), "a%20b%40%C3%BC");
        assert_eq!(encode_uri_component("Az09-_.!~*'()"), "Az09-_.!~*'()");
    }

    #[test]
    fn posix_paths() {
        assert_eq!(
            posix::join("/usr/local/bin/", "openconnect"),
            "/usr/local/bin/openconnect"
        );
        assert_eq!(posix::join("/a/../b", "x"), "/b/x");
        assert_eq!(posix::dirname("/usr/sbin/openconnect"), "/usr/sbin");
        assert_eq!(posix::dirname("/usr"), "/");
        assert_eq!(posix::dirname("/"), "/");
    }

    #[test]
    fn win_paths() {
        assert!(win::is_absolute("C:\\x"));
        assert!(win::is_absolute("c:/x"));
        assert!(win::is_absolute("\\\\server\\share"));
        assert!(!win::is_absolute("C:x"));
        assert!(!win::is_absolute("relative\\x"));
        assert_eq!(
            win::join("C:\\Tools", "openconnect.exe"),
            "C:\\Tools\\openconnect.exe"
        );
        assert_eq!(
            win::join("C:/Quoted Dir/", "openconnect.exe"),
            "C:\\Quoted Dir\\openconnect.exe"
        );
        assert_eq!(win::normalize("C:\\a\\..\\b\\.\\c"), "C:\\b\\c");
        assert_eq!(win::normalize("C:\\Program Files\\"), "C:\\Program Files\\");
        assert_eq!(
            win::dirname("C:\\Program Files\\A\\b.exe"),
            "C:\\Program Files\\A"
        );
        assert_eq!(win::dirname("C:\\Program Files"), "C:\\");
        assert_eq!(win::dirname("C:\\"), "C:\\");
    }
}
