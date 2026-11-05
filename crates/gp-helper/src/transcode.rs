//! openconnect output → UTF-8 for the app. openconnect.exe writes its own messages as UTF-8, but
//! Windows error texts (FormatMessage, e.g. "Этот хост неизвестен.") come in the console's code
//! page (OEM, cp866 on Russian Windows). Each line is decoded as UTF-8 when it is valid UTF-8,
//! otherwise with the console code page (`fallback`).
//!
//! The decision is made per complete line, never per pipe read: code-page bytes form valid UTF-8
//! by accident in short fragments (cp866 "тен" is the UTF-8 sequence `E2 A5 AD`), but practically
//! never across a whole line. Complete lines (ending in `\n` or `\r`) are forwarded at once; an
//! unterminated tail (a prompt like "Password:") is forwarded as a whole by [`flush`] once the
//! stream is idle (see `relay`) or ends. Every byte is forwarded exactly once.
//!
//! [`flush`]: LineTranscoder::flush

use std::borrow::Cow;

/// Decodes bytes that are not valid UTF-8 (the console code page on Windows).
pub type Fallback = dyn Fn(&[u8]) -> String + Sync;

/// `fallback` for systems whose console output is UTF-8 anyway.
pub fn utf8_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One line (or fragment): UTF-8 if valid, else `fallback`.
pub fn decode_line<'a>(bytes: &'a [u8], fallback: &Fallback) -> Cow<'a, str> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(fallback(bytes)),
    }
}

/// Per-stream state (stdout and stderr each have one).
#[derive(Debug, Default)]
pub struct LineTranscoder {
    pending: Vec<u8>,
}

impl LineTranscoder {
    /// The complete lines in the data so far (empty while a line is still incomplete).
    pub fn push(&mut self, data: &[u8], fallback: &Fallback) -> String {
        self.pending.extend_from_slice(data);
        let Some(last) = self.pending.iter().rposition(|b| matches!(b, b'\n' | b'\r')) else {
            return String::new();
        };
        let mut out = String::new();
        for line in self.pending[..=last].split_inclusive(|b| matches!(b, b'\n' | b'\r')) {
            out.push_str(&decode_line(line, fallback));
        }
        self.pending.drain(..=last);
        out
    }

    /// An unterminated tail is waiting.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The unterminated tail as a whole (prompt, or the rest when the stream ends).
    pub fn flush(&mut self, fallback: &Fallback) -> String {
        let out = decode_line(&self.pending, fallback).into_owned();
        self.pending.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cp866 for the Cyrillic letters (А–п at 0x80–0xAF, р–я at 0xE0–0xEF); ASCII as is.
    fn cp866(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|&b| match b {
                0x80..=0xAF => char::from_u32(0x0410 + u32::from(b - 0x80)).unwrap_or('?'),
                0xE0..=0xEF => char::from_u32(0x0440 + u32::from(b - 0xE0)).unwrap_or('?'),
                b if b.is_ascii() => char::from(b),
                _ => '?',
            })
            .collect()
    }

    /// "Этот хост неизвестен." in cp866.
    pub(crate) const HOST_UNKNOWN_866: &[u8] = &[
        0x9D, 0xE2, 0xAE, 0xE2, 0x20, 0xE5, 0xAE, 0xE1, 0xE2, 0x20, 0xAD, 0xA5, 0xA8, 0xA7, 0xA2, 0xA5, 0xE1,
        0xE2, 0xA5, 0xAD, 0x2E,
    ];
    const HOST_LINE: &str = "getaddrinfo failed for host 'gp-qa-test.invalid': Этот хост неизвестен.\r\n";

    fn line_866() -> Vec<u8> {
        let mut l = b"getaddrinfo failed for host 'gp-qa-test.invalid': ".to_vec();
        l.extend_from_slice(HOST_UNKNOWN_866);
        l.extend_from_slice(b"\r\n");
        l
    }

    #[test]
    fn code_page_lines_are_decoded_with_the_fallback() {
        let mut t = LineTranscoder::default();
        assert_eq!(t.push(&line_866(), &cp866), HOST_LINE);
        assert!(!t.has_pending());
    }

    #[test]
    fn utf8_lines_stay_utf8_next_to_code_page_lines() {
        let mut t = LineTranscoder::default();
        let mut data = "Подключено к шлюзу\n".as_bytes().to_vec();
        data.extend(line_866());
        data.extend_from_slice("ESP ✓\n".as_bytes());
        assert_eq!(
            t.push(&data, &cp866),
            format!("Подключено к шлюзу\n{HOST_LINE}ESP ✓\n")
        );
    }

    #[test]
    fn every_chunking_gives_exactly_the_same_text() {
        let mut data = "Пароль для alice\n".as_bytes().to_vec();
        data.extend(line_866());
        data.extend_from_slice("Password:".as_bytes());
        let want = format!("Пароль для alice\n{HOST_LINE}Password:");
        for size in 1..=data.len() {
            let mut t = LineTranscoder::default();
            let mut out = String::new();
            for chunk in data.chunks(size) {
                out.push_str(&t.push(chunk, &cp866));
            }
            out.push_str(&t.flush(&cp866));
            assert_eq!(out, want, "chunk size {size}");
        }
    }

    #[test]
    fn an_unterminated_prompt_is_flushed_as_a_whole() {
        let mut t = LineTranscoder::default();
        assert_eq!(t.push(b"Password:", &cp866), "");
        assert!(t.has_pending());
        assert_eq!(t.flush(&cp866), "Password:");
        assert!(!t.has_pending());
        // A code-page prompt split in UTF-8-looking pieces is still decoded with the code page.
        assert_eq!(t.push(&HOST_UNKNOWN_866[..3], &cp866), "");
        assert_eq!(t.push(&HOST_UNKNOWN_866[3..], &cp866), "");
        assert_eq!(t.flush(&cp866), "Этот хост неизвестен.");
        assert_eq!(t.flush(&cp866), "");
    }
}
