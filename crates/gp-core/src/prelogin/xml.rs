//! Minimal helpers for the flat XML documents returned by GlobalProtect endpoints. Regex-based on purpose: the same helpers read the SAML result from an
//! HTML comment, which an XML parser would not see.

use std::sync::LazyLock;

use regex::{Captures, Regex};

static ENTITY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)&(#x[0-9a-f]+|#[0-9]+|[a-z]+);").expect("valid regex"));
static CDATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*<!\[CDATA\[((?s:.)*?)\]\]>\s*$").expect("valid regex"));

pub fn decode_xml_entities(s: &str) -> String {
    ENTITY_RE
        .replace_all(s, |c: &Captures<'_>| {
            let ent = &c[1];
            if let Some(num) = ent.strip_prefix('#') {
                let code = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse::<u32>().ok(),
                };
                return code
                    .filter(|&n| n > 0)
                    .and_then(char::from_u32)
                    .map_or_else(|| c[0].to_string(), String::from);
            }
            match ent.to_ascii_lowercase().as_str() {
                "amp" => "&".into(),
                "lt" => "<".into(),
                "gt" => ">".into(),
                "quot" => "\"".into(),
                "apos" => "'".into(),
                _ => c[0].to_string(),
            }
        })
        .into_owned()
}

/// Text content of the first `<tag>` element (no nesting support — not needed for prelogin/SAML
/// documents). `None` if the tag is absent, `Some("")` if empty or self-closing. CDATA sections
/// are unwrapped.
pub fn get_tag_text(xml: &str, tag: &str) -> Option<String> {
    let t = regex::escape(tag);
    let full = Regex::new(&format!(r"(?i)<{t}(?:\s[^>]*)?>((?s:.)*?)</{t}\s*>")).expect("valid regex");
    if let Some(c) = full.captures(xml) {
        let raw = c.get(1).map_or("", |m| m.as_str());
        if let Some(cd) = CDATA_RE.captures(raw) {
            return Some(cd[1].to_string());
        }
        return Some(decode_xml_entities(crate::util::js_trim(raw)));
    }
    let empty = Regex::new(&format!(r"(?i)<{t}(?:\s[^>]*)?/>")).expect("valid regex");
    empty.is_match(xml).then(String::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_entities() {
        assert_eq!(
            decode_xml_entities("a &amp; b &LT;x&gt; &#65;&#x42; &bogus; &#0;"),
            "a & b <x> AB &bogus; &#0;"
        );
    }

    #[test]
    fn reads_tags_cdata_and_self_closing() {
        let xml = "<r><a x=\"1\"> v &amp; w </a><b/><c><![CDATA[<raw>]]></c></r>";
        assert_eq!(get_tag_text(xml, "a").as_deref(), Some("v & w"));
        assert_eq!(get_tag_text(xml, "B").as_deref(), Some(""));
        assert_eq!(get_tag_text(xml, "c").as_deref(), Some("<raw>"));
        assert_eq!(get_tag_text(xml, "d"), None);
    }
}
