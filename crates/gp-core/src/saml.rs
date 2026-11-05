//! SAML helpers: what the SAML window must load, and
//! extraction/validation of the GlobalProtect auth result from response headers or HTML.

use std::collections::HashMap;
use std::sync::LazyLock;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::prelogin::xml::get_tag_text;
use crate::prelogin::{AuthType, PreloginResult, SamlMethod};
use crate::types::Profile;
use crate::util::js_len;
use crate::validation::url_host;
use crate::vpn::VpnError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamlCookieName {
    PreloginCookie,
    PortalUserauthcookie,
}

impl SamlCookieName {
    pub fn as_str(self) -> &'static str {
        match self {
            SamlCookieName::PreloginCookie => "prelogin-cookie",
            SamlCookieName::PortalUserauthcookie => "portal-userauthcookie",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SamlSuccess {
    pub username: String,
    pub cookie_name: SamlCookieName,
    pub cookie: String,
}

impl std::fmt::Debug for SamlSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlSuccess")
            .field("username", &self.username)
            .field("cookie_name", &self.cookie_name)
            .field("cookie", &"***")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlOutcome {
    Success(SamlSuccess),
    Failure { message: String },
}

/// What the SAML window should load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlLoadTarget {
    /// REDIRECT: an https URL.
    Url(String),
    /// POST: the auto-submitting HTML form, also as a `data:` URL.
    Html { html: String, data_url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SamlTargetError(pub String);

/// Node's lenient base64 (`-`/`_` accepted, padding optional, whitespace ignored).
fn decode_base64(b64: &str) -> Result<String, SamlTargetError> {
    static B64_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]*={0,2}$").expect("valid regex"));
    static LENIENT: LazyLock<GeneralPurpose> = LazyLock::new(|| {
        GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_padding_mode(DecodePaddingMode::Indifferent)
                .with_decode_allow_trailing_bits(true),
        )
    });
    let normalized: String = b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let invalid = || SamlTargetError("SAML request is not valid base64".into());
    if !B64_RE.is_match(&normalized) {
        return Err(invalid());
    }
    let bytes = LENIENT
        .decode(normalized.trim_end_matches('='))
        .map_err(|_| invalid())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// What the SAML window should load for the given prelogin result.
pub fn build_saml_load_target(prelogin: &PreloginResult) -> Result<SamlLoadTarget, SamlTargetError> {
    let (AuthType::Saml, Some(request), Some(method)) = (
        prelogin.auth_type,
        prelogin.saml_request.as_deref(),
        prelogin.saml_method,
    ) else {
        return Err(SamlTargetError(
            "Prelogin result does not contain a SAML request".into(),
        ));
    };
    let decoded = decode_base64(request)?;
    let decoded = crate::util::js_trim(&decoded);
    if decoded.is_empty() {
        return Err(SamlTargetError("SAML request is empty".into()));
    }
    match method {
        SamlMethod::Redirect => {
            let url =
                Url::parse(decoded).map_err(|_| SamlTargetError("SAML redirect URL is invalid".into()))?;
            if url.scheme() != "https" {
                return Err(SamlTargetError("SAML redirect URL must use https".into()));
            }
            Ok(SamlLoadTarget::Url(url.to_string()))
        }
        SamlMethod::Post => Ok(SamlLoadTarget::Html {
            html: decoded.to_string(),
            data_url: format!(
                "data:text/html;charset=utf-8;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(decoded)
            ),
        }),
    }
}

fn usable_cookie(v: Option<&str>) -> Option<&str> {
    let t = v?.trim();
    (!t.is_empty() && !t.eq_ignore_ascii_case("empty")).then_some(t)
}

/// Cookie written to openconnect's stdin: printable ASCII, 1–4096 chars.
pub fn is_valid_saml_cookie(v: &str) -> bool {
    (1..=4096).contains(&v.len()) && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Username passed in argv: 1–256 chars, no C0/C1 control characters.
pub fn is_valid_saml_username(v: &str) -> bool {
    let len = js_len(v);
    len > 0
        && len <= 256
        && !v
            .chars()
            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
}

/// The SAML result is accepted only from a top-level https document served by one of the
/// expected hosts (the portal). Results in sub-resources or on IdP / third-party pages are
/// ignored, so a malicious page cannot inject a cookie.
pub fn is_trusted_saml_source(url: &str, top_level_document: bool, allowed_hosts: &[String]) -> bool {
    if !top_level_document {
        return false;
    }
    let Ok(u) = Url::parse(url) else { return false };
    if u.scheme() != "https" {
        return false;
    }
    let host = url_host(&u).to_lowercase();
    allowed_hosts.iter().any(|h| h.to_lowercase() == host)
}

#[derive(Default)]
struct RawFields {
    status: Option<String>,
    username: Option<String>,
    prelogin_cookie: Option<String>,
    user_auth_cookie: Option<String>,
    message: Option<String>,
}

fn failure(message: impl Into<String>) -> SamlOutcome {
    SamlOutcome::Failure {
        message: message.into(),
    }
}

fn evaluate(f: &RawFields) -> Option<SamlOutcome> {
    let status = f.status.as_deref().map(str::trim);
    match status {
        None | Some("") => {
            // Some portals omit the status but still deliver the cookie.
            let has_cookie = usable_cookie(f.prelogin_cookie.as_deref()).is_some()
                || usable_cookie(f.user_auth_cookie.as_deref()).is_some();
            if f.username.as_deref().is_none_or(str::is_empty) || !has_cookie {
                return None;
            }
        }
        Some("1") => {}
        Some(s) => {
            let msg = f.message.clone().filter(|m| !m.is_empty());
            return Some(failure(
                msg.unwrap_or_else(|| format!("SAML authentication failed (status {s})")),
            ));
        }
    }

    let username = f.username.as_deref().map(str::trim).filter(|u| !u.is_empty());
    let prelogin = usable_cookie(f.prelogin_cookie.as_deref());
    let user_auth = usable_cookie(f.user_auth_cookie.as_deref());
    let Some(username) = username.filter(|_| prelogin.is_some() || user_auth.is_some()) else {
        return Some(failure("SAML response did not contain a username and cookie"));
    };
    // Both values are written to openconnect's stdin / argv: no control characters, bounded size.
    if !is_valid_saml_username(username) {
        return Some(failure("SAML response contains an invalid username"));
    }
    let (cookie_name, cookie) = match (prelogin, user_auth) {
        (Some(c), _) => (SamlCookieName::PreloginCookie, c),
        (None, Some(c)) => (SamlCookieName::PortalUserauthcookie, c),
        (None, None) => return Some(failure("SAML response did not contain a username and cookie")),
    };
    if !is_valid_saml_cookie(cookie) {
        return Some(failure("SAML response contains an invalid cookie"));
    }
    Some(SamlOutcome::Success(SamlSuccess {
        username: username.to_string(),
        cookie_name,
        cookie: cookie.to_string(),
    }))
}

/// Looks for the GlobalProtect SAML result in HTTP response headers (names in any case; the
/// first value of a repeated header wins). `None` for ordinary responses.
pub fn extract_saml_from_headers<'a, I>(headers: I) -> Option<SamlOutcome>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut h: HashMap<String, String> = HashMap::new();
    for (k, v) in headers {
        h.entry(k.to_ascii_lowercase())
            .or_insert_with(|| v.trim().to_string());
    }
    if !["saml-auth-status", "prelogin-cookie", "portal-userauthcookie"]
        .iter()
        .any(|k| h.contains_key(*k))
    {
        return None;
    }
    evaluate(&RawFields {
        status: h.remove("saml-auth-status"),
        username: h.remove("saml-username"),
        prelogin_cookie: h.remove("prelogin-cookie"),
        user_auth_cookie: h.remove("portal-userauthcookie"),
        message: h.remove("saml-auth-message"),
    })
}

static SAML_STATUS_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<saml-auth-status>").expect("valid regex"));

/// Looks for the result in the final HTML page, where the portal puts it into a comment:
/// `<!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>…`.
pub fn extract_saml_from_html(html: &str) -> Option<SamlOutcome> {
    if !SAML_STATUS_TAG_RE.is_match(html) {
        return None;
    }
    evaluate(&RawFields {
        status: get_tag_text(html, "saml-auth-status"),
        username: get_tag_text(html, "saml-username"),
        prelogin_cookie: get_tag_text(html, "prelogin-cookie"),
        user_auth_cookie: get_tag_text(html, "portal-userauthcookie"),
        message: get_tag_text(html, "saml-auth-message"),
    })
}

/// Interactive SAML login as seen by the VPN engine (implemented by the app's SAML window).
/// Must return `AUTH_CANCELLED` when the user closes the window and honour `cancel`.
#[async_trait]
pub trait SamlAuthenticator: Send + Sync {
    async fn saml_login(
        &self,
        profile: &Profile,
        prelogin: &PreloginResult,
        cancel: CancellationToken,
    ) -> Result<SamlSuccess, VpnError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelogin::parse_prelogin;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/../../fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[allow(clippy::unnecessary_wraps)] // compared against `Option<SamlOutcome>` results
    fn success(username: &str, cookie_name: SamlCookieName, cookie: &str) -> Option<SamlOutcome> {
        Some(SamlOutcome::Success(SamlSuccess {
            username: username.into(),
            cookie_name,
            cookie: cookie.into(),
        }))
    }

    fn failure_message(o: Option<SamlOutcome>) -> String {
        match o {
            Some(SamlOutcome::Failure { message }) => message,
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn html_extracts_username_and_prelogin_cookie_from_the_comment() {
        assert_eq!(
            extract_saml_from_html(&fixture("saml-success.html")),
            success(
                "j.doe@example.com",
                SamlCookieName::PreloginCookie,
                "PRELOGIN-COOKIE-abc123XYZ"
            )
        );
    }

    #[test]
    fn html_falls_back_to_portal_userauthcookie_when_prelogin_cookie_is_empty() {
        let html = "<!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>empty</prelogin-cookie><portal-userauthcookie>UAC-777</portal-userauthcookie><saml-username>bob</saml-username> -->";
        assert_eq!(
            extract_saml_from_html(html),
            success("bob", SamlCookieName::PortalUserauthcookie, "UAC-777")
        );
    }

    #[test]
    fn html_reports_failures() {
        assert_eq!(
            failure_message(extract_saml_from_html(&fixture("saml-failure.html"))),
            "User is not authorized"
        );
        let r = extract_saml_from_html(
            "<!-- <saml-auth-status>1</saml-auth-status><saml-username>x</saml-username> -->",
        );
        assert!(matches!(r, Some(SamlOutcome::Failure { .. })));
        assert_eq!(
            extract_saml_from_html("<html><form><input name=\"password\"></form></html>"),
            None
        );
    }

    #[test]
    fn headers_are_case_insensitive_and_first_value_wins() {
        assert_eq!(
            extract_saml_from_headers([
                ("Saml-Auth-Status", "1"),
                ("saml-username", "alice@example.com"),
                ("Prelogin-Cookie", "PC-1"),
                ("prelogin-cookie", "PC-2"),
                ("Content-Type", "text/html"),
            ]),
            success("alice@example.com", SamlCookieName::PreloginCookie, "PC-1")
        );
    }

    #[test]
    fn headers_prefer_prelogin_cookie_and_accept_a_missing_status() {
        let r = extract_saml_from_headers([
            ("saml-auth-status", "1"),
            ("saml-username", "a"),
            ("prelogin-cookie", "PC"),
            ("portal-userauthcookie", "UAC"),
        ]);
        assert_eq!(r, success("a", SamlCookieName::PreloginCookie, "PC"));
        let r = extract_saml_from_headers([("saml-username", "a"), ("portal-userauthcookie", "UAC")]);
        assert_eq!(r, success("a", SamlCookieName::PortalUserauthcookie, "UAC"));
    }

    #[test]
    fn headers_report_failure_or_ignore_ordinary_responses() {
        assert!(matches!(
            extract_saml_from_headers([("saml-auth-status", "-1")]),
            Some(SamlOutcome::Failure { .. })
        ));
        assert_eq!(
            extract_saml_from_headers([("content-type", "text/html"), ("set-cookie", "a=b")]),
            None
        );
    }

    #[test]
    fn load_target_for_redirect_is_the_decoded_https_url() {
        let t =
            build_saml_load_target(&parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap()).unwrap();
        let SamlLoadTarget::Url(url) = t else {
            panic!("expected url")
        };
        assert!(url.starts_with("https://idp.example.com/app/sso/saml?SAMLRequest="));
    }

    #[test]
    fn load_target_for_post_is_a_data_url_with_the_form() {
        let t = build_saml_load_target(&parse_prelogin(&fixture("prelogin-saml-post.xml")).unwrap()).unwrap();
        let SamlLoadTarget::Html { html, data_url } = t else {
            panic!("expected html")
        };
        assert!(data_url.starts_with("data:text/html;charset=utf-8;base64,"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data_url.split(',').nth(1).unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), html);
        assert!(html.contains("action=\"https://idp.example.com/sso\""));
    }

    #[test]
    fn load_target_rejects_non_https_redirects_password_prelogins_and_bad_base64() {
        let mut p = PreloginResult::password();
        assert!(build_saml_load_target(&p).is_err());
        p.auth_type = AuthType::Saml;
        p.saml_method = Some(SamlMethod::Redirect);
        p.saml_request = Some(base64::engine::general_purpose::STANDARD.encode("http://idp.example.com/sso"));
        assert!(build_saml_load_target(&p).unwrap_err().0.contains("https"));
        p.saml_request = Some("not base64!".into());
        assert!(build_saml_load_target(&p).unwrap_err().0.contains("base64"));
        // url-safe alphabet and missing padding are accepted like Node does
        p.saml_request =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("https://idp.example.com/?a=>>>"));
        assert!(build_saml_load_target(&p).is_ok());
    }

    #[test]
    fn validates_cookies_and_usernames() {
        assert!(is_valid_saml_cookie("abc-DEF_123+/="));
        assert!(!is_valid_saml_cookie("abc def"));
        assert!(!is_valid_saml_cookie("abc\nINJECTED"));
        assert!(!is_valid_saml_cookie(&"x".repeat(4097)));
        assert!(!is_valid_saml_cookie(""));
        assert!(is_valid_saml_username("j.doe@example.com"));
        assert!(is_valid_saml_username("Иван Петров"));
        assert!(!is_valid_saml_username("bob\n--script=/tmp/x"));
        assert!(!is_valid_saml_username(&"a".repeat(257)));
        assert!(!is_valid_saml_username("a\u{85}b"));
    }

    #[test]
    fn invalid_cookie_or_username_in_a_response_is_a_failure() {
        let r = extract_saml_from_headers([
            ("saml-auth-status", "1"),
            ("saml-username", "bob"),
            ("prelogin-cookie", "a b"),
        ]);
        assert!(failure_message(r).contains("invalid cookie"));
        let r = extract_saml_from_headers([
            ("saml-auth-status", "1"),
            ("saml-username", "bo\u{7}b"),
            ("prelogin-cookie", "ok"),
        ]);
        assert!(failure_message(r).contains("invalid username"));
    }

    #[test]
    fn trusted_source_is_a_top_level_https_document_on_the_portal_host() {
        let hosts = vec!["vpn.example.com".to_string()];
        assert!(is_trusted_saml_source(
            "https://vpn.example.com/SAML20/SP/ACS",
            true,
            &hosts
        ));
        assert!(is_trusted_saml_source("https://VPN.example.com/x", true, &hosts));
        for (url, top) in [
            ("https://vpn.example.com/x", false),
            ("http://vpn.example.com/x", true),
            ("https://idp.example.com/sso", true),
            ("https://vpn.example.com.evil.net/x", true),
            ("https://vpn.example.com:8443/x", true),
            ("data:text/html,<saml-auth-status>1</saml-auth-status>", true),
            ("not a url", true),
        ] {
            assert!(!is_trusted_saml_source(url, top, &hosts), "{url}");
        }
        assert!(is_trusted_saml_source(
            "https://vpn.example.com:8443/x",
            true,
            &["vpn.example.com:8443".into()]
        ));
    }

    #[test]
    fn debug_output_never_shows_the_cookie() {
        let s = SamlSuccess {
            username: "u".into(),
            cookie_name: SamlCookieName::PreloginCookie,
            cookie: "SECRET-1".into(),
        };
        assert!(!format!("{s:?}").contains("SECRET-1"));
    }
}
