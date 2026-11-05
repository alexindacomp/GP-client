//! Portal prelogin: parse `prelogin.esp`, build its URL and
//! fetch it over an injectable HTTP transport with manual redirects (https, same host, ≤ 3 hops)
//! and a 1 MiB body cap.

pub mod xml;

#[cfg(feature = "http")]
mod reqwest_transport;
#[cfg(feature = "http")]
pub use reqwest_transport::ReqwestTransport;

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::platform::Platform;
use crate::types::VpnErrorCode;
use crate::validation::{PortalUrlErrorCode, normalize_portal_url, url_host};
use crate::vpn::VpnError;
use xml::get_tag_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Saml,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SamlMethod {
    Redirect,
    Post,
}

impl SamlMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            SamlMethod::Redirect => "REDIRECT",
            SamlMethod::Post => "POST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResult {
    /// `Saml` when the portal returned a SAML request, otherwise `Password`.
    pub auth_type: AuthType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_method: Option<SamlMethod>,
    /// Base64 payload of `<saml-request>` (URL for REDIRECT, HTML form for POST).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl PreloginResult {
    /// A password-only result without labels.
    pub fn password() -> Self {
        PreloginResult {
            auth_type: AuthType::Password,
            saml_method: None,
            saml_request: None,
            auth_message: None,
            username_label: None,
            password_label: None,
            region: None,
        }
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

static PRELOGIN_RESPONSE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<prelogin-response[\s>]").expect("valid regex"));

/// Parses a `prelogin.esp` response body.
pub fn parse_prelogin(xml: &str) -> Result<PreloginResult, VpnError> {
    if !PRELOGIN_RESPONSE_RE.is_match(xml) {
        return Err(VpnError::new(
            VpnErrorCode::PortalUnreachable,
            "Unexpected prelogin response (not a GlobalProtect portal?)",
        ));
    }
    if let Some(status) = get_tag_text(xml, "status")
        && !status.eq_ignore_ascii_case("success")
    {
        let msg = non_empty(get_tag_text(xml, "msg")).unwrap_or_else(|| "Portal returned an error".into());
        return Err(VpnError::new(
            VpnErrorCode::AuthFailed,
            format!("Prelogin failed: {msg}"),
        ));
    }

    let saml_request = non_empty(get_tag_text(xml, "saml-request").map(|s| s.split_whitespace().collect()));
    let raw_method = non_empty(get_tag_text(xml, "saml-auth-method")).map(|m| m.to_uppercase());
    let saml_method = match raw_method.as_deref() {
        Some("REDIRECT") => Some(SamlMethod::Redirect),
        Some("POST") => Some(SamlMethod::Post),
        _ => None,
    };

    let mut result = PreloginResult {
        auth_type: if saml_request.is_some() {
            AuthType::Saml
        } else {
            AuthType::Password
        },
        saml_method: None,
        saml_request: None,
        auth_message: non_empty(get_tag_text(xml, "authentication-message"))
            .or_else(|| non_empty(get_tag_text(xml, "auth-message"))),
        username_label: non_empty(get_tag_text(xml, "username-label")),
        password_label: non_empty(get_tag_text(xml, "password-label")),
        region: non_empty(get_tag_text(xml, "region")),
    };
    if let Some(req) = saml_request {
        let Some(method) = saml_method else {
            return Err(VpnError::new(
                VpnErrorCode::AuthFailed,
                format!(
                    "Unsupported SAML auth method: {}",
                    raw_method.as_deref().unwrap_or("(none)")
                ),
            ));
        };
        result.saml_method = Some(method);
        result.saml_request = Some(req);
    }
    Ok(result)
}

/// `clientos` sent in prelogin.
pub fn client_os_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Win32 => "Windows",
        Platform::Darwin => "Mac",
        Platform::Linux => "Linux",
    }
}

pub fn build_prelogin_url(portal_url: &str, platform: Platform) -> Result<String, PortalUrlErrorCode> {
    let base = normalize_portal_url(portal_url)?;
    Ok(format!(
        "{base}/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos={}",
        client_os_for(platform)
    ))
}

// ------------------------------------------------------------------ HTTP transport

/// One HTTP request. Transports must never follow redirects themselves (`follow_redirects` is
/// always `false` here); [`fetch_prelogin`] validates every hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub follow_redirects: bool,
}

/// Network / TLS failure. `message` should contain the whole error chain (it is classified by
/// text into TLS_ERROR vs PORTAL_UNREACHABLE and shown as the technical detail).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    pub message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        TransportError {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait HttpBody: Send {
    /// Next chunk of the body, `None` at the end.
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, TransportError>;
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn HttpBody>,
}

impl HttpResponse {
    /// First value of a header (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// In-memory body (tests, fakes).
pub struct BytesBody(Option<Vec<u8>>);

impl BytesBody {
    pub fn boxed(data: impl Into<Vec<u8>>) -> Box<dyn HttpBody> {
        Box::new(BytesBody(Some(data.into())))
    }
}

#[async_trait]
impl HttpBody for BytesBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.0.take().filter(|d| !d.is_empty()))
    }
}

// ------------------------------------------------------------------ fetch

pub const MAX_PRELOGIN_REDIRECTS: usize = 3;
pub const MAX_PRELOGIN_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_PRELOGIN_TIMEOUT: Duration = Duration::from_secs(15);

static TLS_ERROR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)cert|ssl|tls|self[- ]signed|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_CERT|handshake|hostname/ip does not match",
    )
    .expect("valid regex")
});

fn classify_network_error(e: &TransportError) -> VpnErrorCode {
    if TLS_ERROR_RE.is_match(&e.message) {
        VpnErrorCode::TlsError
    } else {
        VpnErrorCode::PortalUnreachable
    }
}

fn unreachable(msg: impl Into<String>) -> VpnError {
    VpnError::new(VpnErrorCode::PortalUnreachable, msg)
}

/// Reads the body, refusing anything larger than `max` bytes.
async fn read_capped_text(res: &mut HttpResponse, max: usize) -> Result<String, VpnError> {
    let too_large = || unreachable("Prelogin response is too large");
    if let Some(declared) = res
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        && declared > max as u64
    {
        return Err(too_large());
    }
    let mut data = Vec::new();
    while let Some(chunk) = res
        .body
        .next_chunk()
        .await
        .map_err(|e| VpnError::new(classify_network_error(&e), format!("Cannot reach portal: {e}")))?
    {
        if data.len() + chunk.len() > max {
            return Err(too_large());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

pub struct PreloginRequestOptions<'a> {
    pub transport: &'a dyn HttpTransport,
    pub platform: Platform,
    /// Caller abort (e.g. Disconnect during prelogin).
    pub cancel: Option<&'a CancellationToken>,
    pub timeout: Duration,
}

/// Error returned when the caller cancels (not wrapped into a network error).
pub fn prelogin_aborted() -> VpnError {
    VpnError::new(VpnErrorCode::AuthCancelled, "Prelogin aborted")
}

async fn fetch_hops(portal_url: &str, opts: &PreloginRequestOptions<'_>) -> Result<PreloginResult, VpnError> {
    let mut url = build_prelogin_url(portal_url, opts.platform)
        .map_err(|c| VpnError::new(VpnErrorCode::Unknown, c.message()))?;
    let portal_host = Url::parse(&url).map(|u| url_host(&u)).unwrap_or_default();

    let mut hop = 0;
    loop {
        let req = HttpRequest {
            method: "POST".into(),
            url: url.clone(),
            headers: vec![
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                ("User-Agent".into(), "PAN GlobalProtect".into()),
            ],
            body: b"cas-support=yes".to_vec(),
            follow_redirects: false,
        };
        let mut res =
            opts.transport.send(req).await.map_err(|e| {
                VpnError::new(classify_network_error(&e), format!("Cannot reach portal: {e}"))
            })?;

        if (300..400).contains(&res.status) {
            let Some(location) = res.header("location").map(str::to_string) else {
                return Err(unreachable(format!(
                    "Portal answered HTTP {} without Location",
                    res.status
                )));
            };
            if hop >= MAX_PRELOGIN_REDIRECTS {
                return Err(unreachable("Too many redirects from portal"));
            }
            let next = Url::parse(&url)
                .and_then(|base| base.join(&location))
                .map_err(|_| unreachable("Portal redirected to an invalid URL"))?;
            if next.scheme() != "https" || url_host(&next) != portal_host {
                return Err(unreachable(format!(
                    "Portal redirected to {}://{}; only redirects within https://{portal_host} are followed",
                    next.scheme(),
                    url_host(&next)
                )));
            }
            url = next.to_string();
            hop += 1;
            continue;
        }
        if !(200..300).contains(&res.status) {
            return Err(unreachable(format!("Portal answered HTTP {}", res.status)));
        }
        return parse_prelogin(&read_capped_text(&mut res, MAX_PRELOGIN_BODY_BYTES).await?);
    }
}

/// POSTs to the portal's prelogin endpoint and parses the answer. Redirects are followed
/// manually: at most [`MAX_PRELOGIN_REDIRECTS`], https only and on the portal's own host.
pub async fn fetch_prelogin(
    portal_url: &str,
    opts: &PreloginRequestOptions<'_>,
) -> Result<PreloginResult, VpnError> {
    let never = CancellationToken::new();
    let cancel = opts.cancel.unwrap_or(&never);
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(prelogin_aborted()),
        r = tokio::time::timeout(opts.timeout, fetch_hops(portal_url, opts)) => {
            r.unwrap_or_else(|_| Err(unreachable("Cannot reach portal: timeout")))
        }
    }
}

// ------------------------------------------------------------------ engine-facing client

/// Prelogin as seen by the VPN engine (injected; fakes in tests).
#[async_trait]
pub trait PreloginClient: Send + Sync {
    async fn prelogin(&self, portal_url: &str, cancel: CancellationToken)
    -> Result<PreloginResult, VpnError>;
}

/// [`PreloginClient`] on top of an [`HttpTransport`].
pub struct HttpPreloginClient {
    pub transport: Arc<dyn HttpTransport>,
    pub platform: Platform,
    pub timeout: Duration,
}

impl HttpPreloginClient {
    pub fn new(transport: Arc<dyn HttpTransport>, platform: Platform) -> Self {
        HttpPreloginClient {
            transport,
            platform,
            timeout: DEFAULT_PRELOGIN_TIMEOUT,
        }
    }
}

#[async_trait]
impl PreloginClient for HttpPreloginClient {
    async fn prelogin(
        &self,
        portal_url: &str,
        cancel: CancellationToken,
    ) -> Result<PreloginResult, VpnError> {
        let opts = PreloginRequestOptions {
            transport: self.transport.as_ref(),
            platform: self.platform,
            cancel: Some(&cancel),
            timeout: self.timeout,
        };
        fetch_prelogin(portal_url, &opts).await
    }
}

#[cfg(test)]
mod tests;
