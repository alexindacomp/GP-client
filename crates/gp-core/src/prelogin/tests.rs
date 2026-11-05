use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;

use super::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn b64decode(s: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
}

// ------------------------------------------------------------------ parse

#[test]
fn detects_saml_redirect_and_keeps_the_base64_request() {
    let r = parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap();
    assert_eq!(r.auth_type, AuthType::Saml);
    assert_eq!(r.saml_method, Some(SamlMethod::Redirect));
    assert!(
        b64decode(r.saml_request.as_deref().unwrap()).starts_with("https://idp.example.com/app/sso/saml?")
    );
    assert_eq!(r.auth_message.as_deref(), Some("Enter login credentials"));
    assert_eq!(r.username_label.as_deref(), Some("Username"));
    assert_eq!(r.password_label.as_deref(), Some("Password"));
    assert_eq!(r.region.as_deref(), Some("DE"));
}

#[test]
fn detects_saml_post_and_strips_whitespace_inside_the_request() {
    let r = parse_prelogin(&fixture("prelogin-saml-post.xml")).unwrap();
    assert_eq!(r.auth_type, AuthType::Saml);
    assert_eq!(r.saml_method, Some(SamlMethod::Post));
    let req = r.saml_request.unwrap();
    assert!(!req.chars().any(char::is_whitespace));
    assert!(b64decode(&req).contains("<form method=\"POST\""));
}

#[test]
fn falls_back_to_password_auth_and_decodes_entities_cdata_and_unicode() {
    let r = parse_prelogin(&fixture("prelogin-password.xml")).unwrap();
    assert_eq!(r.auth_type, AuthType::Password);
    assert_eq!(r.saml_request, None);
    assert_eq!(r.auth_message.as_deref(), Some("Enter login credentials & OTP"));
    assert_eq!(r.username_label.as_deref(), Some("Корп. логин"));
    assert_eq!(r.password_label.as_deref(), Some("Password + <token>"));
}

#[test]
fn accepts_the_short_auth_message_tag() {
    let r = parse_prelogin(
        "<prelogin-response><status>Success</status><auth-message>Hi</auth-message></prelogin-response>",
    )
    .unwrap();
    assert_eq!(r.auth_message.as_deref(), Some("Hi"));
}

#[test]
fn error_status_is_auth_failed_with_the_portal_message() {
    let e = parse_prelogin(&fixture("prelogin-error.xml")).unwrap_err();
    assert_eq!(e.code, VpnErrorCode::AuthFailed);
    assert!(e.message.contains("Valid client certificate is required"));
}

#[test]
fn rejects_non_globalprotect_responses_and_unknown_saml_methods() {
    assert_eq!(
        parse_prelogin("<html>Login</html>").unwrap_err().code,
        VpnErrorCode::PortalUnreachable
    );
    let xml = "<prelogin-response><status>Success</status><saml-auth-method>ARTIFACT</saml-auth-method><saml-request>aGk=</saml-request></prelogin-response>";
    assert!(
        parse_prelogin(xml)
            .unwrap_err()
            .message
            .contains("Unsupported SAML auth method: ARTIFACT")
    );
}

#[test]
fn prelogin_result_serializes_like_the_ts_type() {
    let r = parse_prelogin(&fixture("prelogin-saml-redirect.xml")).unwrap();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["authType"], "saml");
    assert_eq!(v["samlMethod"], "REDIRECT");
}

// ------------------------------------------------------------------ URL

#[test]
fn normalizes_portal_urls() {
    for (input, expected) in [
        ("vpn.example.com", "https://vpn.example.com"),
        ("https://vpn.example.com/", "https://vpn.example.com"),
        (
            "  https://VPN.example.com:8443/global-protect  ",
            "https://vpn.example.com:8443",
        ),
    ] {
        assert_eq!(normalize_portal_url(input).unwrap(), expected);
    }
    for input in [
        "http://vpn.example.com",
        "ftp://x",
        "https://user:pw@vpn.example.com",
        "",
        "vpn example.com",
    ] {
        assert!(normalize_portal_url(input).is_err(), "{input}");
    }
}

#[test]
fn builds_the_prelogin_url_with_clientos_per_platform() {
    for (platform, os) in [
        (Platform::Win32, "Windows"),
        (Platform::Darwin, "Mac"),
        (Platform::Linux, "Linux"),
    ] {
        assert_eq!(
            build_prelogin_url("vpn.example.com", platform).unwrap(),
            format!(
                "https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos={os}"
            )
        );
    }
}

// ------------------------------------------------------------------ fetch (fake HTTP layer)

enum Reply {
    Ok {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    Fail(&'static str),
    Hang,
}

fn ok_body(body: impl Into<Vec<u8>>) -> Reply {
    Reply::Ok {
        status: 200,
        headers: vec![],
        body: body.into(),
    }
}

fn redirect(location: &str, status: u16) -> Reply {
    Reply::Ok {
        status,
        headers: vec![("Location", location.into())],
        body: vec![],
    }
}

/// Scripted transport: replies in order, the last one repeats.
struct FakeHttp {
    replies: Mutex<VecDeque<Reply>>,
    last: Mutex<Option<Reply>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FakeHttp {
    fn new(replies: Vec<Reply>) -> Self {
        FakeHttp {
            replies: Mutex::new(replies.into()),
            last: Mutex::new(None),
            requests: Mutex::new(vec![]),
        }
    }
    fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

fn clone_reply(r: &Reply) -> Reply {
    match r {
        Reply::Ok {
            status,
            headers,
            body,
        } => Reply::Ok {
            status: *status,
            headers: headers.clone(),
            body: body.clone(),
        },
        Reply::Fail(m) => Reply::Fail(m),
        Reply::Hang => Reply::Hang,
    }
}

/// Body delivered in 64 KiB chunks (like a stream).
struct ChunkedBody(Vec<u8>);

#[async_trait]
impl HttpBody for ChunkedBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let n = self.0.len().min(64 * 1024);
        Ok(Some(self.0.drain(..n).collect()))
    }
}

#[async_trait]
impl HttpTransport for FakeHttp {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests.lock().unwrap().push(req);
        let reply = {
            let mut q = self.replies.lock().unwrap();
            let mut last = self.last.lock().unwrap();
            if let Some(r) = q.pop_front() {
                *last = Some(clone_reply(&r));
                r
            } else {
                clone_reply(last.as_ref().expect("no reply scripted"))
            }
        };
        match reply {
            Reply::Ok {
                status,
                headers,
                body,
            } => Ok(HttpResponse {
                status,
                headers: headers.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                body: Box::new(ChunkedBody(body)),
            }),
            Reply::Fail(m) => Err(TransportError::new(m)),
            Reply::Hang => std::future::pending().await,
        }
    }
}

async fn fetch(http: &FakeHttp, portal: &str) -> Result<PreloginResult, VpnError> {
    let opts = PreloginRequestOptions {
        transport: http,
        platform: Platform::Linux,
        cancel: None,
        timeout: DEFAULT_PRELOGIN_TIMEOUT,
    };
    fetch_prelogin(portal, &opts).await
}

#[tokio::test]
async fn posts_to_the_prelogin_endpoint_without_auto_redirects_and_parses_the_body() {
    let http = FakeHttp::new(vec![ok_body(fixture("prelogin-saml-redirect.xml"))]);
    let r = fetch(&http, "https://vpn.example.com").await.unwrap();
    assert_eq!(r.auth_type, AuthType::Saml);
    let req = &http.requests()[0];
    assert_eq!(
        req.url,
        "https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"
    );
    assert_eq!(req.method, "POST");
    assert_eq!(req.body, b"cas-support=yes");
    assert!(!req.follow_redirects);
    assert!(
        req.headers
            .contains(&("User-Agent".into(), "PAN GlobalProtect".into()))
    );
}

#[tokio::test]
async fn maps_http_errors_and_connection_failures_to_portal_unreachable() {
    let http = FakeHttp::new(vec![Reply::Ok {
        status: 404,
        headers: vec![],
        body: b"nope".to_vec(),
    }]);
    assert_eq!(
        fetch(&http, "vpn.example.com").await.unwrap_err().code,
        VpnErrorCode::PortalUnreachable
    );
    let http = FakeHttp::new(vec![Reply::Fail("error sending request: connect ECONNREFUSED")]);
    let e = fetch(&http, "vpn.example.com").await.unwrap_err();
    assert_eq!(e.code, VpnErrorCode::PortalUnreachable);
    assert!(e.message.starts_with("Cannot reach portal: "));
}

#[tokio::test]
async fn maps_certificate_failures_to_tls_error() {
    let http = FakeHttp::new(vec![Reply::Fail(
        "error sending request: invalid peer certificate: Expired",
    )]);
    assert_eq!(
        fetch(&http, "vpn.example.com").await.unwrap_err().code,
        VpnErrorCode::TlsError
    );
}

#[tokio::test]
async fn does_not_wrap_a_caller_abort() {
    let http = FakeHttp::new(vec![Reply::Hang]);
    let cancel = CancellationToken::new();
    let opts = PreloginRequestOptions {
        transport: &http,
        platform: Platform::Linux,
        cancel: Some(&cancel),
        timeout: DEFAULT_PRELOGIN_TIMEOUT,
    };
    let c = cancel.clone();
    tokio::spawn(async move { c.cancel() });
    let e = fetch_prelogin("vpn.example.com", &opts).await.unwrap_err();
    assert_eq!(e, prelogin_aborted());
    assert!(e.message.contains("aborted"));
}

#[tokio::test(start_paused = true)]
async fn times_out_as_portal_unreachable() {
    let http = FakeHttp::new(vec![Reply::Hang]);
    let e = fetch(&http, "vpn.example.com").await.unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (VpnErrorCode::PortalUnreachable, "Cannot reach portal: timeout")
    );
}

#[tokio::test]
async fn follows_a_same_host_https_redirect() {
    let http = FakeHttp::new(vec![
        redirect(
            "/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux&x=1",
            307,
        ),
        ok_body(fixture("prelogin-password.xml")),
    ]);
    let r = fetch(&http, "vpn.example.com").await.unwrap();
    assert_eq!(r.auth_type, AuthType::Password);
    assert_eq!(
        http.requests()[1].url,
        "https://vpn.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux&x=1"
    );
}

#[tokio::test]
async fn rejects_redirects_to_other_hosts_schemes_or_ports() {
    for location in [
        "https://evil.example.net/global-protect/prelogin.esp",
        "http://vpn.example.com/global-protect/prelogin.esp",
        "https://vpn.example.com:8443/global-protect/prelogin.esp",
    ] {
        let http = FakeHttp::new(vec![
            redirect(location, 302),
            ok_body(fixture("prelogin-password.xml")),
        ]);
        let e = fetch(&http, "vpn.example.com").await.unwrap_err();
        assert_eq!(e.code, VpnErrorCode::PortalUnreachable, "{location}");
        assert!(
            e.message
                .contains("only redirects within https://vpn.example.com"),
            "{}",
            e.message
        );
        assert_eq!(http.requests().len(), 1);
    }
}

#[tokio::test]
async fn stops_after_3_redirects() {
    let http = FakeHttp::new(vec![redirect("/loop", 302)]);
    let e = fetch(&http, "vpn.example.com").await.unwrap_err();
    assert!(e.message.contains("Too many redirects"));
    assert_eq!(http.requests().len(), 4);
}

#[tokio::test]
async fn rejects_a_redirect_without_location() {
    let http = FakeHttp::new(vec![Reply::Ok {
        status: 302,
        headers: vec![],
        body: vec![],
    }]);
    assert!(
        fetch(&http, "vpn.example.com")
            .await
            .unwrap_err()
            .message
            .contains("without Location")
    );
}

#[tokio::test]
async fn rejects_bodies_larger_than_1_mib_declared_or_streamed() {
    let declared = FakeHttp::new(vec![Reply::Ok {
        status: 200,
        headers: vec![("content-length", (MAX_PRELOGIN_BODY_BYTES + 1).to_string())],
        body: b"small".to_vec(),
    }]);
    assert!(
        fetch(&declared, "vpn.example.com")
            .await
            .unwrap_err()
            .message
            .contains("too large")
    );
    let streamed = FakeHttp::new(vec![ok_body(vec![b'x'; MAX_PRELOGIN_BODY_BYTES + 1])]);
    assert!(
        fetch(&streamed, "vpn.example.com")
            .await
            .unwrap_err()
            .message
            .contains("too large")
    );
    // exactly at the cap is fine (and then rejected only as "not a portal")
    let exact = FakeHttp::new(vec![ok_body(vec![b'x'; MAX_PRELOGIN_BODY_BYTES])]);
    assert!(
        fetch(&exact, "vpn.example.com")
            .await
            .unwrap_err()
            .message
            .contains("Unexpected prelogin response")
    );
}

#[tokio::test]
async fn http_prelogin_client_uses_the_transport() {
    let http = Arc::new(FakeHttp::new(vec![ok_body(fixture("prelogin-password.xml"))]));
    let client = HttpPreloginClient::new(http.clone(), Platform::Win32);
    let r = client
        .prelogin("vpn.example.com", CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.password_label.as_deref(), Some("Password + <token>"));
    assert!(http.requests()[0].url.ends_with("clientos=Windows"));
}
