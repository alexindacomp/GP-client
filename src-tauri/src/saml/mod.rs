//! Interactive SAML login in a separate webview window.
//!
//! * One window per login, with an isolated, persistent data store per profile (WebView2 /
//!   WebKitGTK: `<app local data>/saml/<profileId>`; macOS 14+: a WKWebsiteDataStore whose
//!   identifier is the profile UUID). macOS < 14 has no per-identifier stores: there the window
//!   is incognito (isolation over persistence). Removing a profile first closes its open SSO
//!   window ([`SamlSessions`]), then deletes the data ([`clear_profile_data`]).
//! * The window gets **no IPC**: no capability lists it, and it shows remote content only.
//! * Navigation: https only (top level and, where the platform reports them, frames); `about:`
//!   blank/srcdoc frames and the initial `data:` page of a POST binding are the exceptions.
//!   Popups go to the system browser. The title shows the host the user is typing into.
//! * Result: (1) the `<saml-auth-status>` HTML comment, read after every top-level page load by
//!   a script whose return value comes back through the platform's evaluate-with-callback API
//!   (`eval_with_callback`, no IPC channel involved); (2) on Windows also the GlobalProtect
//!   response headers of the top-level document (WebView2 `WebResourceResponseReceived`). WebKitGTK
//!   and WKWebView headers are not read (wry does not expose the navigation response); portals
//!   put the same values into the HTML comment, so (1) covers macOS/Linux.
//! * Only top-level https documents from the portal host are trusted (`is_trusted_saml_source`).
//! * Closing the window or cancelling the attempt → `AUTH_CANCELLED`.

#[cfg(windows)]
mod webview2;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use gp_core::logging::Logger;
use gp_core::prelogin::PreloginResult;
use gp_core::saml::{
    SamlAuthenticator, SamlLoadTarget, SamlOutcome, SamlSuccess, build_saml_load_target,
    extract_saml_from_headers, extract_saml_from_html, is_trusted_saml_source,
};
use gp_core::types::{Profile, VpnErrorCode};
use gp_core::vpn::VpnError;
use tauri::webview::{NewWindowResponse, PageLoadEvent};
use tauri::{AppHandle, Runtime, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_opener::OpenerExt;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Returns the page's HTML including comments outside `<html>` (where some portals put the
/// result). Errors are swallowed: WebView2 drops exceptions of evaluated scripts anyway.
const READ_HTML_SCRIPT: &str = "(function(){try{var o=[];var n=document.childNodes;\
for(var i=0;i<n.length;i++){if(n[i].nodeType===8){o.push('<!--'+n[i].data+'-->');}}\
if(document.documentElement){o.push(document.documentElement.outerHTML);}\
return o.join('\\n');}catch(e){return '';}})()";

/// Profile ids name a data directory: same rule as the Electron partition names.
pub(crate) fn is_valid_partition_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `host[:port]` of the portal (WHATWG `URL.host`), the only host allowed to deliver the result.
pub(crate) fn portal_host(portal_url: &str) -> Option<String> {
    let u = Url::parse(portal_url).ok()?;
    let host = u.host_str()?;
    Some(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// Navigation policy of the SAML window.
pub(crate) fn is_navigation_allowed(url: &Url, initial: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "about" => matches!(url.as_str(), "about:blank" | "about:srcdoc"),
        // The auto-submitting form of a POST binding is loaded as a data: URL (only that one).
        "data" => url.as_str() == initial.as_str(),
        _ => false,
    }
}

/// Logged form of a URL: no query/fragment (may carry tokens), data: URLs abbreviated.
pub(crate) fn loggable_url(url: &Url) -> String {
    if url.cannot_be_a_base() {
        return format!("{}:…", url.scheme());
    }
    let mut u = url.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

pub(crate) fn title_with_host(base: &str, url: &Url) -> String {
    match url.host_str() {
        Some(h) if !h.is_empty() => format!(
            "{base} — {}",
            portal_host(url.as_str()).unwrap_or_else(|| h.into())
        ),
        _ => base.to_string(),
    }
}

/// Only the top-level document carries the result: navigations of the main frame are sent with
/// `Sec-Fetch-Dest: document` (frames: `iframe`/`frame`, sub-resources: others). The header is
/// set by the browser's network stack and cannot be forged by page scripts.
pub(crate) fn is_top_level_document_request<'a, I>(request_headers: I) -> bool
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    request_headers
        .into_iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("sec-fetch-dest") && v.trim().eq_ignore_ascii_case("document"))
}

/// Header-based extraction for a finished response (Windows/WebView2).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn saml_from_response(
    uri: &str,
    request_headers: &[(String, String)],
    response_headers: &[(String, String)],
    allowed_hosts: &[String],
) -> Option<SamlOutcome> {
    if !is_top_level_document_request(request_headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
        return None;
    }
    if !is_trusted_saml_source(uri, true, allowed_hosts) {
        return None;
    }
    extract_saml_from_headers(response_headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// Whether WKWebView supports per-identifier data stores (`WKWebsiteDataStore(forIdentifier:)`,
/// macOS 14+) for a `ProductVersion` like "14.2.1". Unknown versions count as unsupported.
pub(crate) fn supports_custom_data_store(product_version: &str) -> bool {
    product_version
        .trim()
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
        .is_some_and(|major| major >= 14)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// `ProductVersion` from /System/Library/CoreServices/SystemVersion.plist.
pub(crate) fn plist_product_version(plist: &str) -> Option<String> {
    let after = &plist[plist.find("<key>ProductVersion</key>")? + "<key>ProductVersion</key>".len()..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].trim().to_string())
}

/// macOS 14+ (detected once). Calling the data-store APIs on older systems raises an
/// Objective-C exception (unknown selector), which aborts the app.
#[cfg(target_os = "macos")]
fn macos_has_custom_data_stores() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .ok()
            .and_then(|p| plist_product_version(&p))
            .is_some_and(|v| supports_custom_data_store(&v))
    })
}

/// Open SSO windows by profile id, so removing a profile can close its window first.
#[derive(Default)]
pub(crate) struct SamlSessions {
    open: Mutex<HashMap<String, (CancellationToken, watch::Receiver<bool>)>>,
}

/// Unregisters the session and reports it as finished when the login returns (any path).
struct SessionGuard<'a> {
    sessions: &'a SamlSessions,
    profile_id: String,
    done: watch::Sender<bool>,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        let _ = self.done.send(true);
        self.sessions.lock().remove(&self.profile_id);
    }
}

impl SamlSessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (CancellationToken, watch::Receiver<bool>)>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, profile_id: &str) -> (CancellationToken, SessionGuard<'_>) {
        let token = CancellationToken::new();
        let (done, done_rx) = watch::channel(false);
        self.lock()
            .insert(profile_id.to_string(), (token.clone(), done_rx));
        (
            token,
            SessionGuard {
                sessions: self,
                profile_id: profile_id.to_string(),
                done,
            },
        )
    }

    /// Cancels the profile's open SSO window (if any) and waits until it is gone.
    pub(crate) async fn close(&self, profile_id: &str) {
        let Some((token, mut done)) = self.lock().get(profile_id).cloned() else {
            return;
        };
        token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), done.wait_for(|d| *d)).await;
    }
}

/// Removes the profile's SAML data (cookies, storage, cache), after closing its open SSO window.
/// Best effort; errors are returned for logging.
pub(crate) async fn clear_profile_data<R: Runtime>(
    app: &AppHandle<R>,
    sessions: &SamlSessions,
    data_root: &Path,
    profile_id: &str,
) -> Result<(), String> {
    if !is_valid_partition_id(profile_id) {
        return Ok(());
    }
    sessions.close(profile_id).await;
    let dir = data_root.join(profile_id);
    // WebView2 releases the folder shortly after its window is gone.
    let mut attempt = 0;
    while dir.exists() {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => break,
            Err(e) if attempt >= 10 => return Err(e.to_string()),
            Err(_) => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    #[cfg(target_os = "macos")]
    if macos_has_custom_data_stores()
        && let Ok(id) = uuid::Uuid::parse_str(profile_id)
    {
        let id = *id.as_bytes();
        let existing = app
            .fetch_data_store_identifiers()
            .await
            .map_err(|e| e.to_string())?;
        if existing.contains(&id) {
            app.remove_data_store(id).await.map_err(|e| e.to_string())?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = app;
    Ok(())
}

enum SamlEvent {
    /// A top-level page started loading (new document).
    Started(Url),
    /// A top-level page finished loading; `generation` identifies the document.
    Finished {
        url: Url,
        generation: u64,
    },
    /// HTML read from the document of `generation`.
    Html {
        html: String,
        generation: u64,
    },
    /// Result found in the response headers of a trusted top-level document.
    Headers(SamlOutcome),
    Closed,
}

pub(crate) struct SamlWindowAuthenticator {
    app: AppHandle,
    logger: Arc<Logger>,
    data_root: PathBuf,
    sessions: Arc<SamlSessions>,
    next_window: AtomicU64,
}

impl SamlWindowAuthenticator {
    pub(crate) fn new(
        app: AppHandle,
        logger: Arc<Logger>,
        data_root: PathBuf,
        sessions: Arc<SamlSessions>,
    ) -> Self {
        SamlWindowAuthenticator {
            app,
            logger,
            data_root,
            sessions,
            next_window: AtomicU64::new(0),
        }
    }

    fn cancelled() -> VpnError {
        VpnError::new(VpnErrorCode::AuthCancelled, "SAML authentication was cancelled")
    }

    fn finish(&self, outcome: SamlOutcome) -> Result<SamlSuccess, VpnError> {
        match outcome {
            SamlOutcome::Success(s) => {
                // Never log the cookie itself.
                self.logger.secrets().add(&s.cookie);
                self.logger.info(
                    "saml",
                    &format!(
                        "SAML login succeeded for {} ({})",
                        s.username,
                        s.cookie_name.as_str()
                    ),
                );
                Ok(s)
            }
            SamlOutcome::Failure { message } => {
                self.logger.warn("saml", &message);
                Err(VpnError::new(VpnErrorCode::AuthFailed, message))
            }
        }
    }
}

#[async_trait]
impl SamlAuthenticator for SamlWindowAuthenticator {
    async fn saml_login(
        &self,
        profile: &Profile,
        prelogin: &PreloginResult,
        cancel: CancellationToken,
    ) -> Result<SamlSuccess, VpnError> {
        if !is_valid_partition_id(&profile.id) {
            return Err(VpnError::new(
                VpnErrorCode::Unknown,
                "Invalid profile id for SAML data",
            ));
        }
        let allowed: Vec<String> = portal_host(&profile.portal_url).into_iter().collect();
        let target =
            build_saml_load_target(prelogin).map_err(|e| VpnError::new(VpnErrorCode::AuthFailed, e.0))?;
        let initial = match &target {
            SamlLoadTarget::Url(u) => u.as_str(),
            SamlLoadTarget::Html { data_url, .. } => data_url.as_str(),
        };
        let initial = Url::parse(initial)
            .map_err(|_| VpnError::new(VpnErrorCode::AuthFailed, "SAML login URL is invalid"))?;
        if cancel.is_cancelled() {
            return Err(Self::cancelled());
        }

        // Profile removal cancels this window through the registry (CR-T11).
        let (closing, _session) = self.sessions.register(&profile.id);

        let base_title = format!("{} — SSO", profile.name);
        let label = format!("saml-{}", self.next_window.fetch_add(1, Ordering::Relaxed));
        let (tx, mut rx) = mpsc::unbounded_channel::<SamlEvent>();
        let generation = Arc::new(AtomicU64::new(0));

        let nav_logger = self.logger.clone();
        let nav_initial = initial.clone();
        let load_tx = tx.clone();
        let load_generation = generation.clone();
        let opener = self.app.clone();
        let builder = WebviewWindowBuilder::new(&self.app, &label, WebviewUrl::External(initial.clone()))
            .title(&base_title)
            .inner_size(520.0, 700.0)
            .center()
            .focused(true)
            .devtools(false)
            .on_navigation(move |url| {
                let allowed = is_navigation_allowed(url, &nav_initial);
                if !allowed {
                    nav_logger.warn(
                        "saml",
                        &format!("Blocked non-https navigation to {}", loggable_url(url)),
                    );
                }
                allowed
            })
            .on_page_load(move |_w, payload| {
                let url = payload.url().clone();
                let _ = match payload.event() {
                    PageLoadEvent::Started => {
                        load_generation.fetch_add(1, Ordering::SeqCst);
                        load_tx.send(SamlEvent::Started(url))
                    }
                    PageLoadEvent::Finished => load_tx.send(SamlEvent::Finished {
                        url,
                        generation: load_generation.load(Ordering::SeqCst),
                    }),
                };
            })
            // Popups (e.g. "help" links) go to the system browser; the login stays here.
            .on_new_window(move |url, _features| {
                if url.scheme() == "https" {
                    let _ = opener.opener().open_url(url.as_str(), None::<&str>);
                }
                NewWindowResponse::Deny
            });
        let builder = self.isolate(builder, &profile.id);
        let window = builder
            .build()
            .map_err(|e| VpnError::new(VpnErrorCode::Unknown, format!("Cannot open the SSO window: {e}")))?;

        let closed_tx = tx.clone();
        window.on_window_event(move |e| {
            if matches!(e, WindowEvent::Destroyed) {
                let _ = closed_tx.send(SamlEvent::Closed);
            }
        });
        #[cfg(windows)]
        webview2::watch_response_headers(&window, allowed.clone(), tx.clone(), &self.logger);

        let mut closed = false;
        let result = loop {
            let event = tokio::select! {
                () = cancel.cancelled() => break Err(Self::cancelled()),
                () = closing.cancelled() => break Err(Self::cancelled()),
                ev = rx.recv() => ev,
            };
            match event {
                None | Some(SamlEvent::Closed) => {
                    closed = true;
                    break Err(Self::cancelled());
                }
                Some(SamlEvent::Started(url)) => {
                    let _ = window.set_title(&title_with_host(&base_title, &url));
                }
                Some(SamlEvent::Finished { url, generation: g }) => {
                    if !is_trusted_saml_source(url.as_str(), true, &allowed) {
                        continue;
                    }
                    let html_tx = tx.clone();
                    let current = generation.clone();
                    let _ = window.eval_with_callback(READ_HTML_SCRIPT, move |json| {
                        // The document may have changed while the script ran.
                        if current.load(Ordering::SeqCst) != g {
                            return;
                        }
                        if let Ok(html) = serde_json::from_str::<String>(&json) {
                            let _ = html_tx.send(SamlEvent::Html { html, generation: g });
                        }
                    });
                }
                Some(SamlEvent::Html { html, generation: g }) => {
                    if g != generation.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let Some(outcome) = extract_saml_from_html(&html) {
                        break self.finish(outcome);
                    }
                }
                Some(SamlEvent::Headers(outcome)) => break self.finish(outcome),
            }
        };
        let _ = window.destroy();
        drop(tx);
        // Report the window as gone only once it really is (the profile's data may be deleted next).
        if !closed {
            let _ = tokio::time::timeout(Duration::from_secs(3), async {
                while !matches!(rx.recv().await, None | Some(SamlEvent::Closed)) {}
            })
            .await;
        }
        result
    }
}

impl SamlWindowAuthenticator {
    /// Per-profile persistent data store.
    fn isolate<'a>(
        &self,
        builder: WebviewWindowBuilder<'a, tauri::Wry, AppHandle>,
        profile_id: &str,
    ) -> WebviewWindowBuilder<'a, tauri::Wry, AppHandle> {
        #[cfg(target_os = "macos")]
        {
            // WKWebView ignores data_directory; a per-profile store needs macOS 14. Older systems
            // would fall back to the default store shared with the main window and every other
            // profile, so they get a non-persistent (incognito) store instead.
            let _ = &self.data_root;
            match uuid::Uuid::parse_str(profile_id) {
                Ok(id) if macos_has_custom_data_stores() => builder.data_store_identifier(*id.as_bytes()),
                _ => builder.incognito(true),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            builder.data_directory(self.data_root.join(profile_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn hosts(h: &[&str]) -> Vec<String> {
        h.iter().map(|s| (*s).to_string()).collect()
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn custom_data_stores_need_macos_14() {
        for (v, ok) in [
            ("14.0", true),
            ("14.2.1", true),
            ("15", true),
            ("26.1", true),
            ("13.6.9", false),
            ("10.15.7", false),
            ("11.0", false),
            ("", false),
            ("x.y", false),
        ] {
            assert_eq!(supports_custom_data_store(v), ok, "{v}");
        }
        let plist = "<dict>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductVersion</key>\n\t<string>13.6.1</string>\n</dict>";
        assert_eq!(plist_product_version(plist).as_deref(), Some("13.6.1"));
        assert_eq!(plist_product_version("<dict></dict>"), None);
    }

    #[tokio::test]
    async fn closing_a_session_cancels_it_and_waits_until_it_is_gone() {
        let sessions = Arc::new(SamlSessions::default());
        sessions.close("nobody").await; // no window: returns at once
        let (token, guard) = sessions.register("p1");
        let s2 = sessions.clone();
        let closer = tokio::spawn(async move { s2.close("p1").await });
        token.cancelled().await;
        // Still open until the login returns.
        assert!(sessions.lock().contains_key("p1"));
        drop(guard);
        closer.await.unwrap();
        assert!(!sessions.lock().contains_key("p1"));
    }

    #[test]
    fn partition_ids_are_restricted() {
        assert!(is_valid_partition_id("3f2b8c4e-1d2a-4b5c-8d9e-0f1a2b3c4d5e"));
        for bad in ["", "../x", "a/b", "a\\b", "a b", &"a".repeat(65)] {
            assert!(!is_valid_partition_id(bad), "{bad}");
        }
    }

    #[test]
    fn portal_host_includes_non_default_ports() {
        assert_eq!(
            portal_host("https://vpn.example.com").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            portal_host("https://vpn.example.com:443/x").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            portal_host("https://vpn.example.com:8443").as_deref(),
            Some("vpn.example.com:8443")
        );
        assert_eq!(portal_host("https://[::1]:8443").as_deref(), Some("[::1]:8443"));
        assert_eq!(portal_host("not a url"), None);
    }

    #[test]
    fn navigation_is_https_only() {
        let initial = u("https://idp.example.com/sso?SAMLRequest=x");
        for ok in [
            "https://idp.example.com/login",
            "https://vpn.example.com/SAML20/SP/ACS",
            "about:blank",
            "about:srcdoc",
        ] {
            assert!(is_navigation_allowed(&u(ok), &initial), "{ok}");
        }
        for bad in [
            "http://idp.example.com/login",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<form>",
            "blob:https://idp.example.com/1",
            "about:config",
            "ftp://example.com/",
        ] {
            assert!(!is_navigation_allowed(&u(bad), &initial), "{bad}");
        }
    }

    #[test]
    fn only_the_initial_data_url_of_a_post_binding_is_allowed() {
        let initial = u("data:text/html;charset=utf-8;base64,PGZvcm0+");
        assert!(is_navigation_allowed(
            &u("data:text/html;charset=utf-8;base64,PGZvcm0+"),
            &initial
        ));
        assert!(!is_navigation_allowed(
            &u("data:text/html;charset=utf-8;base64,PHNjcmlwdD4="),
            &initial
        ));
    }

    #[test]
    fn logged_urls_drop_query_and_data() {
        assert_eq!(
            loggable_url(&u("http://idp.example.com/a?token=secret#f")),
            "http://idp.example.com/a"
        );
        assert_eq!(loggable_url(&u("data:text/html;base64,AAAA")), "data:…");
    }

    #[test]
    fn title_shows_the_current_host() {
        assert_eq!(
            title_with_host("Office — SSO", &u("https://login.example.com:8443/x?y")),
            "Office — SSO — login.example.com:8443"
        );
        assert_eq!(title_with_host("Office — SSO", &u("about:blank")), "Office — SSO");
    }

    #[test]
    fn headers_are_accepted_only_from_the_portal_top_level_document() {
        let allowed = hosts(&["vpn.example.com"]);
        let doc = pairs(&[("Accept", "text/html"), ("Sec-Fetch-Dest", "document")]);
        let ok_headers = pairs(&[
            ("saml-auth-status", "1"),
            ("saml-username", "alice"),
            ("prelogin-cookie", "COOKIE123"),
        ]);
        let uri = "https://vpn.example.com/SAML20/SP/ACS";
        match saml_from_response(uri, &doc, &ok_headers, &allowed) {
            Some(SamlOutcome::Success(s)) => {
                assert_eq!((s.username.as_str(), s.cookie.as_str()), ("alice", "COOKIE123"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // Sub-resources / frames, other hosts and plain http never deliver a result.
        let iframe = pairs(&[("sec-fetch-dest", "iframe")]);
        assert_eq!(saml_from_response(uri, &iframe, &ok_headers, &allowed), None);
        assert_eq!(saml_from_response(uri, &[], &ok_headers, &allowed), None);
        assert_eq!(
            saml_from_response("https://idp.example.com/x", &doc, &ok_headers, &allowed),
            None
        );
        assert_eq!(
            saml_from_response("http://vpn.example.com/x", &doc, &ok_headers, &allowed),
            None
        );
        // Ordinary responses of the portal carry no result.
        assert_eq!(
            saml_from_response(uri, &doc, &pairs(&[("content-type", "text/html")]), &allowed),
            None
        );
    }

    #[test]
    fn html_script_is_an_expression() {
        assert!(READ_HTML_SCRIPT.starts_with("(function(){") && READ_HTML_SCRIPT.ends_with("})()"));
    }
}
