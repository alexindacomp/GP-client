//! Windows: GlobalProtect result from the response headers of the top-level document, via
//! WebView2's `WebResourceResponseReceived` (ICoreWebView2_2). The decision itself is the
//! platform-independent [`super::saml_from_response`].
#![allow(unsafe_code)] // WebView2 COM calls; every call below is a plain COM method on live interfaces.

use std::sync::Arc;

use gp_core::logging::Logger;
use tauri::WebviewWindow;
use tokio::sync::mpsc::UnboundedSender;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2_2, ICoreWebView2Controller, ICoreWebView2HttpHeadersCollectionIterator,
    ICoreWebView2WebResourceResponseReceivedEventArgs,
};
use webview2_com::{WebResourceResponseReceivedEventHandler, take_pwstr};
use windows_core::{BOOL, Interface, PWSTR};

use super::{SamlEvent, saml_from_response};

fn collect_headers(
    it: &ICoreWebView2HttpHeadersCollectionIterator,
) -> windows_core::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    // SAFETY: COM calls on a valid iterator; out-params are owned PWSTRs freed by take_pwstr.
    unsafe {
        let mut has = BOOL::default();
        it.HasCurrentHeader(&raw mut has)?;
        while has.as_bool() {
            let (mut k, mut v) = (PWSTR::null(), PWSTR::null());
            it.GetCurrentHeader(&raw mut k, &raw mut v)?;
            out.push((take_pwstr(k), take_pwstr(v)));
            it.MoveNext(&raw mut has)?;
        }
    }
    Ok(out)
}

fn on_response(
    args: &ICoreWebView2WebResourceResponseReceivedEventArgs,
    allowed: &[String],
    tx: &UnboundedSender<SamlEvent>,
) -> windows_core::Result<()> {
    // SAFETY: COM calls on the event args WebView2 passed to the handler.
    let (uri, request_headers, response_headers) = unsafe {
        let request = args.Request()?;
        let mut uri = PWSTR::null();
        request.Uri(&raw mut uri)?;
        let uri = take_pwstr(uri);
        let request_headers = collect_headers(&request.Headers()?.GetIterator()?)?;
        let response_headers = collect_headers(&args.Response()?.Headers()?.GetIterator()?)?;
        (uri, request_headers, response_headers)
    };
    if let Some(outcome) = saml_from_response(&uri, &request_headers, &response_headers, allowed) {
        let _ = tx.send(SamlEvent::Headers(outcome));
    }
    Ok(())
}

fn attach(
    controller: &ICoreWebView2Controller,
    allowed: Vec<String>,
    tx: UnboundedSender<SamlEvent>,
) -> windows_core::Result<()> {
    let handler = WebResourceResponseReceivedEventHandler::create(Box::new(move |_sender, args| {
        if let Some(args) = args {
            // A failure for one response must not break the handler for the next ones.
            let _ = on_response(&args, &allowed, &tx);
        }
        Ok(())
    }));
    // SAFETY: COM calls on the live controller of this window's webview. The registration lives
    // as long as the webview (it is destroyed with the window).
    unsafe {
        let webview: ICoreWebView2_2 = controller.CoreWebView2()?.cast()?;
        let mut token = 0;
        webview.add_WebResourceResponseReceived(&handler, &raw mut token)?;
    }
    Ok(())
}

/// Registers the response watcher on the SAML window's webview (best effort: without it the
/// HTML comment is still read).
pub(super) fn watch_response_headers(
    window: &WebviewWindow,
    allowed: Vec<String>,
    tx: UnboundedSender<SamlEvent>,
    logger: &Arc<Logger>,
) {
    let log = logger.clone();
    let res = window.with_webview(move |pw| {
        if let Err(e) = attach(&pw.controller(), allowed, tx) {
            log.warn(
                "saml",
                &format!("Cannot read SAML response headers (WebView2): {e}"),
            );
        }
    });
    if let Err(e) = res {
        logger.warn(
            "saml",
            &format!("Cannot read SAML response headers (WebView2): {e}"),
        );
    }
}
