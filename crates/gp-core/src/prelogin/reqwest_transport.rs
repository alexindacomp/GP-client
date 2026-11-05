//! [`HttpTransport`] on reqwest + rustls (ring provider, OS trust store via
//! rustls-platform-verifier, so corporate CAs installed in the OS are honoured).

use std::error::Error as _;
use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;

use super::{HttpBody, HttpRequest, HttpResponse, HttpTransport, TransportError};

#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Fails only if another provider was installed first, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The error and all its sources, `: `-joined (TLS causes are often only in the chain).
fn chain(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(s) = cur {
        out.push_str(": ");
        out.push_str(&s.to_string());
        cur = s.source();
    }
    out
}

impl ReqwestTransport {
    /// Client that never follows redirects (the caller validates each hop).
    pub fn new() -> Result<Self, TransportError> {
        install_crypto_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| TransportError::new(chain(&e)))?;
        Ok(ReqwestTransport { client })
    }
}

struct ReqwestBody(reqwest::Response);

#[async_trait]
impl HttpBody for ReqwestBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.0
            .chunk()
            .await
            .map(|c| c.map(|b| b.to_vec()))
            .map_err(|e| TransportError::new(chain(&e)))
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        debug_assert!(
            !req.follow_redirects,
            "the reqwest client never follows redirects"
        );
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|_| TransportError::new(format!("invalid HTTP method {}", req.method)))?;
        let mut builder = self.client.request(method, &req.url).body(req.body);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        let res = builder.send().await.map_err(|e| TransportError::new(chain(&e)))?;
        let headers = res
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
            .collect();
        Ok(HttpResponse {
            status: res.status().as_u16(),
            headers,
            body: Box::new(ReqwestBody(res)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_client() {
        assert!(ReqwestTransport::new().is_ok());
    }
}
