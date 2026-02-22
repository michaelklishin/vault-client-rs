use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use rand::Rng;
use reqwest::{Client, Method, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::api;
use crate::types::error::VaultError;
use crate::types::kv::ListResponse;
use crate::types::response::{AuthInfo, VaultResponse};

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// HTTP LIST method used by Vault's list endpoints.
static METHOD_LIST: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"LIST").expect("LIST is a valid HTTP method"));

/// Thread-safe, Clone-friendly Vault client. Internally Arc'd.
#[derive(Clone)]
pub struct VaultClient {
    pub(crate) inner: Arc<VaultClientInner>,
    pub(crate) namespace_override: Option<String>,
    pub(crate) wrap_ttl_override: Option<String>,
}

const _: () = {
    fn _assert_send_sync<T: Send + Sync>() {}
    fn _assert() {
        _assert_send_sync::<VaultClient>();
    }
};

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("base_url", &self.inner.base_url.as_str())
            .finish_non_exhaustive()
    }
}

pub(crate) struct VaultClientInner {
    pub(crate) http: Client,
    pub(crate) base_url: Url,
    pub(crate) token: RwLock<Option<TokenState>>,
    pub(crate) namespace: Option<String>,
    pub(crate) config: ClientConfig,
}

/// Internal token state. Fields beyond `value` are populated by
/// `update_token_from_auth` and reserved for future auto-renewal logic.
pub(crate) struct TokenState {
    pub value: SecretString,
    // Written by update_token_from_auth, reserved for future auto-renewal.
    #[allow(dead_code)]
    pub accessor: Option<String>,
    #[allow(dead_code)]
    pub expires_at: Option<Instant>,
    #[allow(dead_code)]
    pub renewable: bool,
    #[allow(dead_code)]
    pub lease_duration: Duration,
}

pub(crate) struct ClientConfig {
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_retry_delay: Duration,
    pub wrap_ttl: Option<String>,
    pub forward_to_leader: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_retries: 2,
            initial_retry_delay: Duration::from_millis(500),
            wrap_ttl: None,
            forward_to_leader: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

#[must_use]
pub struct ClientBuilder {
    address: Option<String>,
    token: Option<SecretString>,
    namespace: Option<String>,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
    initial_retry_delay: Option<Duration>,
    wrap_ttl: Option<String>,
    forward_to_leader: bool,
    danger_disable_tls_verify: bool,
    ca_cert_pem: Option<Vec<u8>>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<zeroize::Zeroizing<Vec<u8>>>,
    reqwest_client: Option<Client>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            address: std::env::var("VAULT_ADDR").ok(),
            token: std::env::var("VAULT_TOKEN").ok().map(SecretString::new),
            namespace: std::env::var("VAULT_NAMESPACE").ok(),
            timeout: std::env::var("VAULT_CLIENT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs),
            max_retries: std::env::var("VAULT_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok()),
            initial_retry_delay: None,
            wrap_ttl: std::env::var("VAULT_WRAP_TTL").ok(),
            forward_to_leader: false,
            danger_disable_tls_verify: std::env::var("VAULT_SKIP_VERIFY")
                .ok()
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            ca_cert_pem: std::env::var("VAULT_CACERT")
                .ok()
                .and_then(|path| std::fs::read(path).ok()),
            client_cert_pem: std::env::var("VAULT_CLIENT_CERT")
                .ok()
                .and_then(|path| std::fs::read(path).ok()),
            client_key_pem: std::env::var("VAULT_CLIENT_KEY")
                .ok()
                .and_then(|path| std::fs::read(path).ok().map(zeroize::Zeroizing::new)),
            reqwest_client: None,
        }
    }
}

impl ClientBuilder {
    pub fn address(mut self, addr: &str) -> Self {
        self.address = Some(addr.to_owned());
        self
    }

    pub fn token(mut self, token: SecretString) -> Self {
        self.token = Some(token);
        self
    }

    pub fn namespace(mut self, ns: &str) -> Self {
        self.namespace = Some(ns.to_owned());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    pub fn initial_retry_delay(mut self, d: Duration) -> Self {
        self.initial_retry_delay = Some(d);
        self
    }

    pub fn wrap_ttl(mut self, ttl: &str) -> Self {
        self.wrap_ttl = Some(ttl.to_owned());
        self
    }

    pub fn forward_to_leader(mut self, yes: bool) -> Self {
        self.forward_to_leader = yes;
        self
    }

    pub fn danger_disable_tls_verify(mut self, yes: bool) -> Self {
        self.danger_disable_tls_verify = yes;
        self
    }

    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    pub fn client_cert_pem(mut self, cert: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        self.client_cert_pem = Some(cert.into());
        self.client_key_pem = Some(zeroize::Zeroizing::new(key.into()));
        self
    }

    pub fn with_reqwest_client(mut self, client: Client) -> Self {
        self.reqwest_client = Some(client);
        self
    }

    pub fn build(self) -> Result<VaultClient, VaultError> {
        let addr = self
            .address
            .ok_or_else(|| VaultError::Config("address is required".into()))?;
        let mut base_url =
            Url::parse(&addr).map_err(|e| VaultError::Config(format!("invalid address: {e}")))?;
        // Ensure trailing slash so path joins work correctly
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }

        let config = ClientConfig {
            timeout: self.timeout.unwrap_or(Duration::from_secs(60)),
            max_retries: self.max_retries.unwrap_or(2),
            initial_retry_delay: self
                .initial_retry_delay
                .unwrap_or(Duration::from_millis(500)),
            wrap_ttl: self.wrap_ttl,
            forward_to_leader: self.forward_to_leader,
        };

        // Build the HTTP client. We must do this after constructing config
        // (for timeout) but handle the partial-move by matching reqwest_client
        // separately: in the None arm we still need &self for TLS fields.
        let http = if let Some(c) = self.reqwest_client {
            c
        } else {
            build_reqwest_client(
                &config,
                self.danger_disable_tls_verify,
                self.ca_cert_pem.as_deref(),
                self.client_cert_pem.as_deref(),
                self.client_key_pem.as_ref().map(|k| k.as_slice()),
            )?
        };

        let token_state = self.token.map(|t| TokenState {
            value: t,
            accessor: None,
            expires_at: None,
            renewable: false,
            lease_duration: Duration::ZERO,
        });

        Ok(VaultClient {
            inner: Arc::new(VaultClientInner {
                http,
                base_url,
                token: RwLock::new(token_state),
                namespace: self.namespace,
                config,
            }),
            namespace_override: None,
            wrap_ttl_override: None,
        })
    }
}

fn build_reqwest_client(
    config: &ClientConfig,
    danger_disable_tls_verify: bool,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Client, VaultError> {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .danger_accept_invalid_certs(danger_disable_tls_verify);

    if let Some(ca_pem) = ca_cert_pem {
        let cert = reqwest::tls::Certificate::from_pem(ca_pem)
            .map_err(|e| VaultError::Config(format!("CA cert: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_pem), Some(key_pem)) = (client_cert_pem, client_key_pem) {
        let mut combined = zeroize::Zeroizing::new(Vec::with_capacity(cert_pem.len() + key_pem.len()));
        combined.extend_from_slice(cert_pem);
        combined.extend_from_slice(key_pem);
        let identity = reqwest::tls::Identity::from_pem(&combined)
            .map_err(|e| VaultError::Config(format!("TLS identity: {e}")))?;
        drop(combined); // zeroize on drop
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| VaultError::Config(format!("reqwest client: {e}")))
}

// ---------------------------------------------------------------------------
// Handler accessors
// ---------------------------------------------------------------------------

impl VaultClient {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn kv1(&self, mount: &str) -> api::kv1::Kv1Handler<'_> {
        api::kv1::Kv1Handler {
            client: self,
            mount: encode_path(mount),
        }
    }

    pub fn kv2(&self, mount: &str) -> api::kv2::Kv2Handler<'_> {
        api::kv2::Kv2Handler {
            client: self,
            mount: encode_path(mount),
        }
    }

    pub fn transit(&self, mount: &str) -> api::transit::TransitHandler<'_> {
        api::transit::TransitHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    pub fn pki(&self, mount: &str) -> api::pki::PkiHandler<'_> {
        api::pki::PkiHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    pub fn sys(&self) -> api::sys::SysHandler<'_> {
        api::sys::SysHandler { client: self }
    }

    pub fn auth(&self) -> api::auth::AuthHandler<'_> {
        api::auth::AuthHandler { client: self }
    }

    /// Replace the current token at runtime.
    pub fn set_token(&self, token: SecretString) -> Result<(), VaultError> {
        let mut guard = self
            .inner
            .token
            .write()
            .map_err(|_| VaultError::LockPoisoned)?;
        *guard = Some(TokenState {
            value: token,
            accessor: None,
            expires_at: None,
            renewable: false,
            lease_duration: Duration::ZERO,
        });
        Ok(())
    }

    /// Return a client view with a different namespace. Cheap (Arc clone).
    pub fn with_namespace(&self, ns: &str) -> Self {
        VaultClient {
            inner: Arc::clone(&self.inner),
            namespace_override: Some(ns.to_owned()),
            wrap_ttl_override: self.wrap_ttl_override.clone(),
        }
    }

    /// Return a client view with a different wrap TTL. Cheap (Arc clone).
    pub fn with_wrap_ttl(&self, ttl: &str) -> Self {
        VaultClient {
            inner: Arc::clone(&self.inner),
            namespace_override: self.namespace_override.clone(),
            wrap_ttl_override: Some(ttl.to_owned()),
        }
    }

    /// Update internal token state from an auth response.
    pub(crate) fn update_token_from_auth(&self, auth: &AuthInfo) -> Result<(), VaultError> {
        let mut guard = self
            .inner
            .token
            .write()
            .map_err(|_| VaultError::LockPoisoned)?;
        *guard = Some(TokenState {
            value: auth.client_token.clone(),
            accessor: Some(auth.accessor.clone()),
            lease_duration: Duration::from_secs(auth.lease_duration),
            expires_at: if auth.lease_duration > 0 {
                Instant::now().checked_add(Duration::from_secs(auth.lease_duration))
            } else {
                None
            },
            renewable: auth.renewable,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Generic escape hatch
// ---------------------------------------------------------------------------

impl VaultClient {
    /// Read from an arbitrary Vault path. Deserializes the `data` field.
    pub async fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T, VaultError> {
        self.exec_with_data(Method::GET, path, None).await
    }

    /// Read from an arbitrary path, returning the full Vault response envelope.
    pub async fn read_raw(
        &self,
        path: &str,
    ) -> Result<VaultResponse<serde_json::Value>, VaultError> {
        self.exec_with_auth(Method::GET, path, None).await
    }

    /// Write to an arbitrary Vault path.
    pub async fn write<T: DeserializeOwned>(
        &self,
        path: &str,
        data: &impl Serialize,
    ) -> Result<VaultResponse<T>, VaultError> {
        let body = to_body(data)?;
        self.exec_with_auth(Method::POST, path, Some(&body)).await
    }

    /// Delete at an arbitrary Vault path.
    pub async fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.exec_empty(Method::DELETE, path, None).await
    }

    /// List keys at an arbitrary Vault path.
    pub async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.exec_list(path).await
    }
}

// ---------------------------------------------------------------------------
// Central execution layer
// ---------------------------------------------------------------------------

impl VaultClient {
    pub(crate) async fn exec_with_data<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        envelope.data.ok_or(VaultError::EmptyResponse)
    }

    pub(crate) async fn exec_with_auth<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<VaultResponse<T>, VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        Ok(envelope)
    }

    pub(crate) async fn exec_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(), VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        Ok(())
    }

    /// Deserialize response body directly (not through the Vault envelope).
    /// Used for endpoints like /sys/health that return flat JSON.
    pub(crate) async fn exec_direct<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, VaultError> {
        let resp = self.execute(method, path, body).await?;
        Ok(resp.json().await?)
    }

    pub(crate) async fn exec_list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        let resp = self.execute(METHOD_LIST.clone(), path, None).await?;
        if resp.status().as_u16() == 404 {
            return Ok(vec![]);
        }
        let envelope: VaultResponse<ListResponse> = resp.json().await?;
        Ok(envelope.data.map(|d| d.keys).unwrap_or_default())
    }

    pub(crate) async fn exec_patch<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, VaultError> {
        let resp = self.execute(Method::PATCH, path, Some(body)).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        envelope.data.ok_or(VaultError::EmptyResponse)
    }

    async fn execute(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Response, VaultError> {
        let url_str = format!("{}v1/{}", self.inner.base_url, path.trim_start_matches('/'));
        let url = Url::parse(&url_str)?;

        let mut req = self
            .inner
            .http
            .request(method.clone(), url.clone())
            .header("X-Vault-Request", "true");

        if method == Method::PATCH {
            req = req.header("Content-Type", "application/merge-patch+json");
        }

        req = self.inject_headers(req)?;

        if let Some(body) = body {
            req = req.json(body);
        }

        self.send_with_retry(req, &url, &method).await
    }

    fn inject_headers(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, VaultError> {
        let guard = self
            .inner
            .token
            .read()
            .map_err(|_| VaultError::LockPoisoned)?;
        if let Some(ts) = guard.as_ref() {
            req = req.header("X-Vault-Token", ts.value.expose_secret());
        }
        drop(guard);

        let ns = self
            .namespace_override
            .as_deref()
            .or(self.inner.namespace.as_deref());
        if let Some(ns) = ns {
            req = req.header("X-Vault-Namespace", ns);
        }
        let ttl = self
            .wrap_ttl_override
            .as_deref()
            .or(self.inner.config.wrap_ttl.as_deref());
        if let Some(ttl) = ttl {
            req = req.header("X-Vault-Wrap-TTL", ttl);
        }
        if self.inner.config.forward_to_leader {
            req = req.header("X-Vault-Forward", "active-node");
        }
        Ok(req)
    }

    async fn send_with_retry(
        &self,
        builder: reqwest::RequestBuilder,
        url: &Url,
        method: &Method,
    ) -> Result<Response, VaultError> {
        let max = self.inner.config.max_retries;
        let mut last_err: Option<VaultError> = None;
        let mut skip_backoff = false;

        for attempt in 0..=max {
            if attempt > 0 && !skip_backoff {
                let base = self
                    .inner
                    .config
                    .initial_retry_delay
                    .checked_mul(2u32.saturating_pow(attempt - 1))
                    .unwrap_or(MAX_BACKOFF);
                let capped = base.min(MAX_BACKOFF);
                let capped_ms = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX).max(1);
                let delay = Duration::from_millis(rand::rng().random_range(0u64..capped_ms));
                tracing::warn!(attempt, max, %url, %method, ?delay, "retrying");
                tokio::time::sleep(delay).await;
            }
            skip_backoff = false;

            let req = match builder.try_clone() {
                Some(r) => r,
                None => {
                    return Err(VaultError::Config(
                        "request body not cloneable (stream body?)".into(),
                    ));
                }
            };

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    match status {
                        200..=299 | 404 => return Ok(resp),
                        401 => {
                            return Err(VaultError::AuthRequired);
                        }
                        403 => {
                            let errors = Self::extract_errors(resp).await;
                            return Err(VaultError::PermissionDenied { errors });
                        }
                        429 => {
                            let retry_after = resp
                                .headers()
                                .get("Retry-After")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            if attempt >= max {
                                return Err(VaultError::RateLimited { retry_after });
                            }
                            last_err = Some(VaultError::RateLimited { retry_after });
                            if let Some(secs) = retry_after {
                                let capped = Duration::from_secs(secs).min(MAX_BACKOFF);
                                tokio::time::sleep(capped).await;
                                skip_backoff = true;
                            }
                            continue;
                        }
                        412 => {
                            if attempt >= max {
                                return Err(VaultError::ConsistencyRetry);
                            }
                            last_err = Some(VaultError::ConsistencyRetry);
                            continue;
                        }
                        503 => {
                            if attempt >= max {
                                return Err(VaultError::Sealed);
                            }
                            last_err = Some(VaultError::Sealed);
                            continue;
                        }
                        _ => {
                            let errors = Self::extract_errors(resp).await;
                            let err = VaultError::Api { status, errors };
                            if err.is_retryable() && attempt < max {
                                last_err = Some(err);
                                continue;
                            }
                            return Err(err);
                        }
                    }
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempt < max => {
                    last_err = Some(VaultError::Http(e));
                    continue;
                }
                Err(e) => return Err(VaultError::Http(e)),
            }
        }

        Err(VaultError::RetryExhausted {
            attempts: max.saturating_add(1),
            last_error: Box::new(
                last_err.unwrap_or_else(|| VaultError::Config("retry exhausted".into())),
            ),
        })
    }

    async fn extract_errors(resp: Response) -> Vec<String> {
        let body = resp.text().await.unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("errors")?.as_array().cloned())
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| if body.is_empty() { vec![] } else { vec![body] })
    }

    fn log_warnings(&self, warnings: &Option<Vec<String>>) {
        if let Some(warns) = warnings {
            for w in warns {
                tracing::debug!(warning = %w, "vault response warning");
            }
        }
    }
}

/// Serialize a value to `serde_json::Value`, mapping errors to `VaultError::Config`.
pub(crate) fn to_body(value: &impl Serialize) -> Result<serde_json::Value, VaultError> {
    serde_json::to_value(value).map_err(|e| VaultError::Config(format!("serialize: {e}")))
}

/// Percent-encode characters in a path segment that would cause URL parsing issues.
/// Preserves `/` as path separators; encodes `?`, `#`, `%`, spaces, and control chars.
pub(crate) fn encode_path(raw: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(raw.len());
    for &byte in raw.as_bytes() {
        match byte {
            b'?' | b'#' | b'%' | b' ' | b'[' | b']' | 0..=0x1F | 0x7F | 0x80..=0xFF => {
                write!(out, "%{byte:02X}").unwrap();
            }
            _ => out.push(byte as char),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::encode_path;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_encode_path_never_contains_raw_special_chars(s in "\\PC{0,128}") {
            let encoded = encode_path(&s);
            // The output should never contain unescaped ?, #, or raw spaces
            for (i, ch) in encoded.char_indices() {
                match ch {
                    '?' | '#' | ' ' | '[' | ']' => {
                        panic!("encode_path({s:?}) produced unescaped '{ch}' at index {i}: {encoded:?}");
                    }
                    _ => {}
                }
            }
        }

        #[test]
        fn prop_encode_path_percent_is_always_followed_by_hex(s in "\\PC{0,64}") {
            let encoded = encode_path(&s);
            let bytes = encoded.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'%' {
                    // Must be followed by exactly two hex digits
                    prop_assert!(i + 2 < bytes.len(),
                        "trailing percent in encode_path({:?}): {:?}", s, encoded);
                    prop_assert!(bytes[i + 1].is_ascii_hexdigit(),
                        "non-hex after percent in encode_path({:?}): {:?}", s, encoded);
                    prop_assert!(bytes[i + 2].is_ascii_hexdigit(),
                        "non-hex after percent in encode_path({:?}): {:?}", s, encoded);
                }
            }
        }

        #[test]
        fn prop_encode_path_preserves_slashes(s in "[a-z]{1,10}/[a-z]{1,10}/[a-z]{1,10}") {
            let encoded = encode_path(&s);
            prop_assert_eq!(&encoded, &s, "slashes should be preserved for path segments");
        }

        #[test]
        fn prop_encode_path_ascii_alnum_preserved(s in "[a-zA-Z0-9]{1,64}") {
            let encoded = encode_path(&s);
            prop_assert_eq!(&encoded, &s, "pure ASCII alphanumeric should pass through unchanged");
        }
    }

    #[test]
    fn encode_path_empty_string() {
        assert_eq!(encode_path(""), "");
    }

    #[test]
    fn encode_path_question_mark() {
        assert_eq!(encode_path("a?b"), "a%3Fb");
    }

    #[test]
    fn encode_path_hash() {
        assert_eq!(encode_path("a#b"), "a%23b");
    }

    #[test]
    fn encode_path_percent() {
        assert_eq!(encode_path("100%"), "100%25");
    }

    #[test]
    fn encode_path_multibyte_utf8() {
        // "café" = 63 61 66 c3 a9 — the é (U+00E9) is two bytes: 0xC3, 0xA9
        let encoded = encode_path("café");
        assert_eq!(encoded, "caf%C3%A9");
    }
}
