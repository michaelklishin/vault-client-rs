use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VaultError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Vault API error (HTTP {status}): {}", errors.join("; "))]
    Api { status: u16, errors: Vec<String> },

    #[error("Vault is sealed")]
    Sealed,

    #[error("Permission denied: {}", errors.join("; "))]
    PermissionDenied { errors: Vec<String> },

    #[error("Resource not found at {path}")]
    NotFound { path: String },

    #[error("Rate limited (HTTP 429){}", retry_after.map(|s| format!("; retry after {s}s")).unwrap_or_default())]
    RateLimited { retry_after: Option<u64> },

    #[error("Eventual consistency retry needed (HTTP 412)")]
    ConsistencyRetry,

    #[error("Empty response from Vault where data was expected")]
    EmptyResponse,

    #[error("Authentication required or token expired")]
    AuthRequired,

    #[error("Request failed after {attempts} retries")]
    RetryExhausted {
        attempts: u32,
        #[source]
        last_error: Box<VaultError>,
    },

    #[error("Invalid client configuration: {0}")]
    Config(String),

    #[error("URL construction error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Internal lock poisoned")]
    LockPoisoned,
}

impl VaultError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Sealed | Self::RateLimited { .. } | Self::ConsistencyRetry => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503),
            _ => false,
        }
    }

    #[must_use]
    pub fn is_auth_error(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. } | Self::AuthRequired)
    }

    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            Self::AuthRequired => Some(401),
            Self::PermissionDenied { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ConsistencyRetry => Some(412),
            Self::Sealed => Some(503),
            _ => None,
        }
    }
}
