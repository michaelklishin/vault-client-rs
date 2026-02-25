use std::num::{ParseFloatError, ParseIntError};
use std::string::FromUtf8Error;

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VaultError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Vault API error (HTTP {status}): {}", errors.join("; "))]
    Api { status: u16, errors: Vec<String> },

    #[error("Vault is sealed ({url})")]
    Sealed { url: String },

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

    #[error("Invalid client configuration: {0}")]
    Config(String),

    #[error("Failed to deserialize response: {0}")]
    Deserialize(#[source] serde_json::Error),

    #[error("URL construction error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Internal lock poisoned")]
    LockPoisoned,

    #[error("Circuit breaker is open — Vault appears unreachable")]
    CircuitOpen,

    #[error("Field '{field}' not found at '{mount}/{path}'")]
    FieldNotFound { mount: String, path: String, field: String },
}

impl From<serde_json::Error> for VaultError {
    fn from(err: serde_json::Error) -> Self {
        Self::Deserialize(err)
    }
}

impl From<FromUtf8Error> for VaultError {
    fn from(err: FromUtf8Error) -> Self {
        Self::Config(format!("invalid UTF-8: {err}"))
    }
}

impl From<ParseIntError> for VaultError {
    fn from(err: ParseIntError) -> Self {
        Self::Config(format!("integer parse error: {err}"))
    }
}

impl From<ParseFloatError> for VaultError {
    fn from(err: ParseFloatError) -> Self {
        Self::Config(format!("float parse error: {err}"))
    }
}

impl VaultError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Sealed { .. } | Self::RateLimited { .. } | Self::ConsistencyRetry => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503 | 504),
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
            Self::Sealed { .. } => Some(503),
            _ => None,
        }
    }
}
