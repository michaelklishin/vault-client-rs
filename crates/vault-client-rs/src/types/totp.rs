use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct TotpKeyRequest {
    pub generate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skew: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_size: Option<u32>,
}

impl Clone for TotpKeyRequest {
    fn clone(&self) -> Self {
        Self {
            generate: self.generate,
            exported: self.exported,
            key_size: self.key_size,
            url: self.url.clone(),
            key: self.key.clone(),
            issuer: self.issuer.clone(),
            account_name: self.account_name.clone(),
            period: self.period,
            algorithm: self.algorithm.clone(),
            digits: self.digits,
            skew: self.skew,
            qr_size: self.qr_size,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TotpKeyInfo {
    #[serde(default)]
    pub account_name: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub digits: u32,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub period: u32,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TotpGenerateResponse {
    pub barcode: Option<SecretString>,
    pub url: Option<SecretString>,
}

impl Clone for TotpGenerateResponse {
    fn clone(&self) -> Self {
        Self {
            barcode: self.barcode.clone(),
            url: self.url.clone(),
        }
    }
}

impl fmt::Debug for TotpGenerateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpGenerateResponse")
            .field(
                "barcode",
                &self.barcode.as_ref().map(|s| redact(s.expose_secret())),
            )
            .field("url", &self.url.as_ref().map(|s| redact(s.expose_secret())))
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TotpCode {
    pub code: SecretString,
}

impl Clone for TotpCode {
    fn clone(&self) -> Self {
        Self {
            code: self.code.clone(),
        }
    }
}

impl From<SecretString> for TotpCode {
    fn from(code: SecretString) -> Self {
        Self { code }
    }
}

impl From<&str> for TotpCode {
    fn from(code: &str) -> Self {
        Self {
            code: SecretString::from(code.to_owned()),
        }
    }
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &redact(self.code.expose_secret()))
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TotpValidation {
    pub valid: bool,
}
