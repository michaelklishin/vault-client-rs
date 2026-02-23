use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Clone)]
pub struct SshRoleRequest {
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_users: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_critical_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_extensions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_extensions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_user_certificates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_host_certificates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_bare_domains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_subdomains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_signer: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SshRole {
    pub key_type: String,
    pub default_user: String,
    pub allowed_users: String,
    pub ttl: String,
    pub max_ttl: String,
    pub allowed_critical_options: String,
    pub allowed_extensions: String,
    pub allow_user_certificates: bool,
    pub allow_host_certificates: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct SshSignRequest {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_principals: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_options: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct SshSignedKey {
    pub serial_number: String,
    pub signed_key: SecretString,
}

impl Clone for SshSignedKey {
    fn clone(&self) -> Self {
        Self {
            serial_number: self.serial_number.clone(),
            signed_key: self.signed_key.clone(),
        }
    }
}

impl std::fmt::Debug for SshSignedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSignedKey")
            .field("serial_number", &self.serial_number)
            .field("signed_key", &redact(self.signed_key.expose_secret()))
            .finish()
    }
}

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct SshCaConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generate_signing_key: Option<bool>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
}

impl Clone for SshCaConfigRequest {
    fn clone(&self) -> Self {
        Self {
            generate_signing_key: self.generate_signing_key,
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
            key_type: self.key_type.clone(),
            key_bits: self.key_bits,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SshCaPublicKey {
    pub public_key: String,
}

#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct SshVerifyRequest {
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub otp: SecretString,
}

impl Clone for SshVerifyRequest {
    fn clone(&self) -> Self {
        Self {
            otp: self.otp.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SshVerifyResponse {
    pub ip: String,
    pub username: String,
}
