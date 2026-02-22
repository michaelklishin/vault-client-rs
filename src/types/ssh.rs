use secrecy::SecretString;
use serde::{Deserialize, Serialize};

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

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct SshSignedKey {
    pub serial_number: String,
    pub signed_key: SecretString,
}

impl std::fmt::Debug for SshSignedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSignedKey")
            .field("serial_number", &self.serial_number)
            .field("signed_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Default, Clone)]
pub struct SshCaConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generate_signing_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
}

impl std::fmt::Debug for SshCaConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshCaConfigRequest")
            .field("generate_signing_key", &self.generate_signing_key)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("public_key", &self.public_key)
            .field("key_type", &self.key_type)
            .field("key_bits", &self.key_bits)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SshCaPublicKey {
    pub public_key: String,
}

#[derive(Serialize, Default, Clone)]
pub struct SshVerifyRequest {
    pub otp: String,
}

impl std::fmt::Debug for SshVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshVerifyRequest")
            .field("otp", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SshVerifyResponse {
    pub ip: String,
    pub username: String,
}
