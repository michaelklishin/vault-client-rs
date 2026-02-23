use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct GcpConfigRequest {
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub credentials: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
}

impl Clone for GcpConfigRequest {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
            ttl: self.ttl.clone(),
            max_ttl: self.max_ttl.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GcpConfig {
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub max_ttl: u64,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct GcpRolesetRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GcpRoleset {
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub bindings: serde_json::Value,
    #[serde(default)]
    pub secret_type: String,
    #[serde(default)]
    pub token_scopes: Vec<String>,
    #[serde(default)]
    pub service_account_email: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct GcpServiceAccountKey {
    pub private_key_data: SecretString,
    #[serde(default)]
    pub key_algorithm: String,
    #[serde(default)]
    pub key_type: String,
}

impl Clone for GcpServiceAccountKey {
    fn clone(&self) -> Self {
        Self {
            private_key_data: self.private_key_data.clone(),
            key_algorithm: self.key_algorithm.clone(),
            key_type: self.key_type.clone(),
        }
    }
}

impl fmt::Debug for GcpServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpServiceAccountKey")
            .field(
                "private_key_data",
                &redact(self.private_key_data.expose_secret()),
            )
            .field("key_algorithm", &self.key_algorithm)
            .field("key_type", &self.key_type)
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct GcpOAuthToken {
    pub token: SecretString,
    #[serde(default)]
    pub expires_at_seconds: u64,
    #[serde(default)]
    pub token_ttl: u64,
}

impl Clone for GcpOAuthToken {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            expires_at_seconds: self.expires_at_seconds,
            token_ttl: self.token_ttl,
        }
    }
}

impl fmt::Debug for GcpOAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpOAuthToken")
            .field("token", &redact(self.token.expose_secret()))
            .field("expires_at_seconds", &self.expires_at_seconds)
            .field("token_ttl", &self.token_ttl)
            .finish()
    }
}

// GCP Auth types
#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct GcpAuthConfigRequest {
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub credentials: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gce_alias: Option<String>,
}

impl Clone for GcpAuthConfigRequest {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
            iam_alias: self.iam_alias.clone(),
            gce_alias: self.gce_alias.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GcpAuthConfig {
    #[serde(default)]
    pub iam_alias: String,
    #[serde(default)]
    pub gce_alias: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct GcpAuthRoleRequest {
    #[serde(rename = "type")]
    pub role_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_service_accounts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_projects: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_zones: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_regions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_instance_groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_labels: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GcpAuthRoleInfo {
    #[serde(default, rename = "type")]
    pub role_type: String,
    #[serde(default)]
    pub bound_service_accounts: Vec<String>,
    #[serde(default)]
    pub bound_projects: Vec<String>,
    #[serde(default)]
    pub bound_zones: Vec<String>,
    #[serde(default)]
    pub bound_regions: Vec<String>,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_policies: Vec<String>,
}
