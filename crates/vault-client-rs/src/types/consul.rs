use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct ConsulConfigRequest {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub token: Option<SecretString>,
}

impl Clone for ConsulConfigRequest {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            scheme: self.scheme.clone(),
            token: self.token.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct ConsulConfig {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub scheme: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct ConsulRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consul_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consul_roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consul_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct ConsulRole {
    #[serde(default)]
    pub consul_policies: Vec<String>,
    #[serde(default)]
    pub consul_roles: Vec<String>,
    #[serde(default)]
    pub service_identities: Vec<String>,
    #[serde(default)]
    pub node_identities: Vec<String>,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub max_ttl: u64,
    #[serde(default)]
    pub local: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct ConsulCredentials {
    pub token: SecretString,
}

impl Clone for ConsulCredentials {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
        }
    }
}

impl From<SecretString> for ConsulCredentials {
    fn from(token: SecretString) -> Self {
        Self { token }
    }
}

impl From<&str> for ConsulCredentials {
    fn from(token: &str) -> Self {
        Self {
            token: SecretString::from(token.to_owned()),
        }
    }
}

impl fmt::Debug for ConsulCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsulCredentials")
            .field("token", &redact(self.token.expose_secret()))
            .finish()
    }
}
