use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct NomadConfigRequest {
    pub address: String,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub token: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_token_name_length: Option<u32>,
}

impl Clone for NomadConfigRequest {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            token: self.token.clone(),
            max_token_name_length: self.max_token_name_length,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct NomadConfig {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub max_token_name_length: u32,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct NomadRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct NomadRole {
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default, rename = "type")]
    pub token_type: String,
    #[serde(default)]
    pub global: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct NomadCredentials {
    pub secret_id: SecretString,
    pub accessor_id: String,
}

impl Clone for NomadCredentials {
    fn clone(&self) -> Self {
        Self {
            secret_id: self.secret_id.clone(),
            accessor_id: self.accessor_id.clone(),
        }
    }
}

impl From<(String, SecretString)> for NomadCredentials {
    fn from((accessor_id, secret_id): (String, SecretString)) -> Self {
        Self {
            accessor_id,
            secret_id,
        }
    }
}

impl From<(&str, &str)> for NomadCredentials {
    fn from((accessor_id, secret_id): (&str, &str)) -> Self {
        Self {
            accessor_id: accessor_id.to_owned(),
            secret_id: SecretString::from(secret_id.to_owned()),
        }
    }
}

impl fmt::Debug for NomadCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NomadCredentials")
            .field("secret_id", &redact(self.secret_id.expose_secret()))
            .field("accessor_id", &self.accessor_id)
            .finish()
    }
}
