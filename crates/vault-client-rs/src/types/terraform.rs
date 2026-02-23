use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct TerraformCloudConfigRequest {
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub token: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl Clone for TerraformCloudConfigRequest {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            address: self.address.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TerraformCloudConfig {
    #[serde(default)]
    pub address: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct TerraformCloudRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TerraformCloudRole {
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub team_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub max_ttl: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TerraformCloudToken {
    pub token: SecretString,
    #[serde(default)]
    pub token_id: String,
}

impl Clone for TerraformCloudToken {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            token_id: self.token_id.clone(),
        }
    }
}

impl From<SecretString> for TerraformCloudToken {
    fn from(token: SecretString) -> Self {
        Self {
            token,
            token_id: String::new(),
        }
    }
}

impl fmt::Debug for TerraformCloudToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerraformCloudToken")
            .field("token", &redact(self.token.expose_secret()))
            .field("token_id", &self.token_id)
            .finish()
    }
}
