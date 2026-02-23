use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct RabbitmqConfigRequest {
    pub connection_uri: String,
    pub username: String,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_connection: Option<bool>,
}

impl Clone for RabbitmqConfigRequest {
    fn clone(&self) -> Self {
        Self {
            connection_uri: self.connection_uri.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            verify_connection: self.verify_connection,
        }
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct RabbitmqRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhosts: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhost_topics: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RabbitmqRole {
    #[serde(default)]
    pub vhosts: serde_json::Value,
    #[serde(default)]
    pub vhost_topics: serde_json::Value,
    #[serde(default)]
    pub tags: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct RabbitmqCredentials {
    pub username: String,
    pub password: SecretString,
}

impl Clone for RabbitmqCredentials {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

impl From<(String, SecretString)> for RabbitmqCredentials {
    fn from((username, password): (String, SecretString)) -> Self {
        Self { username, password }
    }
}

impl From<(&str, &str)> for RabbitmqCredentials {
    fn from((username, password): (&str, &str)) -> Self {
        Self {
            username: username.to_owned(),
            password: SecretString::from(password.to_owned()),
        }
    }
}

impl fmt::Debug for RabbitmqCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RabbitmqCredentials")
            .field("username", &self.username)
            .field("password", &redact(self.password.expose_secret()))
            .finish()
    }
}
