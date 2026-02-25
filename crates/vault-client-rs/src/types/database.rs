use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct DatabaseConfigRequest {
    pub plugin_name: String,
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub connection_url: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_open_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connection_lifetime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_connection: Option<bool>,
}

impl Clone for DatabaseConfigRequest {
    fn clone(&self) -> Self {
        Self {
            plugin_name: self.plugin_name.clone(),
            connection_url: self.connection_url.clone(),
            allowed_roles: self.allowed_roles.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            max_open_connections: self.max_open_connections,
            max_idle_connections: self.max_idle_connections,
            max_connection_lifetime: self.max_connection_lifetime.clone(),
            username_template: self.username_template.clone(),
            verify_connection: self.verify_connection,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct DatabaseConfig {
    pub plugin_name: String,
    pub connection_details: serde_json::Value,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct DatabaseRoleRequest {
    pub db_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_statements: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_statements: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_statements: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_statements: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct DatabaseRole {
    pub db_name: String,
    #[serde(default)]
    pub creation_statements: Vec<String>,
    #[serde(default)]
    pub revocation_statements: Vec<String>,
    #[serde(default)]
    pub rollback_statements: Vec<String>,
    #[serde(default)]
    pub renew_statements: Vec<String>,
    pub default_ttl: u64,
    pub max_ttl: u64,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct DatabaseStaticRoleRequest {
    pub db_name: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_statements: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_period: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct DatabaseStaticRole {
    pub db_name: String,
    pub username: String,
    #[serde(default)]
    pub rotation_statements: Vec<String>,
    pub rotation_period: u64,
    pub last_vault_rotation: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct DatabaseCredentials {
    pub username: SecretString,
    pub password: SecretString,
}

impl Clone for DatabaseCredentials {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

impl From<(SecretString, SecretString)> for DatabaseCredentials {
    fn from((username, password): (SecretString, SecretString)) -> Self {
        Self { username, password }
    }
}

impl From<(&str, &str)> for DatabaseCredentials {
    fn from((username, password): (&str, &str)) -> Self {
        Self {
            username: SecretString::from(username.to_owned()),
            password: SecretString::from(password.to_owned()),
        }
    }
}

impl fmt::Debug for DatabaseCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseCredentials")
            .field("username", &redact(self.username.expose_secret()))
            .field("password", &redact(self.password.expose_secret()))
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct DatabaseStaticCredentials {
    pub username: SecretString,
    pub password: SecretString,
    pub last_vault_rotation: Option<String>,
    pub rotation_period: u64,
    pub ttl: u64,
}

impl Clone for DatabaseStaticCredentials {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
            last_vault_rotation: self.last_vault_rotation.clone(),
            rotation_period: self.rotation_period,
            ttl: self.ttl,
        }
    }
}

impl fmt::Debug for DatabaseStaticCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseStaticCredentials")
            .field("username", &redact(self.username.expose_secret()))
            .field("password", &redact(self.password.expose_secret()))
            .field("ttl", &self.ttl)
            .finish()
    }
}
