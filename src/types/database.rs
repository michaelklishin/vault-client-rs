use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Default, Clone)]
pub struct DatabaseConfigRequest {
    pub plugin_name: String,
    pub connection_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
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

impl std::fmt::Debug for DatabaseConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfigRequest")
            .field("plugin_name", &self.plugin_name)
            .field("connection_url", &"[REDACTED]")
            .field("allowed_roles", &self.allowed_roles)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("max_open_connections", &self.max_open_connections)
            .field("max_idle_connections", &self.max_idle_connections)
            .field("max_connection_lifetime", &self.max_connection_lifetime)
            .field("username_template", &self.username_template)
            .field("verify_connection", &self.verify_connection)
            .finish()
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

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct DatabaseCredentials {
    pub username: SecretString,
    pub password: SecretString,
}

impl std::fmt::Debug for DatabaseCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct DatabaseStaticCredentials {
    pub username: SecretString,
    pub password: SecretString,
    pub last_vault_rotation: Option<String>,
    pub rotation_period: u64,
    pub ttl: u64,
}

impl std::fmt::Debug for DatabaseStaticCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseStaticCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("ttl", &self.ttl)
            .finish()
    }
}
