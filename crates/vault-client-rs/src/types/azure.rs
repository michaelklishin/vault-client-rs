use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct AzureConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

impl Clone for AzureConfigRequest {
    fn clone(&self) -> Self {
        Self {
            subscription_id: self.subscription_id.clone(),
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            environment: self.environment.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AzureConfig {
    #[serde(default)]
    pub subscription_id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub environment: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct AzureRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_roles: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_groups: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AzureRole {
    #[serde(default)]
    pub azure_roles: serde_json::Value,
    #[serde(default)]
    pub azure_groups: serde_json::Value,
    #[serde(default)]
    pub application_object_id: String,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub max_ttl: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct AzureCredentials {
    pub client_id: String,
    pub client_secret: SecretString,
}

impl Clone for AzureCredentials {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        }
    }
}

impl From<(String, SecretString)> for AzureCredentials {
    fn from((client_id, client_secret): (String, SecretString)) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

impl From<(&str, &str)> for AzureCredentials {
    fn from((client_id, client_secret): (&str, &str)) -> Self {
        Self {
            client_id: client_id.to_owned(),
            client_secret: SecretString::from(client_secret.to_owned()),
        }
    }
}

impl fmt::Debug for AzureCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &redact(self.client_secret.expose_secret()))
            .finish()
    }
}

// Azure Auth types
#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct AzureAuthConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret: Option<SecretString>,
}

impl Clone for AzureAuthConfigRequest {
    fn clone(&self) -> Self {
        Self {
            tenant_id: self.tenant_id.clone(),
            resource: self.resource.clone(),
            environment: self.environment.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AzureAuthConfig {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub client_id: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct AzureAuthRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_service_principal_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_group_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_locations: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subscription_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_resource_groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_scale_sets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AzureAuthRoleInfo {
    #[serde(default)]
    pub bound_service_principal_ids: Vec<String>,
    #[serde(default)]
    pub bound_group_ids: Vec<String>,
    #[serde(default)]
    pub bound_locations: Vec<String>,
    #[serde(default)]
    pub bound_subscription_ids: Vec<String>,
    #[serde(default)]
    pub bound_resource_groups: Vec<String>,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_policies: Vec<String>,
}

// Azure auth login request
#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct AzureAuthLoginRequest {
    pub role: String,
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub jwt: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmss_name: Option<String>,
}

impl Clone for AzureAuthLoginRequest {
    fn clone(&self) -> Self {
        Self {
            role: self.role.clone(),
            jwt: self.jwt.clone(),
            subscription_id: self.subscription_id.clone(),
            resource_group_name: self.resource_group_name.clone(),
            vm_name: self.vm_name.clone(),
            vmss_name: self.vmss_name.clone(),
        }
    }
}
