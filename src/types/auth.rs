use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

// --- Token auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct TokenCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_parent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_default_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_alias: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TokenLookupResponse {
    pub accessor: String,
    pub creation_time: u64,
    pub creation_ttl: u64,
    pub display_name: String,
    pub entity_id: String,
    pub expire_time: Option<String>,
    pub explicit_max_ttl: u64,
    pub id: SecretString,
    pub issue_time: String,
    pub meta: Option<HashMap<String, String>>,
    pub num_uses: u64,
    pub orphan: bool,
    pub path: String,
    #[serde(default)]
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: u64,
    #[serde(rename = "type")]
    pub token_type: String,
}

// --- AppRole auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct AppRoleCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_secret_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AppRoleInfo {
    pub bind_secret_id: bool,
    #[serde(default)]
    pub secret_id_bound_cidrs: Vec<String>,
    #[serde(default)]
    pub token_bound_cidrs: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    pub token_num_uses: u64,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AppRoleRoleIdResponse {
    pub role_id: String,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AppRoleSecretIdResponse {
    pub secret_id: SecretString,
    pub secret_id_accessor: String,
    pub secret_id_num_uses: u64,
    pub secret_id_ttl: u64,
}

// --- Kubernetes auth ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct K8sAuthRoleInfo {
    #[serde(default)]
    pub bound_service_account_names: Vec<String>,
    #[serde(default)]
    pub bound_service_account_namespaces: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Serialize, Default, Clone)]
pub struct K8sAuthConfigRequest {
    pub kubernetes_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes_ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_reviewer_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_local_ca_jwt: Option<bool>,
}

impl std::fmt::Debug for K8sAuthConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sAuthConfigRequest")
            .field("kubernetes_host", &self.kubernetes_host)
            .field("kubernetes_ca_cert", &self.kubernetes_ca_cert)
            .field("token_reviewer_jwt", &self.token_reviewer_jwt.as_ref().map(|_| "[REDACTED]"))
            .field("disable_local_ca_jwt", &self.disable_local_ca_jwt)
            .finish()
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct K8sAuthRoleRequest {
    pub bound_service_account_names: Vec<String>,
    pub bound_service_account_namespaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}
