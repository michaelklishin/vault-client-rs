use std::collections::HashMap;

use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct VaultResponse<T> {
    pub request_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_duration: Option<u64>,
    pub renewable: Option<bool>,
    pub data: Option<T>,
    pub auth: Option<AuthInfo>,
    pub warnings: Option<Vec<String>>,
    pub wrap_info: Option<WrapInfo>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AuthInfo {
    pub client_token: SecretString,
    pub accessor: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    #[serde(default)]
    pub orphan: bool,
    pub mfa_requirement: Option<serde_json::Value>,
    pub num_uses: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct WrapInfo {
    pub token: SecretString,
    pub accessor: String,
    pub ttl: u64,
    pub creation_time: String,
    pub creation_path: String,
    pub wrapped_accessor: Option<String>,
}
