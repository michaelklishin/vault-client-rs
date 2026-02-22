use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

// --- Health ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct HealthResponse {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    #[serde(default)]
    pub performance_standby: bool,
    pub replication_performance_mode: Option<String>,
    pub replication_dr_mode: Option<String>,
    pub server_time_utc: Option<u64>,
    pub version: String,
    pub cluster_name: Option<String>,
    pub cluster_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LeaderResponse {
    pub ha_enabled: bool,
    pub is_self: bool,
    #[serde(default)]
    pub leader_address: String,
    #[serde(default)]
    pub leader_cluster_address: String,
    #[serde(default)]
    pub performance_standby: bool,
}

// --- Seal ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct SealStatus {
    #[serde(rename = "type")]
    pub seal_type: String,
    pub initialized: bool,
    pub sealed: bool,
    pub t: u32,
    pub n: u32,
    pub progress: u32,
    pub nonce: String,
    pub version: String,
    pub build_date: Option<String>,
    pub migration: Option<bool>,
    pub cluster_name: Option<String>,
    pub cluster_id: Option<String>,
    pub recovery_seal: Option<bool>,
    pub storage_type: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct InitParams {
    pub secret_shares: u32,
    pub secret_threshold: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_token_pgp_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_shares: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_threshold: Option<u32>,
}

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct InitResponse {
    #[serde(default)]
    pub keys: Vec<SecretString>,
    #[serde(default)]
    pub keys_base64: Vec<SecretString>,
    pub root_token: SecretString,
}

impl std::fmt::Debug for InitResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitResponse")
            .field("keys", &format_args!("[REDACTED; {} keys]", self.keys.len()))
            .field("keys_base64", &format_args!("[REDACTED; {} keys]", self.keys_base64.len()))
            .field("root_token", &"[REDACTED]")
            .finish()
    }
}

// --- Mounts ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct MountInfo {
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(default)]
    pub description: String,
    pub accessor: String,
    pub config: MountConfig,
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub seal_wrap: bool,
    #[serde(default)]
    pub external_entropy_access: bool,
    pub options: Option<HashMap<String, String>>,
    pub uuid: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct MountConfig {
    pub default_lease_ttl: u64,
    pub max_lease_ttl: u64,
    #[serde(default)]
    pub force_no_cache: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct MountParams {
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountTuneParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct MountTuneParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_lease_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AuthMountInfo {
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(default)]
    pub description: String,
    pub accessor: String,
    pub config: MountConfig,
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub seal_wrap: bool,
    pub uuid: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuthMountParams {
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountTuneParams>,
}

// --- Policies ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PolicyInfo {
    pub name: String,
    pub policy: String,
}

// --- Leases ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LeaseInfo {
    pub id: String,
    pub issue_time: String,
    pub expire_time: Option<String>,
    pub last_renewal: Option<String>,
    pub renewable: bool,
    pub ttl: u64,
}

/// Lease renewal response. Vault returns renewal info at the response envelope
/// level (not inside `.data`), so this maps directly to the top-level fields.
#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LeaseRenewal {
    pub lease_id: String,
    pub lease_duration: u64,
    pub renewable: bool,
}

// --- Audit ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AuditDevice {
    #[serde(rename = "type")]
    pub audit_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    pub path: String,
    #[serde(default)]
    pub local: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditParams {
    #[serde(rename = "type")]
    pub audit_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub options: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

// --- Wrapping ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KeyStatus {
    pub term: u64,
    pub install_time: String,
    pub encryptions: Option<u64>,
}

