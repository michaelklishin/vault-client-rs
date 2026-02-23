use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

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

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct InitResponse {
    #[serde(default)]
    pub keys: Vec<SecretString>,
    #[serde(default)]
    pub keys_base64: Vec<SecretString>,
    pub root_token: SecretString,
}

impl Clone for InitResponse {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            keys_base64: self.keys_base64.clone(),
            root_token: self.root_token.clone(),
        }
    }
}

impl std::fmt::Debug for InitResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self
            .keys
            .iter()
            .map(|s| redact(s.expose_secret()))
            .collect();
        let keys_b64: Vec<String> = self
            .keys_base64
            .iter()
            .map(|s| redact(s.expose_secret()))
            .collect();
        f.debug_struct("InitResponse")
            .field("keys", &keys)
            .field("keys_base64", &keys_b64)
            .field("root_token", &redact(self.root_token.expose_secret()))
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

/// Lease renewal response
///
/// Vault returns renewal info at the response envelope level (not inside
/// `.data`), so this maps directly to the top-level fields
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

// --- Key status ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KeyStatus {
    pub term: u64,
    pub install_time: String,
    pub encryptions: Option<u64>,
}

// --- Plugins ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PluginInfo {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub sha256: String,
    pub version: Option<String>,
    pub builtin: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct RegisterPluginRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    pub command: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// --- Raft ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RaftConfig {
    #[serde(default)]
    pub servers: Vec<RaftServer>,
    pub index: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RaftServer {
    pub node_id: String,
    pub address: String,
    pub leader: bool,
    pub voter: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AutopilotState {
    pub healthy: bool,
    pub failure_tolerance: u64,
    pub leader: String,
    #[serde(default)]
    pub voters: Vec<String>,
    #[serde(default)]
    pub servers: HashMap<String, AutopilotServerState>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AutopilotServerState {
    pub id: String,
    pub name: String,
    pub address: String,
    pub node_status: String,
    pub status: String,
    pub healthy: bool,
    pub last_contact: String,
    pub last_index: u64,
    pub last_term: u64,
    pub voter: bool,
    pub leader: bool,
}

// --- Namespaces (Enterprise) ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct NamespaceInfo {
    pub id: String,
    pub path: String,
}

// --- Quotas ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct RateLimitQuotaRequest {
    pub name: String,
    pub rate: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inheritable: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RateLimitQuota {
    pub name: String,
    pub rate: f64,
    pub burst: u64,
    pub path: String,
    pub interval: Option<String>,
    pub block_interval: Option<String>,
    pub role: Option<String>,
    #[serde(rename = "type")]
    pub quota_type: Option<String>,
}

// --- Rekey ---

#[derive(Debug, Serialize, Clone)]
pub struct RekeyInitRequest {
    pub secret_shares: u32,
    pub secret_threshold: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct RekeyStatus {
    pub started: bool,
    pub nonce: String,
    pub t: u32,
    pub n: u32,
    pub progress: u32,
    pub required: u32,
    pub pgp_finger_prints: Option<Vec<String>>,
    pub backup: bool,
    pub verification_required: bool,
    pub complete: bool,
    pub keys: Option<Vec<SecretString>>,
    pub keys_base64: Option<Vec<SecretString>>,
}

impl Clone for RekeyStatus {
    fn clone(&self) -> Self {
        Self {
            started: self.started,
            nonce: self.nonce.clone(),
            t: self.t,
            n: self.n,
            progress: self.progress,
            required: self.required,
            pgp_finger_prints: self.pgp_finger_prints.clone(),
            backup: self.backup,
            verification_required: self.verification_required,
            complete: self.complete,
            keys: self.keys.clone(),
            keys_base64: self.keys_base64.clone(),
        }
    }
}

impl std::fmt::Debug for RekeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekeyStatus")
            .field("started", &self.started)
            .field("nonce", &self.nonce)
            .field("t", &self.t)
            .field("n", &self.n)
            .field("progress", &self.progress)
            .field("required", &self.required)
            .field("pgp_finger_prints", &self.pgp_finger_prints)
            .field("backup", &self.backup)
            .field("verification_required", &self.verification_required)
            .field("complete", &self.complete)
            .field(
                "keys",
                &self.keys.as_ref().map(|v| {
                    v.iter()
                        .map(|s| redact(s.expose_secret()))
                        .collect::<Vec<_>>()
                }),
            )
            .field(
                "keys_base64",
                &self.keys_base64.as_ref().map(|v| {
                    v.iter()
                        .map(|s| redact(s.expose_secret()))
                        .collect::<Vec<_>>()
                }),
            )
            .finish()
    }
}

// --- Generate root ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct GenerateRootInitRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_key: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct GenerateRootStatus {
    pub started: bool,
    #[zeroize(skip)]
    pub nonce: String,
    pub progress: u32,
    pub required: u32,
    pub complete: bool,
    pub encoded_token: Option<SecretString>,
    pub encoded_root_token: Option<SecretString>,
    pub otp_length: Option<u64>,
    pub otp: Option<SecretString>,
}

impl Clone for GenerateRootStatus {
    fn clone(&self) -> Self {
        Self {
            started: self.started,
            nonce: self.nonce.clone(),
            progress: self.progress,
            required: self.required,
            complete: self.complete,
            encoded_token: self.encoded_token.clone(),
            encoded_root_token: self.encoded_root_token.clone(),
            otp_length: self.otp_length,
            otp: self.otp.clone(),
        }
    }
}

impl std::fmt::Debug for GenerateRootStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateRootStatus")
            .field("started", &self.started)
            .field("nonce", &self.nonce)
            .field("progress", &self.progress)
            .field("required", &self.required)
            .field("complete", &self.complete)
            .field(
                "encoded_token",
                &self
                    .encoded_token
                    .as_ref()
                    .map(|s| redact(s.expose_secret())),
            )
            .field(
                "encoded_root_token",
                &self
                    .encoded_root_token
                    .as_ref()
                    .map(|s| redact(s.expose_secret())),
            )
            .field("otp_length", &self.otp_length)
            .field("otp", &self.otp.as_ref().map(|s| redact(s.expose_secret())))
            .finish()
    }
}

// --- Remount ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RemountStatus {
    pub migration_id: String,
}

// --- Host info ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct HostInfo {
    pub cpu: Option<Vec<serde_json::Value>>,
    pub disk: Option<Vec<serde_json::Value>>,
    pub host: Option<serde_json::Value>,
    pub memory: Option<serde_json::Value>,
    pub timestamp: String,
}

// --- In-flight requests ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct InFlightRequest {
    pub request_id: String,
    pub request_path: String,
    pub client_address: String,
    pub start_time: String,
}

// --- Version history ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct VersionHistoryEntry {
    #[serde(default)]
    pub version: String,
    pub timestamp_installed: String,
    pub build_date: Option<String>,
    pub previous_version: Option<String>,
}
