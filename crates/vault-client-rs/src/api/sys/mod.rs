mod audit;
mod health;
mod lease;
mod mounts;
mod namespaces;
mod plugins;
mod policy;
mod quotas;
mod raft;
mod rekey;
mod seal;
mod wrapping;

use std::collections::HashMap;

use secrecy::SecretString;
use serde::de::DeserializeOwned;

use crate::VaultClient;
use crate::api::traits::SysOperations;
use crate::types::error::VaultError;
use crate::types::response::WrapInfo;
use crate::types::sys::*;

#[derive(Debug)]
pub struct SysHandler<'a> {
    pub(crate) client: &'a VaultClient,
}

// Inherent methods are defined in the submodules (health.rs, seal.rs, etc.).
// This trait impl delegates to them for mockability.
impl SysOperations for SysHandler<'_> {
    async fn health(&self) -> Result<HealthResponse, VaultError> {
        self.health().await
    }
    async fn leader(&self) -> Result<LeaderResponse, VaultError> {
        self.leader().await
    }
    async fn seal_status(&self) -> Result<SealStatus, VaultError> {
        self.seal_status().await
    }
    async fn seal(&self) -> Result<(), VaultError> {
        self.seal().await
    }
    async fn unseal(&self, key: &SecretString) -> Result<SealStatus, VaultError> {
        self.unseal(key).await
    }
    async fn init(&self, params: &InitParams) -> Result<InitResponse, VaultError> {
        self.init(params).await
    }
    async fn step_down(&self) -> Result<(), VaultError> {
        self.step_down().await
    }
    async fn list_mounts(&self) -> Result<HashMap<String, MountInfo>, VaultError> {
        self.list_mounts().await
    }
    async fn mount(&self, path: &str, params: &MountParams) -> Result<(), VaultError> {
        self.mount(path, params).await
    }
    async fn unmount(&self, path: &str) -> Result<(), VaultError> {
        self.unmount(path).await
    }
    async fn tune_mount(&self, path: &str, params: &MountTuneParams) -> Result<(), VaultError> {
        self.tune_mount(path, params).await
    }
    async fn read_mount_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.read_mount_tune(path).await
    }
    async fn list_auth_mounts(&self) -> Result<HashMap<String, AuthMountInfo>, VaultError> {
        self.list_auth_mounts().await
    }
    async fn enable_auth(&self, path: &str, params: &AuthMountParams) -> Result<(), VaultError> {
        self.enable_auth(path, params).await
    }
    async fn disable_auth(&self, path: &str) -> Result<(), VaultError> {
        self.disable_auth(path).await
    }
    async fn read_auth_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.read_auth_tune(path).await
    }
    async fn list_policies(&self) -> Result<Vec<String>, VaultError> {
        self.list_policies().await
    }
    async fn read_policy(&self, name: &str) -> Result<PolicyInfo, VaultError> {
        self.read_policy(name).await
    }
    async fn write_policy(&self, name: &str, rules: &str) -> Result<(), VaultError> {
        self.write_policy(name, rules).await
    }
    async fn delete_policy(&self, name: &str) -> Result<(), VaultError> {
        self.delete_policy(name).await
    }
    async fn read_lease(&self, lease_id: &str) -> Result<LeaseInfo, VaultError> {
        self.read_lease(lease_id).await
    }
    async fn renew_lease(
        &self,
        lease_id: &str,
        increment: Option<&str>,
    ) -> Result<LeaseRenewal, VaultError> {
        self.renew_lease(lease_id, increment).await
    }
    async fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultError> {
        self.revoke_lease(lease_id).await
    }
    async fn revoke_prefix(&self, prefix: &str) -> Result<(), VaultError> {
        self.revoke_prefix(prefix).await
    }
    async fn list_audit_devices(&self) -> Result<HashMap<String, AuditDevice>, VaultError> {
        self.list_audit_devices().await
    }
    async fn enable_audit(&self, path: &str, params: &AuditParams) -> Result<(), VaultError> {
        self.enable_audit(path, params).await
    }
    async fn disable_audit(&self, path: &str) -> Result<(), VaultError> {
        self.disable_audit(path).await
    }
    async fn unwrap<T: DeserializeOwned + Send>(
        &self,
        token: &SecretString,
    ) -> Result<T, VaultError> {
        self.unwrap(token).await
    }
    async fn wrap_lookup(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        self.wrap_lookup(token).await
    }
    async fn capabilities(
        &self,
        token: &SecretString,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        self.capabilities(token, paths).await
    }
    async fn capabilities_self(
        &self,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        self.capabilities_self(paths).await
    }
    async fn key_status(&self) -> Result<KeyStatus, VaultError> {
        self.key_status().await
    }
    async fn rotate_encryption_key(&self) -> Result<(), VaultError> {
        self.rotate_encryption_key().await
    }

    // Plugins
    async fn list_plugins(&self, plugin_type: &str) -> Result<Vec<String>, VaultError> {
        self.list_plugins(plugin_type).await
    }
    async fn read_plugin(&self, plugin_type: &str, name: &str) -> Result<PluginInfo, VaultError> {
        self.read_plugin(plugin_type, name).await
    }
    async fn register_plugin(&self, params: &RegisterPluginRequest) -> Result<(), VaultError> {
        self.register_plugin(params).await
    }
    async fn deregister_plugin(&self, plugin_type: &str, name: &str) -> Result<(), VaultError> {
        self.deregister_plugin(plugin_type, name).await
    }
    async fn reload_plugin(&self, plugin: &str) -> Result<(), VaultError> {
        self.reload_plugin(plugin).await
    }

    // Raft
    async fn raft_config(&self) -> Result<RaftConfig, VaultError> {
        self.raft_config().await
    }
    async fn raft_autopilot_state(&self) -> Result<AutopilotState, VaultError> {
        self.raft_autopilot_state().await
    }
    async fn raft_remove_peer(&self, server_id: &str) -> Result<(), VaultError> {
        self.raft_remove_peer(server_id).await
    }
    async fn raft_snapshot(&self) -> Result<Vec<u8>, VaultError> {
        self.raft_snapshot().await
    }
    async fn raft_snapshot_restore(&self, snapshot: &[u8]) -> Result<(), VaultError> {
        self.raft_snapshot_restore(snapshot).await
    }

    // In-flight requests
    async fn in_flight_requests(&self) -> Result<HashMap<String, InFlightRequest>, VaultError> {
        self.in_flight_requests().await
    }

    // Namespaces
    async fn list_namespaces(&self) -> Result<Vec<String>, VaultError> {
        self.list_namespaces().await
    }
    async fn create_namespace(&self, path: &str) -> Result<NamespaceInfo, VaultError> {
        self.create_namespace(path).await
    }
    async fn delete_namespace(&self, path: &str) -> Result<(), VaultError> {
        self.delete_namespace(path).await
    }

    // Quotas
    async fn list_rate_limit_quotas(&self) -> Result<Vec<String>, VaultError> {
        self.list_rate_limit_quotas().await
    }
    async fn read_rate_limit_quota(&self, name: &str) -> Result<RateLimitQuota, VaultError> {
        self.read_rate_limit_quota(name).await
    }
    async fn write_rate_limit_quota(
        &self,
        name: &str,
        params: &RateLimitQuotaRequest,
    ) -> Result<(), VaultError> {
        self.write_rate_limit_quota(name, params).await
    }
    async fn delete_rate_limit_quota(&self, name: &str) -> Result<(), VaultError> {
        self.delete_rate_limit_quota(name).await
    }

    // Rekey
    async fn rekey_init(&self, params: &RekeyInitRequest) -> Result<RekeyStatus, VaultError> {
        self.rekey_init(params).await
    }
    async fn rekey_status(&self) -> Result<RekeyStatus, VaultError> {
        self.rekey_status().await
    }
    async fn rekey_cancel(&self) -> Result<(), VaultError> {
        self.rekey_cancel().await
    }
    async fn rekey_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> Result<RekeyStatus, VaultError> {
        self.rekey_update(key, nonce).await
    }

    // Generate root
    async fn generate_root_init(
        &self,
        params: &GenerateRootInitRequest,
    ) -> Result<GenerateRootStatus, VaultError> {
        self.generate_root_init(params).await
    }
    async fn generate_root_status(&self) -> Result<GenerateRootStatus, VaultError> {
        self.generate_root_status().await
    }
    async fn generate_root_cancel(&self) -> Result<(), VaultError> {
        self.generate_root_cancel().await
    }
    async fn generate_root_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> Result<GenerateRootStatus, VaultError> {
        self.generate_root_update(key, nonce).await
    }

    // Remount
    async fn remount(&self, from: &str, to: &str) -> Result<RemountStatus, VaultError> {
        self.remount(from, to).await
    }

    // Metrics & info
    async fn metrics_json(&self) -> Result<serde_json::Value, VaultError> {
        self.metrics_json().await
    }
    async fn host_info(&self) -> Result<HostInfo, VaultError> {
        self.host_info().await
    }
    async fn internal_counters_activity(&self) -> Result<serde_json::Value, VaultError> {
        self.internal_counters_activity().await
    }
    async fn version_history(&self) -> Result<Vec<VersionHistoryEntry>, VaultError> {
        self.version_history().await
    }

    // Wrapping (rewrap)
    async fn rewrap(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        self.rewrap(token).await
    }
}
