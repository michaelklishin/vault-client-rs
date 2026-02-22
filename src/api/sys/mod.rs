mod audit;
mod health;
mod lease;
mod mounts;
mod policy;
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
}
