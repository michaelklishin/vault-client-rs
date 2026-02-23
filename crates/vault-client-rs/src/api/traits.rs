use std::collections::HashMap;
use std::future::Future;

use secrecy::SecretString;
use serde::de::DeserializeOwned;

use crate::types::auth::*;
use crate::types::aws::*;
use crate::types::azure::*;
use crate::types::consul::*;
use crate::types::database::*;
use crate::types::error::VaultError;
use crate::types::gcp::*;
use crate::types::identity::*;
use crate::types::kv::{KvConfig, KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse};
use crate::types::nomad::*;
use crate::types::pki::*;
use crate::types::rabbitmq::*;
use crate::types::response::{AuthInfo, WrapInfo};
use crate::types::ssh::*;
use crate::types::sys::*;
use crate::types::terraform::*;
use crate::types::totp::*;
use crate::types::transit::*;

// ---------------------------------------------------------------------------
// CubbyholeOperations
// ---------------------------------------------------------------------------

pub trait CubbyholeOperations: Send + Sync {
    fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, VaultError>> + Send;

    fn write(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn delete(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list(&self, path: &str) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// Kv1Operations
// ---------------------------------------------------------------------------

pub trait Kv1Operations: Send + Sync {
    fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, VaultError>> + Send;

    fn write(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn delete(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list(&self, path: &str) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// Kv2Operations
// ---------------------------------------------------------------------------

pub trait Kv2Operations: Send + Sync {
    fn read_config(&self) -> impl Future<Output = Result<KvConfig, VaultError>> + Send;

    fn write_config(&self, cfg: &KvConfig) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<KvReadResponse<T>, VaultError>> + Send;

    /// Read a secret and return just the data, discarding metadata
    fn read_data<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<T, VaultError>> + Send;

    fn read_version<T: DeserializeOwned + Send>(
        &self,
        path: &str,
        version: u64,
    ) -> impl Future<Output = Result<KvReadResponse<T>, VaultError>> + Send;

    fn write(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> impl Future<Output = Result<KvMetadata, VaultError>> + Send;

    fn write_cas(
        &self,
        path: &str,
        data: &serde_json::Value,
        cas: u64,
    ) -> impl Future<Output = Result<KvMetadata, VaultError>> + Send;

    fn patch(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> impl Future<Output = Result<KvMetadata, VaultError>> + Send;

    fn list(&self, path: &str) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn delete_versions(
        &self,
        path: &str,
        versions: &[u64],
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn undelete_versions(
        &self,
        path: &str,
        versions: &[u64],
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn destroy_versions(
        &self,
        path: &str,
        versions: &[u64],
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_metadata(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<KvFullMetadata, VaultError>> + Send;

    fn write_metadata(
        &self,
        path: &str,
        meta: &KvMetadataParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn patch_metadata(
        &self,
        path: &str,
        meta: &KvMetadataParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn delete_metadata(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_subkeys(
        &self,
        path: &str,
        depth: Option<u32>,
    ) -> impl Future<Output = Result<serde_json::Value, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// TransitOperations
// ---------------------------------------------------------------------------

pub trait TransitOperations: Send + Sync {
    fn create_key(
        &self,
        name: &str,
        params: &TransitKeyParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_key(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<TransitKeyInfo, VaultError>> + Send;

    fn list_keys(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete_key(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn update_key_config(
        &self,
        name: &str,
        cfg: &TransitKeyConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn rotate_key(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn export_key(
        &self,
        name: &str,
        key_type: &str,
        version: Option<u64>,
    ) -> impl Future<Output = Result<TransitExportedKey, VaultError>> + Send;

    fn encrypt(
        &self,
        name: &str,
        plaintext: &SecretString,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn decrypt(
        &self,
        name: &str,
        ciphertext: &str,
    ) -> impl Future<Output = Result<SecretString, VaultError>> + Send;

    fn rewrap(
        &self,
        name: &str,
        ciphertext: &str,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn batch_encrypt(
        &self,
        name: &str,
        items: &[TransitBatchPlaintext],
    ) -> impl Future<Output = Result<Vec<TransitBatchCiphertext>, VaultError>> + Send;

    fn batch_decrypt(
        &self,
        name: &str,
        items: &[TransitBatchCiphertext],
    ) -> impl Future<Output = Result<Vec<TransitBatchDecryptItem>, VaultError>> + Send;

    fn sign(
        &self,
        name: &str,
        input: &[u8],
        params: &TransitSignParams,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn verify(
        &self,
        name: &str,
        input: &[u8],
        signature: &str,
    ) -> impl Future<Output = Result<bool, VaultError>> + Send;

    fn batch_sign(
        &self,
        name: &str,
        items: &[TransitBatchSignInput],
        params: &TransitSignParams,
    ) -> impl Future<Output = Result<Vec<TransitBatchSignResult>, VaultError>> + Send;

    fn batch_verify(
        &self,
        name: &str,
        items: &[TransitBatchVerifyInput],
    ) -> impl Future<Output = Result<Vec<TransitBatchVerifyResult>, VaultError>> + Send;

    fn hash(
        &self,
        input: &[u8],
        algorithm: &str,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn hmac(
        &self,
        name: &str,
        input: &[u8],
        algorithm: &str,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn random(
        &self,
        num_bytes: u32,
        format: &str,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

    fn generate_data_key(
        &self,
        name: &str,
        key_type: &str,
    ) -> impl Future<Output = Result<TransitDataKey, VaultError>> + Send;

    fn trim_key(
        &self,
        name: &str,
        min_version: u64,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn backup_key(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<SecretString, VaultError>> + Send;

    fn restore_key(
        &self,
        name: &str,
        backup: &SecretString,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_cache_config(
        &self,
    ) -> impl Future<Output = Result<TransitCacheConfig, VaultError>> + Send;

    fn write_cache_config(&self, size: u64) -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// PkiOperations
// ---------------------------------------------------------------------------

pub trait PkiOperations: Send + Sync {
    fn generate_root(
        &self,
        params: &PkiRootParams,
    ) -> impl Future<Output = Result<PkiCertificate, VaultError>> + Send;

    fn generate_intermediate_csr(
        &self,
        params: &PkiIntermediateParams,
    ) -> impl Future<Output = Result<PkiCsr, VaultError>> + Send;

    fn set_signed_intermediate(
        &self,
        certificate: &str,
    ) -> impl Future<Output = Result<PkiImportResult, VaultError>> + Send;

    fn delete_root(&self) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_issuers(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_issuer(
        &self,
        issuer_ref: &str,
    ) -> impl Future<Output = Result<PkiIssuerInfo, VaultError>> + Send;

    fn update_issuer(
        &self,
        issuer_ref: &str,
        params: &PkiIssuerUpdateParams,
    ) -> impl Future<Output = Result<PkiIssuerInfo, VaultError>> + Send;

    fn delete_issuer(
        &self,
        issuer_ref: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn create_role(
        &self,
        name: &str,
        params: &PkiRoleParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_role(&self, name: &str) -> impl Future<Output = Result<PkiRole, VaultError>> + Send;

    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn issue(
        &self,
        role: &str,
        params: &PkiIssueParams,
    ) -> impl Future<Output = Result<PkiIssuedCert, VaultError>> + Send;

    fn sign(
        &self,
        role: &str,
        params: &PkiSignParams,
    ) -> impl Future<Output = Result<PkiSignedCert, VaultError>> + Send;

    fn sign_verbatim(
        &self,
        role: &str,
        csr: &str,
    ) -> impl Future<Output = Result<PkiSignedCert, VaultError>> + Send;

    fn list_certs(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_cert(
        &self,
        serial: &str,
    ) -> impl Future<Output = Result<PkiCertificateEntry, VaultError>> + Send;

    fn set_urls(
        &self,
        config: &PkiUrlsConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_urls(&self) -> impl Future<Output = Result<PkiUrlsConfig, VaultError>> + Send;

    fn revoke(
        &self,
        serial: &str,
    ) -> impl Future<Output = Result<PkiRevocationInfo, VaultError>> + Send;

    fn revoke_with_key(
        &self,
        serial: &str,
        private_key: &SecretString,
    ) -> impl Future<Output = Result<PkiRevocationInfo, VaultError>> + Send;

    fn rotate_crl(&self) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn tidy(&self, params: &PkiTidyParams) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn tidy_status(&self) -> impl Future<Output = Result<PkiTidyStatus, VaultError>> + Send;

    fn cross_sign_intermediate(
        &self,
        params: &PkiCrossSignRequest,
    ) -> impl Future<Output = Result<PkiCertificate, VaultError>> + Send;

    fn read_acme_config(&self) -> impl Future<Output = Result<PkiAcmeConfig, VaultError>> + Send;

    fn write_acme_config(
        &self,
        config: &PkiAcmeConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn rotate_delta_crl(&self) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_crl(&self) -> impl Future<Output = Result<Vec<u8>, VaultError>> + Send;

    fn read_crl_delta(&self) -> impl Future<Output = Result<Vec<u8>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// SysOperations
// ---------------------------------------------------------------------------

pub trait SysOperations: Send + Sync {
    fn health(&self) -> impl Future<Output = Result<HealthResponse, VaultError>> + Send;
    fn leader(&self) -> impl Future<Output = Result<LeaderResponse, VaultError>> + Send;
    fn seal_status(&self) -> impl Future<Output = Result<SealStatus, VaultError>> + Send;
    fn seal(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn unseal(
        &self,
        key: &SecretString,
    ) -> impl Future<Output = Result<SealStatus, VaultError>> + Send;
    fn init(
        &self,
        params: &InitParams,
    ) -> impl Future<Output = Result<InitResponse, VaultError>> + Send;
    fn step_down(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_mounts(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, MountInfo>, VaultError>> + Send;
    fn mount(
        &self,
        path: &str,
        params: &MountParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn unmount(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn tune_mount(
        &self,
        path: &str,
        params: &MountTuneParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_mount_tune(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<MountConfig, VaultError>> + Send;
    fn list_auth_mounts(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, AuthMountInfo>, VaultError>> + Send;
    fn enable_auth(
        &self,
        path: &str,
        params: &AuthMountParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn disable_auth(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_auth_tune(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<MountConfig, VaultError>> + Send;
    fn list_policies(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn read_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<PolicyInfo, VaultError>> + Send;
    fn write_policy(
        &self,
        name: &str,
        rules: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn delete_policy(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_lease(
        &self,
        lease_id: &str,
    ) -> impl Future<Output = Result<LeaseInfo, VaultError>> + Send;
    fn renew_lease(
        &self,
        lease_id: &str,
        increment: Option<&str>,
    ) -> impl Future<Output = Result<LeaseRenewal, VaultError>> + Send;
    fn revoke_lease(&self, lease_id: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn revoke_prefix(&self, prefix: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_audit_devices(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, AuditDevice>, VaultError>> + Send;
    fn enable_audit(
        &self,
        path: &str,
        params: &AuditParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn disable_audit(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn unwrap<T: DeserializeOwned + Send>(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<T, VaultError>> + Send;
    fn wrap_lookup(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<WrapInfo, VaultError>> + Send;
    fn capabilities(
        &self,
        token: &SecretString,
        paths: &[&str],
    ) -> impl Future<Output = Result<HashMap<String, Vec<String>>, VaultError>> + Send;
    fn capabilities_self(
        &self,
        paths: &[&str],
    ) -> impl Future<Output = Result<HashMap<String, Vec<String>>, VaultError>> + Send;
    fn key_status(&self) -> impl Future<Output = Result<KeyStatus, VaultError>> + Send;
    fn rotate_encryption_key(&self) -> impl Future<Output = Result<(), VaultError>> + Send;

    // Plugins
    fn list_plugins(
        &self,
        plugin_type: &str,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn read_plugin(
        &self,
        plugin_type: &str,
        name: &str,
    ) -> impl Future<Output = Result<PluginInfo, VaultError>> + Send;
    fn register_plugin(
        &self,
        params: &RegisterPluginRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn deregister_plugin(
        &self,
        plugin_type: &str,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn reload_plugin(&self, plugin: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    // Raft
    fn raft_config(&self) -> impl Future<Output = Result<RaftConfig, VaultError>> + Send;
    fn raft_autopilot_state(
        &self,
    ) -> impl Future<Output = Result<AutopilotState, VaultError>> + Send;
    fn raft_remove_peer(
        &self,
        server_id: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn raft_snapshot(&self) -> impl Future<Output = Result<Vec<u8>, VaultError>> + Send;
    fn raft_snapshot_restore(
        &self,
        snapshot: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    // In-flight requests
    fn in_flight_requests(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, InFlightRequest>, VaultError>> + Send;

    // Namespaces
    fn list_namespaces(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn create_namespace(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<NamespaceInfo, VaultError>> + Send;
    fn delete_namespace(&self, path: &str) -> impl Future<Output = Result<(), VaultError>> + Send;

    // Quotas
    fn list_rate_limit_quotas(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn read_rate_limit_quota(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<RateLimitQuota, VaultError>> + Send;
    fn write_rate_limit_quota(
        &self,
        name: &str,
        params: &RateLimitQuotaRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn delete_rate_limit_quota(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    // Rekey
    fn rekey_init(
        &self,
        params: &RekeyInitRequest,
    ) -> impl Future<Output = Result<RekeyStatus, VaultError>> + Send;
    fn rekey_status(&self) -> impl Future<Output = Result<RekeyStatus, VaultError>> + Send;
    fn rekey_cancel(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn rekey_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> impl Future<Output = Result<RekeyStatus, VaultError>> + Send;

    // Generate root
    fn generate_root_init(
        &self,
        params: &GenerateRootInitRequest,
    ) -> impl Future<Output = Result<GenerateRootStatus, VaultError>> + Send;
    fn generate_root_status(
        &self,
    ) -> impl Future<Output = Result<GenerateRootStatus, VaultError>> + Send;
    fn generate_root_cancel(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn generate_root_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> impl Future<Output = Result<GenerateRootStatus, VaultError>> + Send;

    // Remount
    fn remount(
        &self,
        from: &str,
        to: &str,
    ) -> impl Future<Output = Result<RemountStatus, VaultError>> + Send;

    // Metrics & info
    fn metrics_json(&self) -> impl Future<Output = Result<serde_json::Value, VaultError>> + Send;
    fn host_info(&self) -> impl Future<Output = Result<HostInfo, VaultError>> + Send;
    fn internal_counters_activity(
        &self,
    ) -> impl Future<Output = Result<serde_json::Value, VaultError>> + Send;
    fn version_history(
        &self,
    ) -> impl Future<Output = Result<Vec<VersionHistoryEntry>, VaultError>> + Send;

    // Wrapping (rewrap)
    fn rewrap(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<WrapInfo, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// TokenAuthOperations
// ---------------------------------------------------------------------------

pub trait TokenAuthOperations: Send + Sync {
    fn lookup_self(&self) -> impl Future<Output = Result<TokenLookupResponse, VaultError>> + Send;
    fn lookup(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<TokenLookupResponse, VaultError>> + Send;
    fn renew_self(
        &self,
        increment: Option<&str>,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn create(
        &self,
        params: &TokenCreateRequest,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn create_orphan(
        &self,
        params: &TokenCreateRequest,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn revoke(&self, token: &SecretString) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn revoke_self(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn revoke_accessor(
        &self,
        accessor: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_accessors(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// AppRoleAuthOperations
// ---------------------------------------------------------------------------

pub trait AppRoleAuthOperations: Send + Sync {
    fn login(
        &self,
        role_id: &str,
        secret_id: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &AppRoleCreateRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str)
    -> impl Future<Output = Result<AppRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn read_role_id(&self, name: &str) -> impl Future<Output = Result<String, VaultError>> + Send;
    fn generate_secret_id(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<AppRoleSecretIdResponse, VaultError>> + Send;
    fn destroy_secret_id(
        &self,
        name: &str,
        secret_id: &SecretString,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// K8sAuthOperations
// ---------------------------------------------------------------------------

pub trait K8sAuthOperations: Send + Sync {
    fn login(
        &self,
        role: &str,
        jwt: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &K8sAuthConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &K8sAuthRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<K8sAuthRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// UserpassAuthOperations
// ---------------------------------------------------------------------------

pub trait UserpassAuthOperations: Send + Sync {
    fn login(
        &self,
        username: &str,
        password: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn create_user(
        &self,
        username: &str,
        params: &UserpassUserRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_user(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<UserpassUserInfo, VaultError>> + Send;
    fn delete_user(&self, username: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_users(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn update_password(
        &self,
        username: &str,
        password: &SecretString,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// LdapAuthOperations
// ---------------------------------------------------------------------------

pub trait LdapAuthOperations: Send + Sync {
    fn login(
        &self,
        username: &str,
        password: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &LdapConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<LdapConfig, VaultError>> + Send;
    fn write_group(
        &self,
        name: &str,
        params: &LdapGroupRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_group(&self, name: &str) -> impl Future<Output = Result<LdapGroup, VaultError>> + Send;
    fn delete_group(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_groups(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn write_user(
        &self,
        name: &str,
        params: &LdapUserRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_user(&self, name: &str) -> impl Future<Output = Result<LdapUser, VaultError>> + Send;
    fn delete_user(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_users(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// CertAuthOperations
// ---------------------------------------------------------------------------

pub trait CertAuthOperations: Send + Sync {
    fn login(
        &self,
        name: Option<&str>,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &CertRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<CertRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// GithubAuthOperations
// ---------------------------------------------------------------------------

pub trait GithubAuthOperations: Send + Sync {
    fn login(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &GithubConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<GithubConfig, VaultError>> + Send;
    fn map_team(
        &self,
        team: &str,
        params: &GithubTeamMapping,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_team_mapping(
        &self,
        team: &str,
    ) -> impl Future<Output = Result<GithubTeamInfo, VaultError>> + Send;
    fn list_teams(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// OidcAuthOperations
// ---------------------------------------------------------------------------

pub trait OidcAuthOperations: Send + Sync {
    fn login_jwt(
        &self,
        role: &str,
        jwt: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &OidcConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<OidcConfig, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &OidcRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<OidcRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// DatabaseOperations
// ---------------------------------------------------------------------------

pub trait DatabaseOperations: Send + Sync {
    fn configure(
        &self,
        name: &str,
        params: &DatabaseConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<DatabaseConfig, VaultError>> + Send;
    fn delete_config(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_connections(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn reset_connection(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &DatabaseRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<DatabaseRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<DatabaseCredentials, VaultError>> + Send;
    fn create_static_role(
        &self,
        name: &str,
        params: &DatabaseStaticRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_static_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<DatabaseStaticRole, VaultError>> + Send;
    fn delete_static_role(&self, name: &str)
    -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_static_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_static_credentials(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<DatabaseStaticCredentials, VaultError>> + Send;
    fn rotate_static_role(&self, name: &str)
    -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// SshOperations
// ---------------------------------------------------------------------------

pub trait SshOperations: Send + Sync {
    fn configure_ca(
        &self,
        params: &SshCaConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_public_key(&self) -> impl Future<Output = Result<SshCaPublicKey, VaultError>> + Send;
    fn delete_ca(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &SshRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str) -> impl Future<Output = Result<SshRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn sign_key(
        &self,
        role: &str,
        params: &SshSignRequest,
    ) -> impl Future<Output = Result<SshSignedKey, VaultError>> + Send;
    fn verify_otp(
        &self,
        params: &SshVerifyRequest,
    ) -> impl Future<Output = Result<SshVerifyResponse, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// IdentityOperations
// ---------------------------------------------------------------------------

pub trait IdentityOperations: Send + Sync {
    fn create_entity(
        &self,
        params: &EntityCreateRequest,
    ) -> impl Future<Output = Result<Entity, VaultError>> + Send;
    fn read_entity(&self, id: &str) -> impl Future<Output = Result<Entity, VaultError>> + Send;
    fn read_entity_by_name(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Entity, VaultError>> + Send;
    fn update_entity(
        &self,
        id: &str,
        params: &EntityCreateRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn delete_entity(&self, id: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_entities(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn create_entity_alias(
        &self,
        params: &EntityAliasCreateRequest,
    ) -> impl Future<Output = Result<EntityAliasResponse, VaultError>> + Send;
    fn read_entity_alias(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<EntityAliasResponse, VaultError>> + Send;
    fn delete_entity_alias(&self, id: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_entity_aliases(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn create_group(
        &self,
        params: &GroupCreateRequest,
    ) -> impl Future<Output = Result<Group, VaultError>> + Send;
    fn read_group(&self, id: &str) -> impl Future<Output = Result<Group, VaultError>> + Send;
    fn read_group_by_name(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Group, VaultError>> + Send;
    fn update_group(
        &self,
        id: &str,
        params: &GroupCreateRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn delete_group(&self, id: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_groups(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn create_group_alias(
        &self,
        params: &GroupAliasCreateRequest,
    ) -> impl Future<Output = Result<GroupAliasResponse, VaultError>> + Send;
    fn read_group_alias(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<GroupAliasResponse, VaultError>> + Send;
    fn delete_group_alias(&self, id: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_group_aliases(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// AwsSecretsOperations
// ---------------------------------------------------------------------------

pub trait AwsSecretsOperations: Send + Sync {
    fn configure_root(
        &self,
        params: &AwsConfigRootRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config_root(&self) -> impl Future<Output = Result<AwsConfigRoot, VaultError>> + Send;
    fn rotate_root(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &AwsRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str) -> impl Future<Output = Result<AwsRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<AwsCredentials, VaultError>> + Send;
    fn get_sts_credentials(
        &self,
        name: &str,
        params: &AwsStsRequest,
    ) -> impl Future<Output = Result<AwsCredentials, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// AwsAuthOperations
// ---------------------------------------------------------------------------

pub trait AwsAuthOperations: Send + Sync {
    fn login(
        &self,
        params: &AwsAuthLoginRequest,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &AwsAuthConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<AwsAuthConfig, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &AwsAuthRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<AwsAuthRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// TotpOperations
// ---------------------------------------------------------------------------

pub trait TotpOperations: Send + Sync {
    fn create_key(
        &self,
        name: &str,
        params: &TotpKeyRequest,
    ) -> impl Future<Output = Result<Option<TotpGenerateResponse>, VaultError>> + Send;
    fn read_key(&self, name: &str) -> impl Future<Output = Result<TotpKeyInfo, VaultError>> + Send;
    fn delete_key(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_keys(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn generate_code(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<TotpCode, VaultError>> + Send;
    fn validate_code(
        &self,
        name: &str,
        code: &str,
    ) -> impl Future<Output = Result<TotpValidation, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// ConsulOperations
// ---------------------------------------------------------------------------

pub trait ConsulOperations: Send + Sync {
    fn configure(
        &self,
        params: &ConsulConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<ConsulConfig, VaultError>> + Send;
    fn delete_config(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &ConsulRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str) -> impl Future<Output = Result<ConsulRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<ConsulCredentials, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// NomadOperations
// ---------------------------------------------------------------------------

pub trait NomadOperations: Send + Sync {
    fn configure(
        &self,
        params: &NomadConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<NomadConfig, VaultError>> + Send;
    fn delete_config(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &NomadRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str) -> impl Future<Output = Result<NomadRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<NomadCredentials, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// AzureSecretsOperations
// ---------------------------------------------------------------------------

pub trait AzureSecretsOperations: Send + Sync {
    fn configure(
        &self,
        params: &AzureConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<AzureConfig, VaultError>> + Send;
    fn delete_config(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &AzureRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(&self, name: &str) -> impl Future<Output = Result<AzureRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<AzureCredentials, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// AzureAuthOperations
// ---------------------------------------------------------------------------

pub trait AzureAuthOperations: Send + Sync {
    fn login(
        &self,
        role: &str,
        jwt: &SecretString,
        subscription_id: Option<&str>,
        resource_group_name: Option<&str>,
        vm_name: Option<&str>,
        vmss_name: Option<&str>,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &AzureAuthConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<AzureAuthConfig, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &AzureAuthRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<AzureAuthRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// GcpSecretsOperations
// ---------------------------------------------------------------------------

pub trait GcpSecretsOperations: Send + Sync {
    fn configure(
        &self,
        params: &GcpConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<GcpConfig, VaultError>> + Send;
    fn delete_config(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_roleset(
        &self,
        name: &str,
        params: &GcpRolesetRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_roleset(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<GcpRoleset, VaultError>> + Send;
    fn delete_roleset(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_rolesets(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_service_account_key(
        &self,
        roleset: &str,
    ) -> impl Future<Output = Result<GcpServiceAccountKey, VaultError>> + Send;
    fn get_oauth_token(
        &self,
        roleset: &str,
    ) -> impl Future<Output = Result<GcpOAuthToken, VaultError>> + Send;
    fn rotate_roleset(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// GcpAuthOperations
// ---------------------------------------------------------------------------

pub trait GcpAuthOperations: Send + Sync {
    fn login(
        &self,
        role: &str,
        jwt: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &GcpAuthConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<GcpAuthConfig, VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &GcpAuthRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<GcpAuthRoleInfo, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// RabbitmqOperations
// ---------------------------------------------------------------------------

pub trait RabbitmqOperations: Send + Sync {
    fn configure(
        &self,
        params: &RabbitmqConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn configure_lease(
        &self,
        ttl: &str,
        max_ttl: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &RabbitmqRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<RabbitmqRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<RabbitmqCredentials, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// TerraformCloudOperations
// ---------------------------------------------------------------------------

pub trait TerraformCloudOperations: Send + Sync {
    fn configure(
        &self,
        params: &TerraformCloudConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<TerraformCloudConfig, VaultError>> + Send;
    fn delete_config(&self) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn create_role(
        &self,
        name: &str,
        params: &TerraformCloudRoleRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<TerraformCloudRole, VaultError>> + Send;
    fn delete_role(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_roles(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
    fn get_credentials(
        &self,
        role: &str,
    ) -> impl Future<Output = Result<TerraformCloudToken, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// RadiusAuthOperations
// ---------------------------------------------------------------------------

pub trait RadiusAuthOperations: Send + Sync {
    fn login(
        &self,
        username: &str,
        password: &SecretString,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &RadiusConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<RadiusConfig, VaultError>> + Send;
    fn write_user(
        &self,
        username: &str,
        params: &RadiusUserRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_user(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<RadiusUser, VaultError>> + Send;
    fn delete_user(&self, username: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_users(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// KerberosAuthOperations
// ---------------------------------------------------------------------------

pub trait KerberosAuthOperations: Send + Sync {
    fn login(
        &self,
        authorization: &str,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send;
    fn configure(
        &self,
        config: &KerberosConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_config(&self) -> impl Future<Output = Result<KerberosConfig, VaultError>> + Send;
    fn configure_ldap(
        &self,
        config: &KerberosLdapConfigRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_ldap_config(
        &self,
    ) -> impl Future<Output = Result<KerberosLdapConfig, VaultError>> + Send;
    fn write_group(
        &self,
        name: &str,
        params: &KerberosGroupRequest,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn read_group(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<KerberosGroup, VaultError>> + Send;
    fn delete_group(&self, name: &str) -> impl Future<Output = Result<(), VaultError>> + Send;
    fn list_groups(&self) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}
