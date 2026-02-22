use std::collections::HashMap;
use std::future::Future;

use secrecy::SecretString;
use serde::de::DeserializeOwned;

use crate::types::auth::{
    AppRoleCreateRequest, AppRoleInfo, AppRoleSecretIdResponse, K8sAuthConfigRequest,
    K8sAuthRoleInfo, K8sAuthRoleRequest, TokenCreateRequest, TokenLookupResponse,
};
use crate::types::error::VaultError;
use crate::types::kv::{KvConfig, KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse};
use crate::types::pki::*;
use crate::types::response::{AuthInfo, WrapInfo};
use crate::types::sys::*;
use crate::types::transit::*;

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

    fn delete(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// Kv2Operations
// ---------------------------------------------------------------------------

pub trait Kv2Operations: Send + Sync {
    fn read_config(
        &self,
    ) -> impl Future<Output = Result<KvConfig, VaultError>> + Send;

    fn write_config(
        &self,
        cfg: &KvConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<KvReadResponse<T>, VaultError>> + Send;

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

    fn list(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn delete_metadata(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn list_keys(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete_key(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn update_key_config(
        &self,
        name: &str,
        cfg: &TransitKeyConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn rotate_key(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn write_cache_config(
        &self,
        size: u64,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
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

    fn delete_root(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_issuers(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_issuer(
        &self,
        issuer_ref: &str,
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

    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<PkiRole, VaultError>> + Send;

    fn list_roles(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn delete_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn list_certs(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_cert(
        &self,
        serial: &str,
    ) -> impl Future<Output = Result<PkiCertificateEntry, VaultError>> + Send;

    fn set_urls(
        &self,
        config: &PkiUrlsConfig,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_urls(
        &self,
    ) -> impl Future<Output = Result<PkiUrlsConfig, VaultError>> + Send;

    fn revoke(
        &self,
        serial: &str,
    ) -> impl Future<Output = Result<PkiRevocationInfo, VaultError>> + Send;

    fn revoke_with_key(
        &self,
        serial: &str,
        private_key: &SecretString,
    ) -> impl Future<Output = Result<PkiRevocationInfo, VaultError>> + Send;

    fn rotate_crl(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn tidy(
        &self,
        params: &PkiTidyParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn tidy_status(
        &self,
    ) -> impl Future<Output = Result<PkiTidyStatus, VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// SysOperations
// ---------------------------------------------------------------------------

pub trait SysOperations: Send + Sync {
    fn health(
        &self,
    ) -> impl Future<Output = Result<HealthResponse, VaultError>> + Send;

    fn leader(
        &self,
    ) -> impl Future<Output = Result<LeaderResponse, VaultError>> + Send;

    fn seal_status(
        &self,
    ) -> impl Future<Output = Result<SealStatus, VaultError>> + Send;

    fn seal(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn unseal(
        &self,
        key: &SecretString,
    ) -> impl Future<Output = Result<SealStatus, VaultError>> + Send;

    fn init(
        &self,
        params: &InitParams,
    ) -> impl Future<Output = Result<InitResponse, VaultError>> + Send;

    fn step_down(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_mounts(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, MountInfo>, VaultError>> + Send;

    fn mount(
        &self,
        path: &str,
        params: &MountParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn unmount(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn disable_auth(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_auth_tune(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<MountConfig, VaultError>> + Send;

    fn list_policies(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<PolicyInfo, VaultError>> + Send;

    fn write_policy(
        &self,
        name: &str,
        rules: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn delete_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn read_lease(
        &self,
        lease_id: &str,
    ) -> impl Future<Output = Result<LeaseInfo, VaultError>> + Send;

    fn renew_lease(
        &self,
        lease_id: &str,
        increment: Option<&str>,
    ) -> impl Future<Output = Result<LeaseRenewal, VaultError>> + Send;

    fn revoke_lease(
        &self,
        lease_id: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn revoke_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_audit_devices(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, AuditDevice>, VaultError>> + Send;

    fn enable_audit(
        &self,
        path: &str,
        params: &AuditParams,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn disable_audit(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

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

    fn key_status(
        &self,
    ) -> impl Future<Output = Result<KeyStatus, VaultError>> + Send;

    fn rotate_encryption_key(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
}

// ---------------------------------------------------------------------------
// TokenAuthOperations
// ---------------------------------------------------------------------------

pub trait TokenAuthOperations: Send + Sync {
    fn lookup_self(
        &self,
    ) -> impl Future<Output = Result<TokenLookupResponse, VaultError>> + Send;

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

    fn revoke(
        &self,
        token: &SecretString,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn revoke_self(
        &self,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn revoke_accessor(
        &self,
        accessor: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_accessors(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
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

    fn read_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<AppRoleInfo, VaultError>> + Send;

    fn delete_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_roles(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;

    fn read_role_id(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<String, VaultError>> + Send;

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

    fn delete_role(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    fn list_roles(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, VaultError>> + Send;
}
