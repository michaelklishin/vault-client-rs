use std::collections::HashMap;

use secrecy::SecretString;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::api::traits::{
    AppRoleAuthOperations, K8sAuthOperations, Kv1Operations, Kv2Operations, PkiOperations,
    TokenAuthOperations, TransitOperations,
};
use crate::client::blocking_client::BlockingVaultClient;
use crate::types::auth::*;
use crate::types::error::VaultError;
use crate::types::kv::*;
use crate::types::pki::*;
use crate::types::response::{AuthInfo, WrapInfo};
use crate::types::sys::*;
use crate::types::transit::*;

pub use crate::client::blocking_client::{
    BlockingClientBuilder, BlockingVaultClient as VaultClient,
};

// ---------------------------------------------------------------------------
// Handler accessors
// ---------------------------------------------------------------------------

impl BlockingVaultClient {
    pub fn kv1(&self, mount: &str) -> Kv1Handler<'_> {
        Kv1Handler {
            inner: self.inner.kv1(mount),
            rt: &self.rt,
        }
    }

    pub fn kv2(&self, mount: &str) -> Kv2Handler<'_> {
        Kv2Handler {
            inner: self.inner.kv2(mount),
            rt: &self.rt,
        }
    }

    pub fn transit(&self, mount: &str) -> TransitHandler<'_> {
        TransitHandler {
            inner: self.inner.transit(mount),
            rt: &self.rt,
        }
    }

    pub fn pki(&self, mount: &str) -> PkiHandler<'_> {
        PkiHandler {
            inner: self.inner.pki(mount),
            rt: &self.rt,
        }
    }

    pub fn sys(&self) -> SysHandler<'_> {
        SysHandler {
            inner: self.inner.sys(),
            rt: &self.rt,
        }
    }

    pub fn auth(&self) -> AuthHandler<'_> {
        AuthHandler {
            inner: self.inner.auth(),
            rt: &self.rt,
        }
    }
}

// ---------------------------------------------------------------------------
// Generic escape hatch
// ---------------------------------------------------------------------------

impl BlockingVaultClient {
    /// Read from an arbitrary Vault path. Deserializes the `data` field.
    pub fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T, VaultError> {
        self.rt.block_on(self.inner.read(path))
    }

    /// Read from an arbitrary path, returning the full Vault response envelope.
    pub fn read_raw(
        &self,
        path: &str,
    ) -> Result<crate::types::response::VaultResponse<serde_json::Value>, VaultError> {
        self.rt.block_on(self.inner.read_raw(path))
    }

    /// Write to an arbitrary Vault path.
    pub fn write<T: DeserializeOwned>(
        &self,
        path: &str,
        data: &impl Serialize,
    ) -> Result<crate::types::response::VaultResponse<T>, VaultError> {
        self.rt.block_on(self.inner.write(path, data))
    }

    /// Delete at an arbitrary Vault path.
    pub fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete(path))
    }

    /// List keys at an arbitrary Vault path.
    pub fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list(path))
    }
}

// ---------------------------------------------------------------------------
// KV v1
// ---------------------------------------------------------------------------

pub struct Kv1Handler<'a> {
    inner: crate::api::kv1::Kv1Handler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl Kv1Handler<'_> {
    pub fn read<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        self.rt.block_on(self.inner.read(path))
    }

    pub fn write(&self, path: &str, data: &impl Serialize) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write(path, data))
    }

    pub fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete(path))
    }

    pub fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list(path))
    }
}

// ---------------------------------------------------------------------------
// KV v2
// ---------------------------------------------------------------------------

pub struct Kv2Handler<'a> {
    inner: crate::api::kv2::Kv2Handler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl Kv2Handler<'_> {
    pub fn read_config(&self) -> Result<KvConfig, VaultError> {
        self.rt.block_on(self.inner.read_config())
    }

    pub fn write_config(&self, cfg: &KvConfig) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_config(cfg))
    }

    pub fn read<T: DeserializeOwned + Send>(&self, path: &str) -> Result<KvReadResponse<T>, VaultError> {
        self.rt.block_on(self.inner.read(path))
    }

    pub fn read_version<T: DeserializeOwned + Send>(
        &self,
        path: &str,
        version: u64,
    ) -> Result<KvReadResponse<T>, VaultError> {
        self.rt.block_on(self.inner.read_version(path, version))
    }

    pub fn write(&self, path: &str, data: &impl Serialize) -> Result<KvMetadata, VaultError> {
        self.rt.block_on(self.inner.write(path, data))
    }

    pub fn write_cas(
        &self,
        path: &str,
        data: &impl Serialize,
        cas: u64,
    ) -> Result<KvMetadata, VaultError> {
        self.rt.block_on(self.inner.write_cas(path, data, cas))
    }

    pub fn patch(&self, path: &str, data: &impl Serialize) -> Result<KvMetadata, VaultError> {
        self.rt.block_on(self.inner.patch(path, data))
    }

    pub fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list(path))
    }

    pub fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete(path))
    }

    pub fn delete_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_versions(path, versions))
    }

    pub fn undelete_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.undelete_versions(path, versions))
    }

    pub fn destroy_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.destroy_versions(path, versions))
    }

    pub fn read_metadata(&self, path: &str) -> Result<KvFullMetadata, VaultError> {
        self.rt.block_on(self.inner.read_metadata(path))
    }

    pub fn write_metadata(&self, path: &str, meta: &KvMetadataParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_metadata(path, meta))
    }

    pub fn delete_metadata(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_metadata(path))
    }

    pub fn read_subkeys(
        &self,
        path: &str,
        depth: Option<u32>,
    ) -> Result<serde_json::Value, VaultError> {
        self.rt.block_on(self.inner.read_subkeys(path, depth))
    }
}

// ---------------------------------------------------------------------------
// Transit
// ---------------------------------------------------------------------------

pub struct TransitHandler<'a> {
    inner: crate::api::transit::TransitHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl TransitHandler<'_> {
    pub fn create_key(&self, name: &str, params: &TransitKeyParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_key(name, params))
    }

    pub fn read_key(&self, name: &str) -> Result<TransitKeyInfo, VaultError> {
        self.rt.block_on(self.inner.read_key(name))
    }

    pub fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_keys())
    }

    pub fn delete_key(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_key(name))
    }

    pub fn update_key_config(
        &self,
        name: &str,
        cfg: &TransitKeyConfig,
    ) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.update_key_config(name, cfg))
    }

    pub fn rotate_key(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rotate_key(name))
    }

    pub fn export_key(
        &self,
        name: &str,
        key_type: &str,
        version: Option<u64>,
    ) -> Result<TransitExportedKey, VaultError> {
        self.rt
            .block_on(self.inner.export_key(name, key_type, version))
    }

    pub fn encrypt(&self, name: &str, plaintext: &SecretString) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.encrypt(name, plaintext))
    }

    pub fn decrypt(&self, name: &str, ciphertext: &str) -> Result<SecretString, VaultError> {
        self.rt.block_on(self.inner.decrypt(name, ciphertext))
    }

    pub fn rewrap(&self, name: &str, ciphertext: &str) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.rewrap(name, ciphertext))
    }

    pub fn batch_encrypt(
        &self,
        name: &str,
        items: &[TransitBatchPlaintext],
    ) -> Result<Vec<TransitBatchCiphertext>, VaultError> {
        self.rt.block_on(self.inner.batch_encrypt(name, items))
    }

    pub fn batch_decrypt(
        &self,
        name: &str,
        items: &[TransitBatchCiphertext],
    ) -> Result<Vec<TransitBatchDecryptItem>, VaultError> {
        self.rt.block_on(self.inner.batch_decrypt(name, items))
    }

    pub fn sign(
        &self,
        name: &str,
        input: &[u8],
        params: &TransitSignParams,
    ) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.sign(name, input, params))
    }

    pub fn verify(
        &self,
        name: &str,
        input: &[u8],
        signature: &str,
    ) -> Result<bool, VaultError> {
        self.rt
            .block_on(self.inner.verify(name, input, signature))
    }

    pub fn hash(&self, input: &[u8], algorithm: &str) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.hash(input, algorithm))
    }

    pub fn hmac(
        &self,
        name: &str,
        input: &[u8],
        algorithm: &str,
    ) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.hmac(name, input, algorithm))
    }

    pub fn random(&self, num_bytes: u32, format: &str) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.random(num_bytes, format))
    }

    pub fn generate_data_key(
        &self,
        name: &str,
        key_type: &str,
    ) -> Result<TransitDataKey, VaultError> {
        self.rt
            .block_on(self.inner.generate_data_key(name, key_type))
    }

    pub fn trim_key(&self, name: &str, min_version: u64) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.trim_key(name, min_version))
    }

    pub fn backup_key(&self, name: &str) -> Result<SecretString, VaultError> {
        self.rt.block_on(self.inner.backup_key(name))
    }

    pub fn restore_key(&self, name: &str, backup: &SecretString) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.restore_key(name, backup))
    }

    pub fn read_cache_config(&self) -> Result<TransitCacheConfig, VaultError> {
        self.rt.block_on(self.inner.read_cache_config())
    }

    pub fn write_cache_config(&self, size: u64) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_cache_config(size))
    }
}

// ---------------------------------------------------------------------------
// PKI
// ---------------------------------------------------------------------------

pub struct PkiHandler<'a> {
    inner: crate::api::pki::PkiHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl PkiHandler<'_> {
    pub fn generate_root(&self, params: &PkiRootParams) -> Result<PkiCertificate, VaultError> {
        self.rt.block_on(self.inner.generate_root(params))
    }

    pub fn generate_intermediate_csr(
        &self,
        params: &PkiIntermediateParams,
    ) -> Result<PkiCsr, VaultError> {
        self.rt
            .block_on(self.inner.generate_intermediate_csr(params))
    }

    pub fn set_signed_intermediate(
        &self,
        certificate: &str,
    ) -> Result<PkiImportResult, VaultError> {
        self.rt
            .block_on(self.inner.set_signed_intermediate(certificate))
    }

    pub fn delete_root(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_root())
    }

    pub fn list_issuers(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_issuers())
    }

    pub fn read_issuer(&self, issuer_ref: &str) -> Result<PkiIssuerInfo, VaultError> {
        self.rt.block_on(self.inner.read_issuer(issuer_ref))
    }

    pub fn delete_issuer(&self, issuer_ref: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_issuer(issuer_ref))
    }

    pub fn create_role(&self, name: &str, params: &PkiRoleParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<PkiRole, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn issue(&self, role: &str, params: &PkiIssueParams) -> Result<PkiIssuedCert, VaultError> {
        self.rt.block_on(self.inner.issue(role, params))
    }

    pub fn sign(&self, role: &str, params: &PkiSignParams) -> Result<PkiSignedCert, VaultError> {
        self.rt.block_on(self.inner.sign(role, params))
    }

    pub fn sign_verbatim(&self, role: &str, csr: &str) -> Result<PkiSignedCert, VaultError> {
        self.rt.block_on(self.inner.sign_verbatim(role, csr))
    }

    pub fn list_certs(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_certs())
    }

    pub fn read_cert(&self, serial: &str) -> Result<PkiCertificateEntry, VaultError> {
        self.rt.block_on(self.inner.read_cert(serial))
    }

    pub fn set_urls(&self, config: &PkiUrlsConfig) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.set_urls(config))
    }

    pub fn read_urls(&self) -> Result<PkiUrlsConfig, VaultError> {
        self.rt.block_on(self.inner.read_urls())
    }

    pub fn revoke(&self, serial: &str) -> Result<PkiRevocationInfo, VaultError> {
        self.rt.block_on(self.inner.revoke(serial))
    }

    pub fn revoke_with_key(
        &self,
        serial: &str,
        private_key: &SecretString,
    ) -> Result<PkiRevocationInfo, VaultError> {
        self.rt
            .block_on(self.inner.revoke_with_key(serial, private_key))
    }

    pub fn rotate_crl(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rotate_crl())
    }

    pub fn tidy(&self, params: &PkiTidyParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.tidy(params))
    }

    pub fn tidy_status(&self) -> Result<PkiTidyStatus, VaultError> {
        self.rt.block_on(self.inner.tidy_status())
    }
}

// ---------------------------------------------------------------------------
// Sys
// ---------------------------------------------------------------------------

pub struct SysHandler<'a> {
    inner: crate::api::sys::SysHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl SysHandler<'_> {
    pub fn health(&self) -> Result<HealthResponse, VaultError> {
        self.rt.block_on(self.inner.health())
    }

    pub fn leader(&self) -> Result<LeaderResponse, VaultError> {
        self.rt.block_on(self.inner.leader())
    }

    pub fn seal_status(&self) -> Result<SealStatus, VaultError> {
        self.rt.block_on(self.inner.seal_status())
    }

    pub fn seal(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.seal())
    }

    pub fn unseal(&self, key: &SecretString) -> Result<SealStatus, VaultError> {
        self.rt.block_on(self.inner.unseal(key))
    }

    pub fn init(&self, params: &InitParams) -> Result<InitResponse, VaultError> {
        self.rt.block_on(self.inner.init(params))
    }

    pub fn step_down(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.step_down())
    }

    pub fn list_mounts(&self) -> Result<HashMap<String, MountInfo>, VaultError> {
        self.rt.block_on(self.inner.list_mounts())
    }

    pub fn mount(&self, path: &str, params: &MountParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.mount(path, params))
    }

    pub fn unmount(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.unmount(path))
    }

    pub fn tune_mount(&self, path: &str, params: &MountTuneParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.tune_mount(path, params))
    }

    pub fn read_mount_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.rt.block_on(self.inner.read_mount_tune(path))
    }

    pub fn list_auth_mounts(&self) -> Result<HashMap<String, AuthMountInfo>, VaultError> {
        self.rt.block_on(self.inner.list_auth_mounts())
    }

    pub fn enable_auth(&self, path: &str, params: &AuthMountParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.enable_auth(path, params))
    }

    pub fn disable_auth(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.disable_auth(path))
    }

    pub fn read_auth_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.rt.block_on(self.inner.read_auth_tune(path))
    }

    pub fn list_policies(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_policies())
    }

    pub fn read_policy(&self, name: &str) -> Result<PolicyInfo, VaultError> {
        self.rt.block_on(self.inner.read_policy(name))
    }

    pub fn write_policy(&self, name: &str, rules: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_policy(name, rules))
    }

    pub fn delete_policy(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_policy(name))
    }

    pub fn read_lease(&self, lease_id: &str) -> Result<LeaseInfo, VaultError> {
        self.rt.block_on(self.inner.read_lease(lease_id))
    }

    pub fn renew_lease(
        &self,
        lease_id: &str,
        increment: Option<&str>,
    ) -> Result<LeaseRenewal, VaultError> {
        self.rt
            .block_on(self.inner.renew_lease(lease_id, increment))
    }

    pub fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.revoke_lease(lease_id))
    }

    pub fn revoke_prefix(&self, prefix: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.revoke_prefix(prefix))
    }

    pub fn list_audit_devices(&self) -> Result<HashMap<String, AuditDevice>, VaultError> {
        self.rt.block_on(self.inner.list_audit_devices())
    }

    pub fn enable_audit(&self, path: &str, params: &AuditParams) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.enable_audit(path, params))
    }

    pub fn disable_audit(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.disable_audit(path))
    }

    pub fn unwrap<T: DeserializeOwned>(&self, token: &SecretString) -> Result<T, VaultError> {
        self.rt.block_on(self.inner.unwrap(token))
    }

    pub fn wrap_lookup(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        self.rt.block_on(self.inner.wrap_lookup(token))
    }

    pub fn capabilities(
        &self,
        token: &SecretString,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        self.rt.block_on(self.inner.capabilities(token, paths))
    }

    pub fn capabilities_self(
        &self,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        self.rt.block_on(self.inner.capabilities_self(paths))
    }

    pub fn key_status(&self) -> Result<KeyStatus, VaultError> {
        self.rt.block_on(self.inner.key_status())
    }

    pub fn rotate_encryption_key(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rotate_encryption_key())
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

pub struct AuthHandler<'a> {
    inner: crate::api::auth::AuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl<'a> AuthHandler<'a> {
    pub fn token(&self) -> TokenAuthHandler<'a> {
        TokenAuthHandler {
            inner: self.inner.token(),
            rt: self.rt,
        }
    }

    pub fn approle(&self) -> AppRoleAuthHandler<'a> {
        AppRoleAuthHandler {
            inner: self.inner.approle(),
            rt: self.rt,
        }
    }

    pub fn approle_at(&self, mount: &str) -> AppRoleAuthHandler<'a> {
        AppRoleAuthHandler {
            inner: self.inner.approle_at(mount),
            rt: self.rt,
        }
    }

    pub fn kubernetes(&self) -> K8sAuthHandler<'a> {
        K8sAuthHandler {
            inner: self.inner.kubernetes(),
            rt: self.rt,
        }
    }

    pub fn kubernetes_at(&self, mount: &str) -> K8sAuthHandler<'a> {
        K8sAuthHandler {
            inner: self.inner.kubernetes_at(mount),
            rt: self.rt,
        }
    }
}

pub struct TokenAuthHandler<'a> {
    inner: crate::api::auth::token::TokenAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl TokenAuthHandler<'_> {
    pub fn lookup_self(&self) -> Result<TokenLookupResponse, VaultError> {
        self.rt.block_on(self.inner.lookup_self())
    }

    pub fn lookup(&self, token: &SecretString) -> Result<TokenLookupResponse, VaultError> {
        self.rt.block_on(self.inner.lookup(token))
    }

    pub fn renew_self(&self, increment: Option<&str>) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.renew_self(increment))
    }

    pub fn create(&self, params: &TokenCreateRequest) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.create(params))
    }

    pub fn create_orphan(&self, params: &TokenCreateRequest) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.create_orphan(params))
    }

    pub fn revoke(&self, token: &SecretString) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.revoke(token))
    }

    pub fn revoke_self(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.revoke_self())
    }

    pub fn revoke_accessor(&self, accessor: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.revoke_accessor(accessor))
    }

    pub fn list_accessors(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_accessors())
    }
}

pub struct AppRoleAuthHandler<'a> {
    inner: crate::api::auth::approle::AppRoleAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl AppRoleAuthHandler<'_> {
    pub fn login(&self, role_id: &str, secret_id: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(role_id, secret_id))
    }

    pub fn create_role(&self, name: &str, params: &AppRoleCreateRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<AppRoleInfo, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }

    pub fn read_role_id(&self, name: &str) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.read_role_id(name))
    }

    pub fn generate_secret_id(&self, name: &str) -> Result<AppRoleSecretIdResponse, VaultError> {
        self.rt.block_on(self.inner.generate_secret_id(name))
    }

    pub fn destroy_secret_id(
        &self,
        name: &str,
        secret_id: &SecretString,
    ) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.destroy_secret_id(name, secret_id))
    }
}

pub struct K8sAuthHandler<'a> {
    inner: crate::api::auth::kubernetes::K8sAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl K8sAuthHandler<'_> {
    pub fn login(&self, role: &str, jwt: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(role, jwt))
    }

    pub fn configure(&self, config: &K8sAuthConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure(config))
    }

    pub fn create_role(&self, name: &str, params: &K8sAuthRoleRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<K8sAuthRoleInfo, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }
}
