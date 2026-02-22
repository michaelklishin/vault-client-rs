use std::collections::HashMap;

use secrecy::SecretString;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::api::traits::{
    AppRoleAuthOperations, CertAuthOperations, DatabaseOperations, GithubAuthOperations,
    IdentityOperations, K8sAuthOperations, Kv1Operations, Kv2Operations, LdapAuthOperations,
    OidcAuthOperations, PkiOperations, SshOperations, TokenAuthOperations, TransitOperations,
    UserpassAuthOperations,
};
use crate::client::blocking_client::BlockingVaultClient;
use crate::types::auth::*;
use crate::types::database::*;
use crate::types::error::VaultError;
use crate::types::identity::*;
use crate::types::kv::*;
use crate::types::pki::*;
use crate::types::response::{AuthInfo, WrapInfo};
use crate::types::ssh::*;
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

    pub fn database(&self, mount: &str) -> DatabaseHandler<'_> {
        DatabaseHandler {
            inner: self.inner.database(mount),
            rt: &self.rt,
        }
    }

    pub fn ssh(&self, mount: &str) -> SshHandler<'_> {
        SshHandler {
            inner: self.inner.ssh(mount),
            rt: &self.rt,
        }
    }

    pub fn identity(&self) -> IdentityHandler<'_> {
        IdentityHandler {
            inner: self.inner.identity(),
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
    pub fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T, VaultError> {
        self.rt.block_on(self.inner.read(path))
    }

    pub fn read_raw(
        &self,
        path: &str,
    ) -> Result<crate::types::response::VaultResponse<serde_json::Value>, VaultError> {
        self.rt.block_on(self.inner.read_raw(path))
    }

    pub fn write<T: DeserializeOwned>(
        &self,
        path: &str,
        data: &impl Serialize,
    ) -> Result<crate::types::response::VaultResponse<T>, VaultError> {
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

    pub fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> Result<KvReadResponse<T>, VaultError> {
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

    pub fn update_key_config(&self, name: &str, cfg: &TransitKeyConfig) -> Result<(), VaultError> {
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

    pub fn verify(&self, name: &str, input: &[u8], signature: &str) -> Result<bool, VaultError> {
        self.rt.block_on(self.inner.verify(name, input, signature))
    }

    pub fn batch_sign(
        &self,
        name: &str,
        items: &[TransitBatchSignInput],
        params: &TransitSignParams,
    ) -> Result<Vec<TransitBatchSignResult>, VaultError> {
        self.rt.block_on(self.inner.batch_sign(name, items, params))
    }

    pub fn batch_verify(
        &self,
        name: &str,
        items: &[TransitBatchVerifyInput],
    ) -> Result<Vec<TransitBatchVerifyResult>, VaultError> {
        self.rt.block_on(self.inner.batch_verify(name, items))
    }

    pub fn hash(&self, input: &[u8], algorithm: &str) -> Result<String, VaultError> {
        self.rt.block_on(self.inner.hash(input, algorithm))
    }

    pub fn hmac(&self, name: &str, input: &[u8], algorithm: &str) -> Result<String, VaultError> {
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

    pub fn update_issuer(
        &self,
        issuer_ref: &str,
        params: &PkiIssuerUpdateParams,
    ) -> Result<PkiIssuerInfo, VaultError> {
        self.rt
            .block_on(self.inner.update_issuer(issuer_ref, params))
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

    pub fn cross_sign_intermediate(
        &self,
        params: &PkiCrossSignRequest,
    ) -> Result<PkiCertificate, VaultError> {
        self.rt.block_on(self.inner.cross_sign_intermediate(params))
    }

    pub fn read_acme_config(&self) -> Result<PkiAcmeConfig, VaultError> {
        self.rt.block_on(self.inner.read_acme_config())
    }

    pub fn write_acme_config(&self, config: &PkiAcmeConfig) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_acme_config(config))
    }

    pub fn rotate_delta_crl(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rotate_delta_crl())
    }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

pub struct DatabaseHandler<'a> {
    inner: crate::api::database::DatabaseHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl DatabaseHandler<'_> {
    pub fn configure(&self, name: &str, params: &DatabaseConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure(name, params))
    }

    pub fn read_config(&self, name: &str) -> Result<DatabaseConfig, VaultError> {
        self.rt.block_on(self.inner.read_config(name))
    }

    pub fn delete_config(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_config(name))
    }

    pub fn list_connections(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_connections())
    }

    pub fn reset_connection(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.reset_connection(name))
    }

    pub fn create_role(&self, name: &str, params: &DatabaseRoleRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<DatabaseRole, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }

    pub fn get_credentials(&self, role: &str) -> Result<DatabaseCredentials, VaultError> {
        self.rt.block_on(self.inner.get_credentials(role))
    }

    pub fn create_static_role(
        &self,
        name: &str,
        params: &DatabaseStaticRoleRequest,
    ) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.create_static_role(name, params))
    }

    pub fn read_static_role(&self, name: &str) -> Result<DatabaseStaticRole, VaultError> {
        self.rt.block_on(self.inner.read_static_role(name))
    }

    pub fn delete_static_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_static_role(name))
    }

    pub fn list_static_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_static_roles())
    }

    pub fn get_static_credentials(
        &self,
        name: &str,
    ) -> Result<DatabaseStaticCredentials, VaultError> {
        self.rt.block_on(self.inner.get_static_credentials(name))
    }

    pub fn rotate_static_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rotate_static_role(name))
    }
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

pub struct SshHandler<'a> {
    inner: crate::api::ssh::SshHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl SshHandler<'_> {
    pub fn configure_ca(&self, params: &SshCaConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure_ca(params))
    }

    pub fn read_public_key(&self) -> Result<SshCaPublicKey, VaultError> {
        self.rt.block_on(self.inner.read_public_key())
    }

    pub fn delete_ca(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_ca())
    }

    pub fn create_role(&self, name: &str, params: &SshRoleRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<SshRole, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }

    pub fn sign_key(
        &self,
        role: &str,
        params: &SshSignRequest,
    ) -> Result<SshSignedKey, VaultError> {
        self.rt.block_on(self.inner.sign_key(role, params))
    }

    pub fn verify_otp(&self, params: &SshVerifyRequest) -> Result<SshVerifyResponse, VaultError> {
        self.rt.block_on(self.inner.verify_otp(params))
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

pub struct IdentityHandler<'a> {
    inner: crate::api::identity::IdentityHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl IdentityHandler<'_> {
    pub fn create_entity(&self, params: &EntityCreateRequest) -> Result<Entity, VaultError> {
        self.rt.block_on(self.inner.create_entity(params))
    }

    pub fn read_entity(&self, id: &str) -> Result<Entity, VaultError> {
        self.rt.block_on(self.inner.read_entity(id))
    }

    pub fn read_entity_by_name(&self, name: &str) -> Result<Entity, VaultError> {
        self.rt.block_on(self.inner.read_entity_by_name(name))
    }

    pub fn update_entity(&self, id: &str, params: &EntityCreateRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.update_entity(id, params))
    }

    pub fn delete_entity(&self, id: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_entity(id))
    }

    pub fn list_entities(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_entities())
    }

    pub fn create_entity_alias(
        &self,
        params: &EntityAliasCreateRequest,
    ) -> Result<EntityAliasResponse, VaultError> {
        self.rt.block_on(self.inner.create_entity_alias(params))
    }

    pub fn read_entity_alias(&self, id: &str) -> Result<EntityAliasResponse, VaultError> {
        self.rt.block_on(self.inner.read_entity_alias(id))
    }

    pub fn delete_entity_alias(&self, id: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_entity_alias(id))
    }

    pub fn list_entity_aliases(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_entity_aliases())
    }

    pub fn create_group(&self, params: &GroupCreateRequest) -> Result<Group, VaultError> {
        self.rt.block_on(self.inner.create_group(params))
    }

    pub fn read_group(&self, id: &str) -> Result<Group, VaultError> {
        self.rt.block_on(self.inner.read_group(id))
    }

    pub fn read_group_by_name(&self, name: &str) -> Result<Group, VaultError> {
        self.rt.block_on(self.inner.read_group_by_name(name))
    }

    pub fn update_group(&self, id: &str, params: &GroupCreateRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.update_group(id, params))
    }

    pub fn delete_group(&self, id: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_group(id))
    }

    pub fn list_groups(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_groups())
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

    // --- New sys methods ---

    pub fn list_plugins(&self, plugin_type: &str) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_plugins(plugin_type))
    }

    pub fn read_plugin(&self, plugin_type: &str, name: &str) -> Result<PluginInfo, VaultError> {
        self.rt.block_on(self.inner.read_plugin(plugin_type, name))
    }

    pub fn register_plugin(&self, params: &RegisterPluginRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.register_plugin(params))
    }

    pub fn deregister_plugin(&self, plugin_type: &str, name: &str) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.deregister_plugin(plugin_type, name))
    }

    pub fn reload_plugin(&self, plugin: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.reload_plugin(plugin))
    }

    pub fn raft_config(&self) -> Result<RaftConfig, VaultError> {
        self.rt.block_on(self.inner.raft_config())
    }

    pub fn raft_autopilot_state(&self) -> Result<AutopilotState, VaultError> {
        self.rt.block_on(self.inner.raft_autopilot_state())
    }

    pub fn raft_remove_peer(&self, server_id: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.raft_remove_peer(server_id))
    }

    pub fn list_namespaces(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_namespaces())
    }

    pub fn create_namespace(&self, path: &str) -> Result<NamespaceInfo, VaultError> {
        self.rt.block_on(self.inner.create_namespace(path))
    }

    pub fn delete_namespace(&self, path: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_namespace(path))
    }

    pub fn list_rate_limit_quotas(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_rate_limit_quotas())
    }

    pub fn read_rate_limit_quota(&self, name: &str) -> Result<RateLimitQuota, VaultError> {
        self.rt.block_on(self.inner.read_rate_limit_quota(name))
    }

    pub fn write_rate_limit_quota(
        &self,
        name: &str,
        params: &RateLimitQuotaRequest,
    ) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.write_rate_limit_quota(name, params))
    }

    pub fn delete_rate_limit_quota(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_rate_limit_quota(name))
    }

    pub fn rekey_init(&self, params: &RekeyInitRequest) -> Result<RekeyStatus, VaultError> {
        self.rt.block_on(self.inner.rekey_init(params))
    }

    pub fn rekey_status(&self) -> Result<RekeyStatus, VaultError> {
        self.rt.block_on(self.inner.rekey_status())
    }

    pub fn rekey_cancel(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.rekey_cancel())
    }

    pub fn rekey_update(&self, key: &SecretString, nonce: &str) -> Result<RekeyStatus, VaultError> {
        self.rt.block_on(self.inner.rekey_update(key, nonce))
    }

    pub fn generate_root_init(
        &self,
        params: &GenerateRootInitRequest,
    ) -> Result<GenerateRootStatus, VaultError> {
        self.rt.block_on(self.inner.generate_root_init(params))
    }

    pub fn generate_root_status(&self) -> Result<GenerateRootStatus, VaultError> {
        self.rt.block_on(self.inner.generate_root_status())
    }

    pub fn generate_root_cancel(&self) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.generate_root_cancel())
    }

    pub fn generate_root_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> Result<GenerateRootStatus, VaultError> {
        self.rt
            .block_on(self.inner.generate_root_update(key, nonce))
    }

    pub fn remount(&self, from: &str, to: &str) -> Result<RemountStatus, VaultError> {
        self.rt.block_on(self.inner.remount(from, to))
    }

    pub fn metrics_json(&self) -> Result<serde_json::Value, VaultError> {
        self.rt.block_on(self.inner.metrics_json())
    }

    pub fn host_info(&self) -> Result<HostInfo, VaultError> {
        self.rt.block_on(self.inner.host_info())
    }

    pub fn internal_counters_activity(&self) -> Result<serde_json::Value, VaultError> {
        self.rt.block_on(self.inner.internal_counters_activity())
    }

    pub fn version_history(&self) -> Result<Vec<VersionHistoryEntry>, VaultError> {
        self.rt.block_on(self.inner.version_history())
    }

    pub fn rewrap(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        self.rt.block_on(self.inner.rewrap(token))
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

    pub fn userpass(&self) -> UserpassAuthHandler<'a> {
        UserpassAuthHandler {
            inner: self.inner.userpass(),
            rt: self.rt,
        }
    }

    pub fn userpass_at(&self, mount: &str) -> UserpassAuthHandler<'a> {
        UserpassAuthHandler {
            inner: self.inner.userpass_at(mount),
            rt: self.rt,
        }
    }

    pub fn ldap(&self) -> LdapAuthHandler<'a> {
        LdapAuthHandler {
            inner: self.inner.ldap(),
            rt: self.rt,
        }
    }

    pub fn ldap_at(&self, mount: &str) -> LdapAuthHandler<'a> {
        LdapAuthHandler {
            inner: self.inner.ldap_at(mount),
            rt: self.rt,
        }
    }

    pub fn cert(&self) -> CertAuthHandler<'a> {
        CertAuthHandler {
            inner: self.inner.cert(),
            rt: self.rt,
        }
    }

    pub fn cert_at(&self, mount: &str) -> CertAuthHandler<'a> {
        CertAuthHandler {
            inner: self.inner.cert_at(mount),
            rt: self.rt,
        }
    }

    pub fn github(&self) -> GithubAuthHandler<'a> {
        GithubAuthHandler {
            inner: self.inner.github(),
            rt: self.rt,
        }
    }

    pub fn github_at(&self, mount: &str) -> GithubAuthHandler<'a> {
        GithubAuthHandler {
            inner: self.inner.github_at(mount),
            rt: self.rt,
        }
    }

    pub fn oidc(&self) -> OidcAuthHandler<'a> {
        OidcAuthHandler {
            inner: self.inner.oidc(),
            rt: self.rt,
        }
    }

    pub fn oidc_at(&self, mount: &str) -> OidcAuthHandler<'a> {
        OidcAuthHandler {
            inner: self.inner.oidc_at(mount),
            rt: self.rt,
        }
    }

    pub fn jwt(&self) -> OidcAuthHandler<'a> {
        self.oidc_at("jwt")
    }

    pub fn jwt_at(&self, mount: &str) -> OidcAuthHandler<'a> {
        self.oidc_at(mount)
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

pub struct UserpassAuthHandler<'a> {
    inner: crate::api::auth::userpass::UserpassAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl UserpassAuthHandler<'_> {
    pub fn login(&self, username: &str, password: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(username, password))
    }

    pub fn create_user(
        &self,
        username: &str,
        params: &UserpassUserRequest,
    ) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_user(username, params))
    }

    pub fn read_user(&self, username: &str) -> Result<UserpassUserInfo, VaultError> {
        self.rt.block_on(self.inner.read_user(username))
    }

    pub fn delete_user(&self, username: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_user(username))
    }

    pub fn list_users(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_users())
    }

    pub fn update_password(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<(), VaultError> {
        self.rt
            .block_on(self.inner.update_password(username, password))
    }
}

pub struct LdapAuthHandler<'a> {
    inner: crate::api::auth::ldap::LdapAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl LdapAuthHandler<'_> {
    pub fn login(&self, username: &str, password: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(username, password))
    }

    pub fn configure(&self, config: &LdapConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure(config))
    }

    pub fn read_config(&self) -> Result<LdapConfig, VaultError> {
        self.rt.block_on(self.inner.read_config())
    }

    pub fn write_group(&self, name: &str, params: &LdapGroupRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_group(name, params))
    }

    pub fn read_group(&self, name: &str) -> Result<LdapGroup, VaultError> {
        self.rt.block_on(self.inner.read_group(name))
    }

    pub fn delete_group(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_group(name))
    }

    pub fn list_groups(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_groups())
    }

    pub fn write_user(&self, name: &str, params: &LdapUserRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.write_user(name, params))
    }

    pub fn read_user(&self, name: &str) -> Result<LdapUser, VaultError> {
        self.rt.block_on(self.inner.read_user(name))
    }

    pub fn delete_user(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_user(name))
    }

    pub fn list_users(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_users())
    }
}

pub struct CertAuthHandler<'a> {
    inner: crate::api::auth::cert::CertAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl CertAuthHandler<'_> {
    pub fn login(&self, name: Option<&str>) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(name))
    }

    pub fn create_role(&self, name: &str, params: &CertRoleRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<CertRoleInfo, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }
}

pub struct GithubAuthHandler<'a> {
    inner: crate::api::auth::github::GithubAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl GithubAuthHandler<'_> {
    pub fn login(&self, token: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login(token))
    }

    pub fn configure(&self, config: &GithubConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure(config))
    }

    pub fn read_config(&self) -> Result<GithubConfig, VaultError> {
        self.rt.block_on(self.inner.read_config())
    }

    pub fn map_team(&self, team: &str, params: &GithubTeamMapping) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.map_team(team, params))
    }

    pub fn read_team_mapping(&self, team: &str) -> Result<GithubTeamInfo, VaultError> {
        self.rt.block_on(self.inner.read_team_mapping(team))
    }

    pub fn list_teams(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_teams())
    }
}

pub struct OidcAuthHandler<'a> {
    inner: crate::api::auth::oidc::OidcAuthHandler<'a>,
    rt: &'a tokio::runtime::Runtime,
}

impl OidcAuthHandler<'_> {
    pub fn login_jwt(&self, role: &str, jwt: &SecretString) -> Result<AuthInfo, VaultError> {
        self.rt.block_on(self.inner.login_jwt(role, jwt))
    }

    pub fn configure(&self, config: &OidcConfigRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.configure(config))
    }

    pub fn read_config(&self) -> Result<OidcConfig, VaultError> {
        self.rt.block_on(self.inner.read_config())
    }

    pub fn create_role(&self, name: &str, params: &OidcRoleRequest) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.create_role(name, params))
    }

    pub fn read_role(&self, name: &str) -> Result<OidcRoleInfo, VaultError> {
        self.rt.block_on(self.inner.read_role(name))
    }

    pub fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.rt.block_on(self.inner.delete_role(name))
    }

    pub fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.rt.block_on(self.inner.list_roles())
    }
}
