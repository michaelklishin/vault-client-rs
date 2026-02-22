pub mod api;
pub mod client;
pub mod types;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use client::{ClientBuilder, VaultClient};
pub use types::error::VaultError;

// Handler types (returned by VaultClient accessor methods)
pub use api::auth::approle::AppRoleAuthHandler;
pub use api::auth::kubernetes::K8sAuthHandler;
pub use api::auth::token::TokenAuthHandler;
pub use api::auth::{AppRoleLogin, AuthHandler, AuthMethod, K8sLogin};
pub use api::kv1::Kv1Handler;
pub use api::kv2::Kv2Handler;
pub use api::pki::PkiHandler;
pub use api::sys::SysHandler;
pub use api::transit::TransitHandler;

// Mockability traits
pub use api::traits::{
    AppRoleAuthOperations, K8sAuthOperations, Kv1Operations, Kv2Operations, PkiOperations,
    SysOperations, TokenAuthOperations, TransitOperations,
};

pub use types::kv::{
    KvConfig, KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse, KvVersionMetadata,
};
pub use types::response::{AuthInfo, VaultResponse, WrapInfo};
pub use types::secret::{MountPath, SecretPath, SecretString};

// Transit types
pub use types::transit::{
    TransitBatchCiphertext, TransitBatchDecryptItem, TransitBatchPlaintext, TransitCacheConfig,
    TransitDataKey, TransitExportedKey, TransitKeyConfig, TransitKeyInfo, TransitKeyParams,
    TransitSignParams,
};

// PKI types
pub use types::pki::{
    PkiCertificate, PkiCertificateEntry, PkiCsr, PkiImportResult, PkiIntermediateParams,
    PkiIssuedCert, PkiIssueParams, PkiIssuerInfo, PkiRevocationInfo, PkiRole, PkiRoleParams,
    PkiRootParams, PkiSignParams, PkiSignedCert, PkiTidyParams, PkiTidyStatus, PkiUrlsConfig,
};

// Auth types
pub use types::auth::{
    AppRoleCreateRequest, AppRoleInfo, AppRoleSecretIdResponse, K8sAuthConfigRequest,
    K8sAuthRoleInfo, K8sAuthRoleRequest, TokenCreateRequest, TokenLookupResponse,
};

// Sys types
pub use types::sys::{
    AuditDevice, AuditParams, AuthMountInfo, AuthMountParams, HealthResponse, InitParams,
    InitResponse, KeyStatus, LeaderResponse, LeaseInfo, LeaseRenewal, MountConfig, MountInfo,
    MountParams, MountTuneParams, PolicyInfo, SealStatus,
};
