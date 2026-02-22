pub mod api;
pub mod client;
pub mod types;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use client::{ClientBuilder, VaultClient};
pub use types::error::VaultError;

// Handler types (returned by VaultClient accessor methods)
pub use api::auth::approle::AppRoleAuthHandler;
pub use api::auth::cert::CertAuthHandler;
pub use api::auth::github::GithubAuthHandler;
pub use api::auth::kubernetes::K8sAuthHandler;
pub use api::auth::ldap::LdapAuthHandler;
pub use api::auth::oidc::OidcAuthHandler;
pub use api::auth::token::TokenAuthHandler;
pub use api::auth::userpass::UserpassAuthHandler;
pub use api::auth::{
    AppRoleLogin, AuthHandler, AuthMethod, GithubLogin, JwtLogin, K8sLogin, LdapLogin,
    UserpassLogin,
};
pub use api::database::DatabaseHandler;
pub use api::identity::IdentityHandler;
pub use api::kv1::Kv1Handler;
pub use api::kv2::Kv2Handler;
pub use api::pki::PkiHandler;
pub use api::ssh::SshHandler;
pub use api::sys::SysHandler;
pub use api::transit::TransitHandler;

// Mockability traits
pub use api::traits::{
    AppRoleAuthOperations, CertAuthOperations, DatabaseOperations, GithubAuthOperations,
    IdentityOperations, K8sAuthOperations, Kv1Operations, Kv2Operations, LdapAuthOperations,
    OidcAuthOperations, PkiOperations, SshOperations, SysOperations, TokenAuthOperations,
    TransitOperations, UserpassAuthOperations,
};

pub use types::kv::{
    KvConfig, KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse, KvVersionMetadata,
};
pub use types::response::{AuthInfo, VaultResponse, WrapInfo};
pub use types::secret::{MountPath, SecretPath, SecretString};

// Transit types
pub use types::transit::{
    TransitBatchCiphertext, TransitBatchDecryptItem, TransitBatchPlaintext, TransitBatchSignInput,
    TransitBatchSignResult, TransitBatchVerifyInput, TransitBatchVerifyResult, TransitCacheConfig,
    TransitDataKey, TransitExportedKey, TransitKeyConfig, TransitKeyInfo, TransitKeyParams,
    TransitSignParams,
};

// PKI types
pub use types::pki::{
    PkiAcmeConfig, PkiCertificate, PkiCertificateEntry, PkiCrossSignRequest, PkiCsr,
    PkiImportResult, PkiIntermediateParams, PkiIssueParams, PkiIssuedCert, PkiIssuerInfo,
    PkiIssuerUpdateParams, PkiRevocationInfo, PkiRole, PkiRoleParams, PkiRootParams, PkiSignParams,
    PkiSignedCert, PkiTidyParams, PkiTidyStatus, PkiUrlsConfig,
};

// Auth types
pub use types::auth::{
    AppRoleCreateRequest, AppRoleInfo, AppRoleSecretIdResponse, CertRoleInfo, CertRoleRequest,
    GithubConfig, GithubConfigRequest, GithubTeamInfo, GithubTeamMapping, K8sAuthConfigRequest,
    K8sAuthRoleInfo, K8sAuthRoleRequest, LdapConfig, LdapConfigRequest, LdapGroup,
    LdapGroupRequest, LdapUser, LdapUserRequest, OidcConfig, OidcConfigRequest, OidcRoleInfo,
    OidcRoleRequest, TokenCreateRequest, TokenLookupResponse, UserpassUserInfo,
    UserpassUserRequest,
};

// Sys types
pub use types::sys::{
    AuditDevice, AuditParams, AuthMountInfo, AuthMountParams, AutopilotServerState, AutopilotState,
    GenerateRootInitRequest, GenerateRootStatus, HealthResponse, HostInfo, InitParams,
    InitResponse, KeyStatus, LeaderResponse, LeaseInfo, LeaseRenewal, MountConfig, MountInfo,
    MountParams, MountTuneParams, NamespaceInfo, PluginInfo, PolicyInfo, RaftConfig, RaftServer,
    RateLimitQuota, RateLimitQuotaRequest, RegisterPluginRequest, RekeyInitRequest, RekeyStatus,
    RemountStatus, SealStatus, VersionHistoryEntry,
};

// Database types
pub use types::database::{
    DatabaseConfig, DatabaseConfigRequest, DatabaseCredentials, DatabaseRole, DatabaseRoleRequest,
    DatabaseStaticCredentials, DatabaseStaticRole, DatabaseStaticRoleRequest,
};

// SSH types
pub use types::ssh::{
    SshCaConfigRequest, SshCaPublicKey, SshRole, SshRoleRequest, SshSignRequest, SshSignedKey,
    SshVerifyRequest, SshVerifyResponse,
};

// Identity types
pub use types::identity::{
    Entity, EntityAlias, EntityAliasCreateRequest, EntityAliasResponse, EntityCreateRequest, Group,
    GroupAlias, GroupAliasCreateRequest, GroupCreateRequest,
};
