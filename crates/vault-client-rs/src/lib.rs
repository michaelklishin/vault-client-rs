//! Async and blocking Rust client for the [HashiCorp Vault](https://www.vaultproject.io/) HTTP API
//!
//! ```rust,no_run
//! use vault_client_rs::{VaultClient, Kv2Operations};
//!
//! # async fn example() -> Result<(), vault_client_rs::VaultError> {
//! let client = VaultClient::new("https://vault.example.com:8200", "hvs.EXAMPLE")?;
//!
//! // KV v2: read secret data directly
//! let secret: std::collections::HashMap<String, String> =
//!     client.kv2("secret").read_data("my/path").await?;
//!
//! // Sys
//! let health = client.sys().health().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `blocking` | Enables [`blocking::BlockingVaultClient`] |
//! | `auto-renew` | Enables [`RenewalDaemon`] and [`LeaseWatcher`] for background token/lease lifecycle |

pub mod api;
pub(crate) mod circuit_breaker;
pub mod client;
pub mod types;

#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(feature = "auto-renew")]
pub mod renewal;

pub use circuit_breaker::CircuitBreakerConfig;
pub use client::{ClientBuilder, VaultClient, encode_path};
pub use types::error::VaultError;
pub use types::redaction::{RedactionLevel, redact, redaction_level, set_redaction_level};

#[cfg(feature = "auto-renew")]
pub use renewal::{LeaseEvent, LeaseWatcher, RenewalDaemon};

// Handler types (returned by VaultClient accessor methods)
pub use api::auth::approle::AppRoleAuthHandler;
pub use api::auth::aws::AwsAuthHandler;
pub use api::auth::azure::AzureAuthHandler;
pub use api::auth::cert::CertAuthHandler;
pub use api::auth::gcp::GcpAuthHandler;
pub use api::auth::github::GithubAuthHandler;
pub use api::auth::kerberos::KerberosAuthHandler;
pub use api::auth::kubernetes::K8sAuthHandler;
pub use api::auth::ldap::LdapAuthHandler;
pub use api::auth::oidc::OidcAuthHandler;
pub use api::auth::radius::RadiusAuthHandler;
pub use api::auth::token::TokenAuthHandler;
pub use api::auth::userpass::UserpassAuthHandler;
pub use api::auth::{
    AppRoleLogin, AuthHandler, AuthMethod, AwsLogin, AzureLogin, GcpLogin, GithubLogin, JwtLogin,
    K8sLogin, LdapLogin, UserpassLogin,
};
pub use api::aws::AwsSecretsHandler;
pub use api::azure::AzureHandler;
pub use api::consul::ConsulHandler;
pub use api::cubbyhole::CubbyholeHandler;
pub use api::database::DatabaseHandler;
pub use api::gcp::GcpHandler;
pub use api::identity::IdentityHandler;
pub use api::kv1::Kv1Handler;
pub use api::kv2::Kv2Handler;
pub use api::nomad::NomadHandler;
pub use api::pki::PkiHandler;
pub use api::rabbitmq::RabbitmqHandler;
pub use api::ssh::SshHandler;
pub use api::sys::SysHandler;
pub use api::terraform::TerraformCloudHandler;
pub use api::totp::TotpHandler;
pub use api::transit::TransitHandler;

// Mockability traits
pub use api::traits::{
    AppRoleAuthOperations, AwsAuthOperations, AwsSecretsOperations, AzureAuthOperations,
    AzureSecretsOperations, CertAuthOperations, ConsulOperations, CubbyholeOperations,
    DatabaseOperations, GcpAuthOperations, GcpSecretsOperations, GithubAuthOperations,
    IdentityOperations, K8sAuthOperations, KerberosAuthOperations, Kv1Operations, Kv2Operations,
    LdapAuthOperations, NomadOperations, OidcAuthOperations, PkiOperations, RabbitmqOperations,
    RadiusAuthOperations, SshOperations, SysOperations, TerraformCloudOperations,
    TokenAuthOperations, TotpOperations, TransitOperations, UserpassAuthOperations,
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
    K8sAuthRoleInfo, K8sAuthRoleRequest, KerberosConfig, KerberosConfigRequest, KerberosGroup,
    KerberosGroupRequest, KerberosLdapConfig, KerberosLdapConfigRequest, LdapConfig,
    LdapConfigRequest, LdapGroup, LdapGroupRequest, LdapUser, LdapUserRequest, OidcConfig,
    OidcConfigRequest, OidcRoleInfo, OidcRoleRequest, RadiusConfig, RadiusConfigRequest,
    RadiusUser, RadiusUserRequest, TokenCreateRequest, TokenLookupResponse, UserpassUserInfo,
    UserpassUserRequest,
};

// Sys types
pub use types::sys::{
    AuditDevice, AuditParams, AuthMountInfo, AuthMountParams, AutopilotServerState, AutopilotState,
    GenerateRootInitRequest, GenerateRootStatus, HealthResponse, HostInfo, InFlightRequest,
    InitParams, InitResponse, KeyStatus, LeaderResponse, LeaseInfo, LeaseRenewal, MountConfig,
    MountInfo, MountParams, MountTuneParams, NamespaceInfo, PluginInfo, PolicyInfo, RaftConfig,
    RaftServer, RateLimitQuota, RateLimitQuotaRequest, RegisterPluginRequest, RekeyInitRequest,
    RekeyStatus, RemountStatus, SealStatus, VersionHistoryEntry,
};

// AWS types
pub use types::aws::{
    AwsAuthConfig, AwsAuthConfigRequest, AwsAuthLoginRequest, AwsAuthRoleInfo, AwsAuthRoleRequest,
    AwsConfigRoot, AwsConfigRootRequest, AwsCredentials, AwsRole, AwsRoleRequest, AwsStsRequest,
};

// Azure types
pub use types::azure::{
    AzureAuthConfig, AzureAuthConfigRequest, AzureAuthLoginRequest, AzureAuthRoleInfo,
    AzureAuthRoleRequest, AzureConfig, AzureConfigRequest, AzureCredentials, AzureRole,
    AzureRoleRequest,
};

// GCP types
pub use types::gcp::{
    GcpAuthConfig, GcpAuthConfigRequest, GcpAuthRoleInfo, GcpAuthRoleRequest, GcpConfig,
    GcpConfigRequest, GcpOAuthToken, GcpRoleset, GcpRolesetRequest, GcpServiceAccountKey,
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
    GroupAlias, GroupAliasCreateRequest, GroupAliasResponse, GroupCreateRequest,
};

// TOTP types
pub use types::totp::{
    TotpCode, TotpGenerateResponse, TotpKeyInfo, TotpKeyRequest, TotpValidation,
};

// Consul types
pub use types::consul::{
    ConsulConfig, ConsulConfigRequest, ConsulCredentials, ConsulRole, ConsulRoleRequest,
};

// Nomad types
pub use types::nomad::{
    NomadConfig, NomadConfigRequest, NomadCredentials, NomadRole, NomadRoleRequest,
};

// RabbitMQ types
pub use types::rabbitmq::{
    RabbitmqConfigRequest, RabbitmqCredentials, RabbitmqRole, RabbitmqRoleRequest,
};

// Terraform Cloud types
pub use types::terraform::{
    TerraformCloudConfig, TerraformCloudConfigRequest, TerraformCloudRole,
    TerraformCloudRoleRequest, TerraformCloudToken,
};
