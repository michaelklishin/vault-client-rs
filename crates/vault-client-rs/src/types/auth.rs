use std::collections::HashMap;
use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

// --- Token auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct TokenCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_parent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_default_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_alias: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TokenLookupResponse {
    pub accessor: String,
    pub creation_time: u64,
    pub creation_ttl: u64,
    pub display_name: String,
    pub entity_id: String,
    pub expire_time: Option<String>,
    pub explicit_max_ttl: u64,
    pub id: SecretString,
    pub issue_time: String,
    #[zeroize(skip)]
    pub meta: Option<HashMap<String, String>>,
    pub num_uses: u64,
    pub orphan: bool,
    pub path: String,
    #[serde(default)]
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: u64,
    #[serde(rename = "type")]
    pub token_type: String,
}

impl Clone for TokenLookupResponse {
    fn clone(&self) -> Self {
        Self {
            accessor: self.accessor.clone(),
            creation_time: self.creation_time,
            creation_ttl: self.creation_ttl,
            display_name: self.display_name.clone(),
            entity_id: self.entity_id.clone(),
            expire_time: self.expire_time.clone(),
            explicit_max_ttl: self.explicit_max_ttl,
            id: self.id.clone(),
            issue_time: self.issue_time.clone(),
            meta: self.meta.clone(),
            num_uses: self.num_uses,
            orphan: self.orphan,
            path: self.path.clone(),
            policies: self.policies.clone(),
            renewable: self.renewable,
            ttl: self.ttl,
            token_type: self.token_type.clone(),
        }
    }
}

impl fmt::Debug for TokenLookupResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenLookupResponse")
            .field("accessor", &self.accessor)
            .field("creation_time", &self.creation_time)
            .field("creation_ttl", &self.creation_ttl)
            .field("display_name", &self.display_name)
            .field("entity_id", &self.entity_id)
            .field("expire_time", &self.expire_time)
            .field("explicit_max_ttl", &self.explicit_max_ttl)
            .field("id", &redact(self.id.expose_secret()))
            .field("issue_time", &self.issue_time)
            .field("meta", &self.meta)
            .field("num_uses", &self.num_uses)
            .field("orphan", &self.orphan)
            .field("path", &self.path)
            .field("policies", &self.policies)
            .field("renewable", &self.renewable)
            .field("ttl", &self.ttl)
            .field("token_type", &self.token_type)
            .finish()
    }
}

// --- AppRole auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct AppRoleCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_secret_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AppRoleInfo {
    pub bind_secret_id: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub secret_id_bound_cidrs: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub token_bound_cidrs: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    pub token_num_uses: u64,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AppRoleRoleIdResponse {
    pub role_id: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct AppRoleSecretIdResponse {
    pub secret_id: SecretString,
    pub secret_id_accessor: String,
    pub secret_id_num_uses: u64,
    pub secret_id_ttl: u64,
}

impl Clone for AppRoleSecretIdResponse {
    fn clone(&self) -> Self {
        Self {
            secret_id: self.secret_id.clone(),
            secret_id_accessor: self.secret_id_accessor.clone(),
            secret_id_num_uses: self.secret_id_num_uses,
            secret_id_ttl: self.secret_id_ttl,
        }
    }
}

impl fmt::Debug for AppRoleSecretIdResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppRoleSecretIdResponse")
            .field("secret_id", &redact(self.secret_id.expose_secret()))
            .field("secret_id_accessor", &self.secret_id_accessor)
            .field("secret_id_num_uses", &self.secret_id_num_uses)
            .field("secret_id_ttl", &self.secret_id_ttl)
            .finish()
    }
}

// --- Kubernetes auth ---

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct K8sAuthRoleInfo {
    #[serde(default)]
    pub bound_service_account_names: Vec<String>,
    #[serde(default)]
    pub bound_service_account_namespaces: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct K8sAuthConfigRequest {
    pub kubernetes_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes_ca_cert: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_reviewer_jwt: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_local_ca_jwt: Option<bool>,
}

impl Clone for K8sAuthConfigRequest {
    fn clone(&self) -> Self {
        Self {
            kubernetes_host: self.kubernetes_host.clone(),
            kubernetes_ca_cert: self.kubernetes_ca_cert.clone(),
            token_reviewer_jwt: self.token_reviewer_jwt.clone(),
            disable_local_ca_jwt: self.disable_local_ca_jwt,
        }
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct K8sAuthRoleRequest {
    pub bound_service_account_names: Vec<String>,
    pub bound_service_account_namespaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}

// --- Userpass auth ---

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct UserpassUserRequest {
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
}

impl Clone for UserpassUserRequest {
    fn clone(&self) -> Self {
        Self {
            password: self.password.clone(),
            token_policies: self.token_policies.clone(),
            token_ttl: self.token_ttl.clone(),
            token_max_ttl: self.token_max_ttl.clone(),
            token_bound_cidrs: self.token_bound_cidrs.clone(),
            token_num_uses: self.token_num_uses,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct UserpassUserInfo {
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_bound_cidrs: Vec<String>,
    pub token_num_uses: u64,
}

// --- LDAP auth ---

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct LdapConfigRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userattr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupattr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupfilter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binddn: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub bindpass: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}

impl Clone for LdapConfigRequest {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            userdn: self.userdn.clone(),
            userattr: self.userattr.clone(),
            groupdn: self.groupdn.clone(),
            groupattr: self.groupattr.clone(),
            groupfilter: self.groupfilter.clone(),
            binddn: self.binddn.clone(),
            bindpass: self.bindpass.clone(),
            starttls: self.starttls,
            insecure_tls: self.insecure_tls,
            certificate: self.certificate.clone(),
            token_policies: self.token_policies.clone(),
            token_ttl: self.token_ttl.clone(),
            token_max_ttl: self.token_max_ttl.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LdapConfig {
    pub url: String,
    pub userdn: String,
    pub userattr: String,
    pub groupdn: String,
    pub groupattr: String,
    pub groupfilter: String,
    pub starttls: bool,
    pub insecure_tls: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct LdapGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LdapGroup {
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct LdapUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct LdapUser {
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

// --- TLS Certificate auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct CertRoleRequest {
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_common_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_dns_sans: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_uri_sans: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_extensions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct CertRoleInfo {
    pub certificate: String,
    #[serde(default)]
    pub allowed_common_names: Vec<String>,
    #[serde(default)]
    pub allowed_dns_sans: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    pub display_name: String,
}

// --- GitHub auth ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct GithubConfigRequest {
    pub organization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GithubConfig {
    pub organization: String,
    pub base_url: String,
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct GithubTeamMapping {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GithubTeamInfo {
    #[serde(default)]
    pub value: String,
}

// --- JWT/OIDC auth ---

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct OidcConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_discovery_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_client_id: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub oidc_client_secret: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_validation_pubkeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_supported_algs: Option<Vec<String>>,
}

impl Clone for OidcConfigRequest {
    fn clone(&self) -> Self {
        Self {
            oidc_discovery_url: self.oidc_discovery_url.clone(),
            oidc_client_id: self.oidc_client_id.clone(),
            oidc_client_secret: self.oidc_client_secret.clone(),
            jwt_validation_pubkeys: self.jwt_validation_pubkeys.clone(),
            bound_issuer: self.bound_issuer.clone(),
            default_role: self.default_role.clone(),
            jwt_supported_algs: self.jwt_supported_algs.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct OidcConfig {
    pub oidc_discovery_url: Option<String>,
    pub oidc_client_id: Option<String>,
    pub bound_issuer: Option<String>,
    pub default_role: Option<String>,
    #[serde(default)]
    pub jwt_supported_algs: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct OidcRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_mappings: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct OidcRoleInfo {
    pub role_type: String,
    #[serde(default)]
    pub bound_audiences: Vec<String>,
    pub user_claim: String,
    #[serde(default)]
    pub bound_claims: HashMap<String, String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
}

// --- RADIUS auth ---

#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct RadiusConfigRequest {
    pub host: String,
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub secret: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unregistered_user_policies: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dial_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nas_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}

impl Clone for RadiusConfigRequest {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            secret: self.secret.clone(),
            port: self.port,
            unregistered_user_policies: self.unregistered_user_policies.clone(),
            dial_timeout: self.dial_timeout,
            read_timeout: self.read_timeout,
            nas_port: self.nas_port,
            token_policies: self.token_policies.clone(),
            token_ttl: self.token_ttl.clone(),
            token_max_ttl: self.token_max_ttl.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RadiusConfig {
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub unregistered_user_policies: String,
    #[serde(default)]
    pub dial_timeout: u64,
    #[serde(default)]
    pub read_timeout: u64,
    #[serde(default)]
    pub nas_port: u16,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct RadiusUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct RadiusUser {
    #[serde(default)]
    pub policies: Vec<String>,
}

// --- Kerberos auth ---

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct KerberosConfigRequest {
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub keytab: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
}

impl Clone for KerberosConfigRequest {
    fn clone(&self) -> Self {
        Self {
            keytab: self.keytab.clone(),
            service_account: self.service_account.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KerberosConfig {
    #[serde(default)]
    pub service_account: String,
}

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct KerberosLdapConfigRequest {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userattr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupattr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groupfilter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binddn: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub bindpass: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
}

impl Clone for KerberosLdapConfigRequest {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            userdn: self.userdn.clone(),
            userattr: self.userattr.clone(),
            groupdn: self.groupdn.clone(),
            groupattr: self.groupattr.clone(),
            groupfilter: self.groupfilter.clone(),
            binddn: self.binddn.clone(),
            bindpass: self.bindpass.clone(),
            starttls: self.starttls,
            insecure_tls: self.insecure_tls,
            certificate: self.certificate.clone(),
            token_policies: self.token_policies.clone(),
            token_ttl: self.token_ttl.clone(),
            token_max_ttl: self.token_max_ttl.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KerberosLdapConfig {
    pub url: String,
    #[serde(default)]
    pub userdn: String,
    #[serde(default)]
    pub userattr: String,
    #[serde(default)]
    pub groupdn: String,
    #[serde(default)]
    pub groupattr: String,
    #[serde(default)]
    pub groupfilter: String,
    pub starttls: bool,
    pub insecure_tls: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct KerberosGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KerberosGroup {
    #[serde(default)]
    pub policies: Vec<String>,
}
