use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize, Clone)]
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
    #[serde(default)]
    pub secret_id_bound_cidrs: Vec<String>,
    #[serde(default)]
    pub token_bound_cidrs: Vec<String>,
    #[serde(default)]
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

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AppRoleSecretIdResponse {
    pub secret_id: SecretString,
    pub secret_id_accessor: String,
    pub secret_id_num_uses: u64,
    pub secret_id_ttl: u64,
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

#[derive(Serialize, Default, Clone)]
pub struct K8sAuthConfigRequest {
    pub kubernetes_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes_ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_reviewer_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_local_ca_jwt: Option<bool>,
}

impl std::fmt::Debug for K8sAuthConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sAuthConfigRequest")
            .field("kubernetes_host", &self.kubernetes_host)
            .field("kubernetes_ca_cert", &self.kubernetes_ca_cert)
            .field(
                "token_reviewer_jwt",
                &self.token_reviewer_jwt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("disable_local_ca_jwt", &self.disable_local_ca_jwt)
            .finish()
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

#[derive(Serialize, Default, Clone)]
pub struct UserpassUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
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

impl std::fmt::Debug for UserpassUserRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserpassUserRequest")
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("token_policies", &self.token_policies)
            .field("token_ttl", &self.token_ttl)
            .field("token_max_ttl", &self.token_max_ttl)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .field("token_num_uses", &self.token_num_uses)
            .finish()
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

#[derive(Serialize, Default, Clone)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindpass: Option<String>,
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

impl std::fmt::Debug for LdapConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConfigRequest")
            .field("url", &self.url)
            .field("userdn", &self.userdn)
            .field("userattr", &self.userattr)
            .field("groupdn", &self.groupdn)
            .field("groupattr", &self.groupattr)
            .field("groupfilter", &self.groupfilter)
            .field("binddn", &self.binddn)
            .field("bindpass", &self.bindpass.as_ref().map(|_| "[REDACTED]"))
            .field("starttls", &self.starttls)
            .field("insecure_tls", &self.insecure_tls)
            .field("certificate", &self.certificate)
            .field("token_policies", &self.token_policies)
            .field("token_ttl", &self.token_ttl)
            .field("token_max_ttl", &self.token_max_ttl)
            .finish()
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

#[derive(Serialize, Default, Clone)]
pub struct OidcConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_discovery_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_validation_pubkeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_supported_algs: Option<Vec<String>>,
}

impl std::fmt::Debug for OidcConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfigRequest")
            .field("oidc_discovery_url", &self.oidc_discovery_url)
            .field("oidc_client_id", &self.oidc_client_id)
            .field(
                "oidc_client_secret",
                &self.oidc_client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("jwt_validation_pubkeys", &self.jwt_validation_pubkeys)
            .field("bound_issuer", &self.bound_issuer)
            .field("default_role", &self.default_role)
            .field("jwt_supported_algs", &self.jwt_supported_algs)
            .finish()
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
