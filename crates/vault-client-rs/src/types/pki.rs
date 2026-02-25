use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiRootParams {
    #[serde(skip)]
    pub generate_type: String,
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_sans: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_sans: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct PkiCertificate {
    pub certificate: String,
    pub issuing_ca: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    pub serial_number: String,
    pub expiration: Option<u64>,
    pub private_key: Option<SecretString>,
    pub private_key_type: Option<String>,
}

impl Clone for PkiCertificate {
    fn clone(&self) -> Self {
        Self {
            certificate: self.certificate.clone(),
            issuing_ca: self.issuing_ca.clone(),
            ca_chain: self.ca_chain.clone(),
            serial_number: self.serial_number.clone(),
            expiration: self.expiration,
            private_key: self.private_key.clone(),
            private_key_type: self.private_key_type.clone(),
        }
    }
}

impl fmt::Debug for PkiCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkiCertificate")
            .field("certificate", &self.certificate)
            .field("issuing_ca", &self.issuing_ca)
            .field("ca_chain", &self.ca_chain)
            .field("serial_number", &self.serial_number)
            .field("expiration", &self.expiration)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|s| redact(s.expose_secret())),
            )
            .field("private_key_type", &self.private_key_type)
            .finish()
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiIntermediateParams {
    #[serde(skip)]
    pub generate_type: String,
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct PkiCsr {
    pub csr: String,
    pub private_key: Option<SecretString>,
    pub private_key_type: Option<String>,
}

impl Clone for PkiCsr {
    fn clone(&self) -> Self {
        Self {
            csr: self.csr.clone(),
            private_key: self.private_key.clone(),
            private_key_type: self.private_key_type.clone(),
        }
    }
}

impl fmt::Debug for PkiCsr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkiCsr")
            .field("csr", &self.csr)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|s| redact(s.expose_secret())),
            )
            .field("private_key_type", &self.private_key_type)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiImportResult {
    pub imported_issuers: Option<Vec<String>>,
    pub imported_keys: Option<Vec<String>>,
    pub mapping: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiIssuerInfo {
    pub issuer_id: String,
    pub issuer_name: Option<String>,
    pub certificate: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    #[serde(default)]
    pub leaf_not_after_behavior: String,
    #[serde(default)]
    pub usage: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiRoleParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_localhost: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_bare_domains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_subdomains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_any_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_hostnames: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_ip_sans: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generate_lease: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_store: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiRole {
    pub ttl: u64,
    pub max_ttl: u64,
    pub allow_localhost: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    pub allow_bare_domains: bool,
    pub allow_subdomains: bool,
    pub allow_any_name: bool,
    pub enforce_hostnames: bool,
    pub allow_ip_sans: bool,
    pub server_flag: bool,
    pub client_flag: bool,
    pub key_type: String,
    pub key_bits: u64,
    #[serde(default)]
    pub generate_lease: bool,
    #[serde(default)]
    pub no_store: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiIssueParams {
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_sans: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct PkiIssuedCert {
    pub certificate: String,
    pub issuing_ca: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    pub private_key: SecretString,
    pub private_key_type: String,
    pub serial_number: String,
    pub expiration: u64,
}

impl Clone for PkiIssuedCert {
    fn clone(&self) -> Self {
        Self {
            certificate: self.certificate.clone(),
            issuing_ca: self.issuing_ca.clone(),
            ca_chain: self.ca_chain.clone(),
            private_key: self.private_key.clone(),
            private_key_type: self.private_key_type.clone(),
            serial_number: self.serial_number.clone(),
            expiration: self.expiration,
        }
    }
}

impl fmt::Debug for PkiIssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkiIssuedCert")
            .field("certificate", &self.certificate)
            .field("issuing_ca", &self.issuing_ca)
            .field("ca_chain", &self.ca_chain)
            .field("private_key", &redact(self.private_key.expose_secret()))
            .field("private_key_type", &self.private_key_type)
            .field("serial_number", &self.serial_number)
            .field("expiration", &self.expiration)
            .finish()
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiSignParams {
    pub csr: String,
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiSignedCert {
    pub certificate: String,
    pub issuing_ca: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    pub serial_number: String,
    pub expiration: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiRevocationInfo {
    pub revocation_time: u64,
    #[serde(default)]
    pub revocation_time_rfc3339: String,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiCertificateEntry {
    pub certificate: String,
    #[serde(default)]
    pub revocation_time: u64,
    #[serde(default)]
    pub revocation_time_rfc3339: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PkiUrlsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuing_certificates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_distribution_points: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ocsp_servers: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiTidyParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_cert_store: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_revoked_certs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_buffer: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct PkiTidyStatus {
    #[serde(default)]
    pub state: String,
    pub error: Option<String>,
    pub time_started: Option<String>,
    pub time_finished: Option<String>,
    pub cert_store_deleted_count: Option<u64>,
    pub revoked_cert_deleted_count: Option<u64>,
}

// --- Issuer update ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiIssuerUpdateParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_not_after_behavior: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_chain: Option<Vec<String>>,
}

// --- Cross-signing ---

#[derive(Debug, Serialize, Default, Clone)]
pub struct PkiCrossSignRequest {
    pub common_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
}

// --- ACME (Vault 1.14+) ---

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PkiAcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_roles: Vec<String>,
    pub default_directory_policy: Option<String>,
    pub dns_resolver: Option<String>,
    pub eab_policy: Option<String>,
}
