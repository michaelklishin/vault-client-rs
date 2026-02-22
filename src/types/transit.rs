use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitKeyParams {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergent_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitKeyInfo {
    #[serde(rename = "type")]
    pub key_type: String,
    pub deletion_allowed: bool,
    pub derived: bool,
    pub exportable: bool,
    pub allow_plaintext_backup: bool,
    #[serde(default)]
    pub keys: HashMap<String, serde_json::Value>,
    pub min_decryption_version: u64,
    pub min_encryption_version: u64,
    pub name: String,
    pub supports_encryption: bool,
    pub supports_decryption: bool,
    pub supports_derivation: bool,
    pub supports_signing: bool,
    #[serde(default)]
    pub auto_rotate_period: u64,
    pub latest_version: u64,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitKeyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_decryption_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_encryption_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitEncryptResponse {
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitDecryptResponse {
    pub plaintext: SecretString,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitRewrapResponse {
    pub ciphertext: String,
}

#[derive(Serialize, Clone)]
pub struct TransitBatchPlaintext {
    pub plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

impl std::fmt::Debug for TransitBatchPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitBatchPlaintext")
            .field("plaintext", &"[REDACTED]")
            .field("context", &self.context)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransitBatchCiphertext {
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitSignParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marshaling_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prehashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_length: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitSignResponse {
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitVerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitHashResponse {
    pub sum: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitHmacResponse {
    pub hmac: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitRandomResponse {
    pub random_bytes: String,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitDataKey {
    pub ciphertext: String,
    pub plaintext: Option<SecretString>,
}

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitExportedKey {
    pub name: String,
    pub keys: HashMap<String, SecretString>,
    #[serde(rename = "type")]
    pub key_type: String,
}

impl std::fmt::Debug for TransitExportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitExportedKey")
            .field("name", &self.name)
            .field("keys", &format_args!("[REDACTED; {} versions]", self.keys.len()))
            .field("key_type", &self.key_type)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitCacheConfig {
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchEncryptResponse {
    pub batch_results: Vec<TransitBatchCiphertext>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchDecryptResponse {
    pub batch_results: Vec<TransitBatchDecryptItem>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitBatchDecryptItem {
    pub plaintext: Option<SecretString>,
    #[serde(default)]
    pub error: String,
}

#[derive(Deserialize)]
pub(crate) struct TransitBackupResponse {
    pub backup: SecretString,
}

impl std::fmt::Debug for TransitBackupResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitBackupResponse")
            .field("backup", &"[REDACTED]")
            .finish()
    }
}
