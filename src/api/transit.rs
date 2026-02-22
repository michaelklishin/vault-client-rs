use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::TransitOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::transit::*;

#[derive(Debug)]
pub struct TransitHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl TransitOperations for TransitHandler<'_> {
    // --- Key management ---

    async fn create_key(&self, name: &str, params: &TransitKeyParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/keys/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_key(&self, name: &str) -> Result<TransitKeyInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/keys/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list(&format!("{}/keys", self.mount)).await
    }

    async fn delete_key(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/keys/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn update_key_config(
        &self,
        name: &str,
        cfg: &TransitKeyConfig,
    ) -> Result<(), VaultError> {
        let body = to_body(cfg)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/keys/{}/config", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn rotate_key(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/keys/{}/rotate", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn export_key(
        &self,
        name: &str,
        key_type: &str,
        version: Option<u64>,
    ) -> Result<TransitExportedKey, VaultError> {
        let path = match version {
            Some(v) => format!(
                "{}/export/{}/{}/{}",
                self.mount,
                encode_path(key_type),
                encode_path(name),
                v
            ),
            None => format!(
                "{}/export/{}/{}",
                self.mount,
                encode_path(key_type),
                encode_path(name)
            ),
        };
        self.client.exec_with_data(Method::GET, &path, None).await
    }

    // --- Encrypt / decrypt ---

    async fn encrypt(&self, name: &str, plaintext: &SecretString) -> Result<String, VaultError> {
        let body = serde_json::json!({
            "plaintext": B64.encode(plaintext.expose_secret()),
        });
        let resp: TransitEncryptResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/encrypt/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.ciphertext)
    }

    async fn decrypt(&self, name: &str, ciphertext: &str) -> Result<SecretString, VaultError> {
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp: TransitDecryptResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/decrypt/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        // Vault returns base64-encoded plaintext
        let decoded = B64
            .decode(resp.plaintext.expose_secret())
            .map_err(|e| VaultError::Config(format!("base64 decode: {e}")))?;
        let s = String::from_utf8(decoded)
            .map_err(|e| VaultError::Config(format!("utf-8 decode: {e}")))?;
        Ok(SecretString::new(s))
    }

    async fn rewrap(&self, name: &str, ciphertext: &str) -> Result<String, VaultError> {
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp: TransitRewrapResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/rewrap/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.ciphertext)
    }

    // --- Batch operations ---

    async fn batch_encrypt(
        &self,
        name: &str,
        items: &[TransitBatchPlaintext],
    ) -> Result<Vec<TransitBatchCiphertext>, VaultError> {
        let body = serde_json::json!({ "batch_input": items });
        let resp: TransitBatchEncryptResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/encrypt/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.batch_results)
    }

    async fn batch_decrypt(
        &self,
        name: &str,
        items: &[TransitBatchCiphertext],
    ) -> Result<Vec<TransitBatchDecryptItem>, VaultError> {
        let body = serde_json::json!({ "batch_input": items });
        let resp: TransitBatchDecryptResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/decrypt/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.batch_results)
    }

    // --- Signing ---

    async fn sign(
        &self,
        name: &str,
        input: &[u8],
        params: &TransitSignParams,
    ) -> Result<String, VaultError> {
        let mut body = to_body(params)?;
        body["input"] = serde_json::Value::String(B64.encode(input));
        let resp: TransitSignResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/sign/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.signature)
    }

    async fn verify(&self, name: &str, input: &[u8], signature: &str) -> Result<bool, VaultError> {
        let body = serde_json::json!({
            "input": B64.encode(input),
            "signature": signature,
        });
        let resp: TransitVerifyResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/verify/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.valid)
    }

    // --- Hash / HMAC / random ---

    async fn hash(&self, input: &[u8], algorithm: &str) -> Result<String, VaultError> {
        let body = serde_json::json!({
            "input": B64.encode(input),
            "algorithm": algorithm,
        });
        let resp: TransitHashResponse = self
            .client
            .exec_with_data(Method::POST, &format!("{}/hash", self.mount), Some(&body))
            .await?;
        Ok(resp.sum)
    }

    async fn hmac(&self, name: &str, input: &[u8], algorithm: &str) -> Result<String, VaultError> {
        let body = serde_json::json!({
            "input": B64.encode(input),
            "algorithm": algorithm,
        });
        let resp: TransitHmacResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/hmac/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.hmac)
    }

    async fn random(&self, num_bytes: u32, format: &str) -> Result<String, VaultError> {
        let body = serde_json::json!({
            "bytes": num_bytes,
            "format": format,
        });
        let resp: TransitRandomResponse = self
            .client
            .exec_with_data(Method::POST, &format!("{}/random", self.mount), Some(&body))
            .await?;
        Ok(resp.random_bytes)
    }

    async fn generate_data_key(
        &self,
        name: &str,
        key_type: &str,
    ) -> Result<TransitDataKey, VaultError> {
        self.client
            .exec_with_data(
                Method::POST,
                &format!(
                    "{}/datakey/{}/{}",
                    self.mount,
                    encode_path(key_type),
                    encode_path(name)
                ),
                None,
            )
            .await
    }

    // --- Key maintenance ---

    async fn trim_key(&self, name: &str, min_version: u64) -> Result<(), VaultError> {
        let body = serde_json::json!({ "min_available_version": min_version });
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/keys/{}/trim", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn backup_key(&self, name: &str) -> Result<SecretString, VaultError> {
        let resp: TransitBackupResponse = self
            .client
            .exec_with_data(
                Method::GET,
                &format!("{}/backup/{}", self.mount, encode_path(name)),
                None,
            )
            .await?;
        Ok(resp.backup)
    }

    async fn restore_key(&self, name: &str, backup: &SecretString) -> Result<(), VaultError> {
        let body = serde_json::json!({ "backup": backup.expose_secret() });
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/restore/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn batch_sign(
        &self,
        name: &str,
        items: &[TransitBatchSignInput],
        params: &TransitSignParams,
    ) -> Result<Vec<TransitBatchSignResult>, VaultError> {
        let mut body = to_body(params)?;
        body["batch_input"] = serde_json::to_value(items)
            .map_err(|e| VaultError::Config(format!("serialize batch sign input: {e}")))?;
        let resp: TransitBatchSignResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/sign/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.batch_results)
    }

    async fn batch_verify(
        &self,
        name: &str,
        items: &[TransitBatchVerifyInput],
    ) -> Result<Vec<TransitBatchVerifyResult>, VaultError> {
        let body = serde_json::json!({ "batch_input": items });
        let resp: TransitBatchVerifyResponse = self
            .client
            .exec_with_data(
                Method::POST,
                &format!("{}/verify/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.batch_results)
    }

    async fn read_cache_config(&self) -> Result<TransitCacheConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/cache-config", self.mount), None)
            .await
    }

    async fn write_cache_config(&self, size: u64) -> Result<(), VaultError> {
        let body = serde_json::json!({ "size": size });
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/cache-config", self.mount),
                Some(&body),
            )
            .await
    }
}
