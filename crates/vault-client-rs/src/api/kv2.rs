use std::collections::HashMap;

use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::VaultClient;
use crate::api::traits::Kv2Operations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::kv::{KvConfig, KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse};

#[derive(Debug)]
pub struct Kv2Handler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl Kv2Operations for Kv2Handler<'_> {
    // --- Config ---

    async fn read_config(&self) -> Result<KvConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config", self.mount), None)
            .await
    }

    async fn write_config(&self, cfg: &KvConfig) -> Result<(), VaultError> {
        let body = to_body(cfg)?;
        self.client
            .exec_empty(Method::POST, &format!("{}/config", self.mount), Some(&body))
            .await
    }

    // --- Data operations ---

    async fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> Result<KvReadResponse<T>, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/data/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    async fn read_data<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        self.read(path).await.map(|r| r.data)
    }

    async fn read_version<T: DeserializeOwned + Send>(
        &self,
        path: &str,
        version: u64,
    ) -> Result<KvReadResponse<T>, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!(
                    "{}/data/{}?version={}",
                    self.mount,
                    encode_path(path),
                    version
                ),
                None,
            )
            .await
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<KvMetadata, VaultError> {
        let body = serde_json::json!({ "data": data });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/data/{}", self.mount, encode_path(path)),
                Some(&body),
            )
            .await
    }

    async fn write_cas(
        &self,
        path: &str,
        data: &serde_json::Value,
        cas: u64,
    ) -> Result<KvMetadata, VaultError> {
        let body = serde_json::json!({
            "options": { "cas": cas },
            "data": data,
        });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/data/{}", self.mount, encode_path(path)),
                Some(&body),
            )
            .await
    }

    async fn patch(&self, path: &str, data: &serde_json::Value) -> Result<KvMetadata, VaultError> {
        let body = serde_json::json!({ "data": data });
        self.client
            .exec_patch(&format!("{}/data/{}", self.mount, encode_path(path)), &body)
            .await
    }

    async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/metadata/{}", self.mount, encode_path(path)))
            .await
    }

    async fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/data/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    // --- Version management ---

    async fn delete_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.version_op("delete", path, versions).await
    }

    async fn undelete_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.version_op("undelete", path, versions).await
    }

    async fn destroy_versions(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.version_op("destroy", path, versions).await
    }

    // --- Metadata ---

    async fn read_metadata(&self, path: &str) -> Result<KvFullMetadata, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/metadata/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    async fn write_metadata(&self, path: &str, meta: &KvMetadataParams) -> Result<(), VaultError> {
        let body = to_body(meta)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/metadata/{}", self.mount, encode_path(path)),
                Some(&body),
            )
            .await
    }

    async fn patch_metadata(&self, path: &str, meta: &KvMetadataParams) -> Result<(), VaultError> {
        let body = to_body(meta)?;
        self.client
            .exec_empty(
                Method::PATCH,
                &format!("{}/metadata/{}", self.mount, encode_path(path)),
                Some(&body),
            )
            .await
    }

    async fn delete_metadata(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/metadata/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    // --- Subkeys ---

    async fn read_subkeys(
        &self,
        path: &str,
        depth: Option<u32>,
    ) -> Result<serde_json::Value, VaultError> {
        let url = match depth {
            Some(d) => format!("{}/subkeys/{}?depth={}", self.mount, encode_path(path), d),
            None => format!("{}/subkeys/{}", self.mount, encode_path(path)),
        };
        self.client.exec_with_data(Method::GET, &url, None).await
    }
}

impl Kv2Handler<'_> {
    // --- Private helper ---

    async fn version_op(&self, op: &str, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        let body = serde_json::json!({ "versions": versions });
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/{}/{}", self.mount, op, encode_path(path)),
                Some(&body),
            )
            .await
    }

    // --- Convenience pass-throughs (no trait import needed) ---

    pub async fn delete(&self, path: &str) -> Result<(), VaultError> {
        Kv2Operations::delete(self, path).await
    }

    pub async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        Kv2Operations::list(self, path).await
    }

    // --- Convenience methods accepting &impl Serialize ---

    pub async fn write(&self, path: &str, data: &impl Serialize) -> Result<KvMetadata, VaultError> {
        let body = to_body(data)?;
        Kv2Operations::write(self, path, &body).await
    }

    pub async fn write_cas(
        &self,
        path: &str,
        data: &impl Serialize,
        cas: u64,
    ) -> Result<KvMetadata, VaultError> {
        let body = to_body(data)?;
        Kv2Operations::write_cas(self, path, &body, cas).await
    }

    /// Merge fields into an existing KV2 secret
    pub async fn patch(&self, path: &str, data: &impl Serialize) -> Result<KvMetadata, VaultError> {
        let body = to_body(data)?;
        Kv2Operations::patch(self, path, &body).await
    }

    /// Write a single field to a KV2 secret (replaces all fields, not a patch)
    pub async fn write_field(
        &self,
        path: &str,
        field: &str,
        value: &str,
    ) -> Result<KvMetadata, VaultError> {
        let data = serde_json::json!({ field: value });
        Kv2Operations::write(self, path, &data).await
    }

    pub async fn read_data<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        self.read(path).await.map(|r| r.data)
    }

    /// Read a single field from a KV2 secret, stringified
    ///
    /// String values are returned as-is; other JSON types (numbers,
    /// booleans, objects) are converted via their JSON representation,
    /// matching `vault kv get -field=` behaviour
    pub async fn read_field(&self, path: &str, field: &str) -> Result<String, VaultError> {
        let data: HashMap<String, serde_json::Value> = self.read_data(path).await?;
        data.get(field)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .ok_or_else(|| VaultError::FieldNotFound {
                path: path.to_string(),
                field: field.to_string(),
            })
    }

    /// Read all fields from a KV2 secret as String key-value pairs
    pub async fn read_string_data(
        &self,
        path: &str,
    ) -> Result<HashMap<String, String>, VaultError> {
        self.read_data(path).await
    }
}
