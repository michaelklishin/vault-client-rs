use std::collections::HashMap;

use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::VaultClient;
use crate::api::traits::Kv1Operations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;

#[derive(Debug)]
pub struct Kv1Handler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl<'a> Kv1Operations for Kv1Handler<'a> {
    async fn read<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/{}", self.mount, encode_path(path)),
                Some(data),
            )
            .await
    }

    async fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/{}", self.mount, encode_path(path)),
                None,
            )
            .await
    }

    async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/{}", self.mount, encode_path(path)))
            .await
    }
}

impl Kv1Handler<'_> {
    pub async fn delete(&self, path: &str) -> Result<(), VaultError> {
        Kv1Operations::delete(self, path).await
    }

    pub async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        Kv1Operations::list(self, path).await
    }

    pub async fn write(&self, path: &str, data: &impl Serialize) -> Result<(), VaultError> {
        let body = to_body(data)?;
        Kv1Operations::write(self, path, &body).await
    }

    pub async fn read_data<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        Kv1Operations::read(self, path).await
    }

    /// Read a single field from a KV1 secret, stringified
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
                mount: self.mount.clone(),
                path: path.to_string(),
                field: field.to_string(),
            })
    }

    /// Read all fields from a KV1 secret as `String` key-value pairs
    ///
    /// Every value in the secret must be a JSON string; numeric or boolean
    /// values cause a deserialization error. Use `read_field` to extract a
    /// single field regardless of its JSON type, or `read_data` to
    /// deserialize into a typed struct
    pub async fn read_string_data(&self, path: &str) -> Result<HashMap<String, String>, VaultError> {
        Kv1Operations::read(self, path).await
    }
}
