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
    pub async fn write(&self, path: &str, data: &impl Serialize) -> Result<(), VaultError> {
        let body = to_body(data)?;
        Kv1Operations::write(self, path, &body).await
    }
}
