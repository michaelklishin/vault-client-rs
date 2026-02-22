use std::collections::HashMap;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;

use crate::types::error::VaultError;
use crate::types::response::WrapInfo;
use crate::types::sys::KeyStatus;

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn unwrap<T: DeserializeOwned>(&self, token: &SecretString) -> Result<T, VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
        self.client
            .exec_with_data(Method::POST, "sys/wrapping/unwrap", Some(&body))
            .await
    }

    pub async fn wrap_lookup(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
        self.client
            .exec_with_data(Method::POST, "sys/wrapping/lookup", Some(&body))
            .await
    }

    pub async fn capabilities(
        &self,
        token: &SecretString,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        let body = serde_json::json!({
            "token": token.expose_secret(),
            "paths": paths,
        });
        self.client
            .exec_with_data(Method::POST, "sys/capabilities", Some(&body))
            .await
    }

    pub async fn capabilities_self(
        &self,
        paths: &[&str],
    ) -> Result<HashMap<String, Vec<String>>, VaultError> {
        let body = serde_json::json!({ "paths": paths });
        self.client
            .exec_with_data(Method::POST, "sys/capabilities-self", Some(&body))
            .await
    }

    pub async fn key_status(&self) -> Result<KeyStatus, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/key-status", None)
            .await
    }

    pub async fn rotate_encryption_key(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::PUT, "sys/rotate", None)
            .await
    }
}
