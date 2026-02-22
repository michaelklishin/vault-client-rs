use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::client::to_body;
use crate::types::error::VaultError;
use crate::types::sys::{InitParams, InitResponse, SealStatus};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn seal_status(&self) -> Result<SealStatus, VaultError> {
        self.client
            .exec_direct(Method::GET, "sys/seal-status", None)
            .await
    }

    pub async fn seal(&self) -> Result<(), VaultError> {
        self.client.exec_empty(Method::PUT, "sys/seal", None).await
    }

    pub async fn unseal(&self, key: &SecretString) -> Result<SealStatus, VaultError> {
        let body = serde_json::json!({ "key": key.expose_secret() });
        self.client
            .exec_direct(Method::PUT, "sys/unseal", Some(&body))
            .await
    }

    pub async fn init(&self, params: &InitParams) -> Result<InitResponse, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_direct(Method::PUT, "sys/init", Some(&body))
            .await
    }

    pub async fn step_down(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::PUT, "sys/step-down", None)
            .await
    }
}
