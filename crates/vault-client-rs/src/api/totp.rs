use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::TotpOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::response::VaultResponse;
use crate::types::totp::*;

#[derive(Debug)]
pub struct TotpHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl TotpOperations for TotpHandler<'_> {
    async fn create_key(
        &self,
        name: &str,
        params: &TotpKeyRequest,
    ) -> Result<Option<TotpGenerateResponse>, VaultError> {
        let body = to_body(params)?;
        let resp: VaultResponse<TotpGenerateResponse> = self
            .client
            .exec_with_auth(
                Method::POST,
                &format!("{}/keys/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await?;
        Ok(resp.data)
    }

    async fn read_key(&self, name: &str) -> Result<TotpKeyInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/keys/{}", self.mount, encode_path(name)),
                None,
            )
            .await
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

    async fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list(&format!("{}/keys", self.mount)).await
    }

    async fn generate_code(&self, name: &str) -> Result<TotpCode, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/code/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn validate_code(&self, name: &str, code: &str) -> Result<TotpValidation, VaultError> {
        let body = serde_json::json!({ "code": code });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/code/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }
}
