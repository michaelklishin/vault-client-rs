use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::TokenAuthOperations;
use crate::client::to_body;
use crate::types::auth::{TokenCreateRequest, TokenLookupResponse};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct TokenAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
}

impl TokenAuthOperations for TokenAuthHandler<'_> {
    async fn lookup_self(&self) -> Result<TokenLookupResponse, VaultError> {
        self.client
            .exec_with_data(Method::GET, "auth/token/lookup-self", None)
            .await
    }

    async fn lookup(&self, token: &SecretString) -> Result<TokenLookupResponse, VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
        self.client
            .exec_with_data(Method::POST, "auth/token/lookup", Some(&body))
            .await
    }

    async fn renew_self(&self, increment: Option<&str>) -> Result<AuthInfo, VaultError> {
        let body = increment.map(|i| serde_json::json!({ "increment": i }));
        let resp = self
            .client
            .exec_with_auth::<serde_json::Value>(
                Method::POST,
                "auth/token/renew-self",
                body.as_ref(),
            )
            .await?;
        let auth = resp.auth.ok_or(VaultError::EmptyResponse)?;
        self.client.update_token_from_auth(&auth)?;
        Ok(auth)
    }

    async fn create(&self, params: &TokenCreateRequest) -> Result<AuthInfo, VaultError> {
        let body = to_body(params)?;
        let resp = self
            .client
            .exec_with_auth::<serde_json::Value>(Method::POST, "auth/token/create", Some(&body))
            .await?;
        resp.auth.ok_or(VaultError::EmptyResponse)
    }

    async fn create_orphan(&self, params: &TokenCreateRequest) -> Result<AuthInfo, VaultError> {
        let body = to_body(params)?;
        let resp = self
            .client
            .exec_with_auth::<serde_json::Value>(
                Method::POST,
                "auth/token/create-orphan",
                Some(&body),
            )
            .await?;
        resp.auth.ok_or(VaultError::EmptyResponse)
    }

    async fn revoke(&self, token: &SecretString) -> Result<(), VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
        self.client
            .exec_empty(Method::POST, "auth/token/revoke", Some(&body))
            .await
    }

    async fn revoke_self(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::POST, "auth/token/revoke-self", None)
            .await
    }

    async fn revoke_accessor(&self, accessor: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "accessor": accessor });
        self.client
            .exec_empty(Method::POST, "auth/token/revoke-accessor", Some(&body))
            .await
    }

    async fn list_accessors(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("auth/token/accessors").await
    }
}
