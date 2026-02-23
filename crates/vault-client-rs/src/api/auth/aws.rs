use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::AwsAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::aws::*;
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct AwsAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl AwsAuthOperations for AwsAuthHandler<'_> {
    async fn login(&self, params: &AwsAuthLoginRequest) -> Result<AuthInfo, VaultError> {
        let body = to_body(params)?;
        let resp = self
            .client
            .exec_with_auth::<serde_json::Value>(
                Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&body),
            )
            .await?;
        let auth = resp.auth.ok_or(VaultError::EmptyResponse)?;
        self.client.update_token_from_auth(&auth)?;
        Ok(auth)
    }

    async fn configure(&self, config: &AwsAuthConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config/client", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<AwsAuthConfig, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/config/client", self.mount),
                None,
            )
            .await
    }

    async fn create_role(&self, name: &str, params: &AwsAuthRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/role/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<AwsAuthRoleInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/role/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("auth/{}/role/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("auth/{}/role", self.mount))
            .await
    }
}
