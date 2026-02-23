use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::GcpSecretsOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::gcp::*;

#[derive(Debug)]
pub struct GcpHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl GcpSecretsOperations for GcpHandler<'_> {
    async fn configure(&self, params: &GcpConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(Method::POST, &format!("{}/config", self.mount), Some(&body))
            .await
    }

    async fn read_config(&self) -> Result<GcpConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config", self.mount), None)
            .await
    }

    async fn delete_config(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("{}/config", self.mount), None)
            .await
    }

    async fn create_roleset(
        &self,
        name: &str,
        params: &GcpRolesetRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roleset/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_roleset(&self, name: &str) -> Result<GcpRoleset, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/roleset/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_roleset(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/roleset/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_rolesets(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/rolesets", self.mount))
            .await
    }

    async fn get_service_account_key(
        &self,
        roleset: &str,
    ) -> Result<GcpServiceAccountKey, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/key/{}", self.mount, encode_path(roleset)),
                None,
            )
            .await
    }

    async fn get_oauth_token(&self, roleset: &str) -> Result<GcpOAuthToken, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/token/{}", self.mount, encode_path(roleset)),
                None,
            )
            .await
    }

    async fn rotate_roleset(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roleset/{}/rotate", self.mount, encode_path(name)),
                None,
            )
            .await
    }
}
