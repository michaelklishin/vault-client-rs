use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::AwsSecretsOperations;
use crate::client::{encode_path, to_body};
use crate::types::aws::*;
use crate::types::error::VaultError;

#[derive(Debug)]
pub struct AwsSecretsHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl AwsSecretsOperations for AwsSecretsHandler<'_> {
    async fn configure_root(&self, params: &AwsConfigRootRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/root", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config_root(&self) -> Result<AwsConfigRoot, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config/root", self.mount), None)
            .await
    }

    async fn rotate_root(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/rotate-root", self.mount),
                None,
            )
            .await
    }

    async fn create_role(&self, name: &str, params: &AwsRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<AwsRole, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/roles", self.mount))
            .await
    }

    async fn get_credentials(&self, name: &str) -> Result<AwsCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn get_sts_credentials(
        &self,
        name: &str,
        params: &AwsStsRequest,
    ) -> Result<AwsCredentials, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/sts/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }
}
