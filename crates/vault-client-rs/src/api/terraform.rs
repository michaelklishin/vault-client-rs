use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::TerraformCloudOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::terraform::*;

#[derive(Debug)]
pub struct TerraformCloudHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl TerraformCloudOperations for TerraformCloudHandler<'_> {
    async fn configure(&self, params: &TerraformCloudConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(Method::POST, &format!("{}/config", self.mount), Some(&body))
            .await
    }

    async fn read_config(&self) -> Result<TerraformCloudConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config", self.mount), None)
            .await
    }

    async fn delete_config(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("{}/config", self.mount), None)
            .await
    }

    async fn create_role(
        &self,
        name: &str,
        params: &TerraformCloudRoleRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/role/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<TerraformCloudRole, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/role/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/role/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list(&format!("{}/role", self.mount)).await
    }

    async fn get_credentials(&self, role: &str) -> Result<TerraformCloudToken, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(role)),
                None,
            )
            .await
    }
}
