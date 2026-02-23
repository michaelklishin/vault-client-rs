use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::ConsulOperations;
use crate::client::{encode_path, to_body};
use crate::types::consul::*;
use crate::types::error::VaultError;

#[derive(Debug)]
pub struct ConsulHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl ConsulOperations for ConsulHandler<'_> {
    async fn configure(&self, params: &ConsulConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/access", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<ConsulConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config/access", self.mount), None)
            .await
    }

    async fn delete_config(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/config/access", self.mount),
                None,
            )
            .await
    }

    async fn create_role(&self, name: &str, params: &ConsulRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<ConsulRole, VaultError> {
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

    async fn get_credentials(&self, role: &str) -> Result<ConsulCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(role)),
                None,
            )
            .await
    }
}
