use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::NomadOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::nomad::*;

#[derive(Debug)]
pub struct NomadHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl NomadOperations for NomadHandler<'_> {
    async fn configure(&self, params: &NomadConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/access", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<NomadConfig, VaultError> {
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

    async fn create_role(&self, name: &str, params: &NomadRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/role/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<NomadRole, VaultError> {
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

    async fn get_credentials(&self, role: &str) -> Result<NomadCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(role)),
                None,
            )
            .await
    }
}
