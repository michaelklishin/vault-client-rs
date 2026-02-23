use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::DatabaseOperations;
use crate::client::{encode_path, to_body};
use crate::types::database::*;
use crate::types::error::VaultError;

#[derive(Debug)]
pub struct DatabaseHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl DatabaseOperations for DatabaseHandler<'_> {
    async fn configure(
        &self,
        name: &str,
        params: &DatabaseConfigRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self, name: &str) -> Result<DatabaseConfig, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/config/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_config(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/config/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_connections(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/config", self.mount))
            .await
    }

    async fn reset_connection(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/reset/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn create_role(
        &self,
        name: &str,
        params: &DatabaseRoleRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<DatabaseRole, VaultError> {
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

    async fn get_credentials(&self, role: &str) -> Result<DatabaseCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(role)),
                None,
            )
            .await
    }

    async fn create_static_role(
        &self,
        name: &str,
        params: &DatabaseStaticRoleRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/static-roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_static_role(&self, name: &str) -> Result<DatabaseStaticRole, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/static-roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_static_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/static-roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_static_roles(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/static-roles", self.mount))
            .await
    }

    async fn get_static_credentials(
        &self,
        name: &str,
    ) -> Result<DatabaseStaticCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/static-creds/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn rotate_static_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/rotate-role/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }
}
