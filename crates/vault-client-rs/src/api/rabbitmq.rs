use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::RabbitmqOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::rabbitmq::*;

#[derive(Debug)]
pub struct RabbitmqHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl RabbitmqOperations for RabbitmqHandler<'_> {
    async fn configure(&self, params: &RabbitmqConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/connection", self.mount),
                Some(&body),
            )
            .await
    }

    async fn configure_lease(&self, ttl: &str, max_ttl: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "ttl": ttl, "max_ttl": max_ttl });
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/lease", self.mount),
                Some(&body),
            )
            .await
    }

    async fn create_role(
        &self,
        name: &str,
        params: &RabbitmqRoleRequest,
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

    async fn read_role(&self, name: &str) -> Result<RabbitmqRole, VaultError> {
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

    async fn get_credentials(&self, role: &str) -> Result<RabbitmqCredentials, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/creds/{}", self.mount, encode_path(role)),
                None,
            )
            .await
    }
}
