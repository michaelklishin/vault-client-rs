use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::AppRoleAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::auth::{
    AppRoleCreateRequest, AppRoleInfo, AppRoleRoleIdResponse, AppRoleSecretIdResponse,
};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct AppRoleAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl AppRoleAuthOperations for AppRoleAuthHandler<'_> {
    async fn login(&self, role_id: &str, secret_id: &SecretString) -> Result<AuthInfo, VaultError> {
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id.expose_secret(),
        });
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

    async fn create_role(
        &self,
        name: &str,
        params: &AppRoleCreateRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/role/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<AppRoleInfo, VaultError> {
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

    async fn read_role_id(&self, name: &str) -> Result<String, VaultError> {
        let resp: AppRoleRoleIdResponse = self
            .client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/role/{}/role-id", self.mount, encode_path(name)),
                None,
            )
            .await?;
        Ok(resp.role_id)
    }

    async fn generate_secret_id(&self, name: &str) -> Result<AppRoleSecretIdResponse, VaultError> {
        self.client
            .exec_with_data(
                Method::POST,
                &format!("auth/{}/role/{}/secret-id", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn destroy_secret_id(
        &self,
        name: &str,
        secret_id: &SecretString,
    ) -> Result<(), VaultError> {
        let body = serde_json::json!({ "secret_id": secret_id.expose_secret() });
        self.client
            .exec_empty(
                Method::POST,
                &format!(
                    "auth/{}/role/{}/secret-id/destroy",
                    self.mount,
                    encode_path(name)
                ),
                Some(&body),
            )
            .await
    }
}
