use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::GcpAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::gcp::{GcpAuthConfig, GcpAuthConfigRequest, GcpAuthRoleInfo, GcpAuthRoleRequest};
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct GcpAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl GcpAuthOperations for GcpAuthHandler<'_> {
    async fn login(&self, role: &str, jwt: &SecretString) -> Result<AuthInfo, VaultError> {
        let body = serde_json::json!({
            "role": role,
            "jwt": jwt.expose_secret(),
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

    async fn configure(&self, config: &GcpAuthConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<GcpAuthConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("auth/{}/config", self.mount), None)
            .await
    }

    async fn create_role(&self, name: &str, params: &GcpAuthRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/role/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<GcpAuthRoleInfo, VaultError> {
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
