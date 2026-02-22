use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::UserpassAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::auth::{UserpassUserInfo, UserpassUserRequest};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct UserpassAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl UserpassAuthOperations for UserpassAuthHandler<'_> {
    async fn login(&self, username: &str, password: &SecretString) -> Result<AuthInfo, VaultError> {
        let body = serde_json::json!({ "password": password.expose_secret() });
        let resp = self
            .client
            .exec_with_auth::<serde_json::Value>(
                Method::POST,
                &format!("auth/{}/login/{}", self.mount, encode_path(username)),
                Some(&body),
            )
            .await?;
        let auth = resp.auth.ok_or(VaultError::EmptyResponse)?;
        self.client.update_token_from_auth(&auth)?;
        Ok(auth)
    }

    async fn create_user(
        &self,
        username: &str,
        params: &UserpassUserRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/users/{}", self.mount, encode_path(username)),
                Some(&body),
            )
            .await
    }

    async fn read_user(&self, username: &str) -> Result<UserpassUserInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/users/{}", self.mount, encode_path(username)),
                None,
            )
            .await
    }

    async fn delete_user(&self, username: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("auth/{}/users/{}", self.mount, encode_path(username)),
                None,
            )
            .await
    }

    async fn list_users(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("auth/{}/users", self.mount))
            .await
    }

    async fn update_password(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<(), VaultError> {
        let body = serde_json::json!({ "password": password.expose_secret() });
        self.client
            .exec_empty(
                Method::POST,
                &format!(
                    "auth/{}/users/{}/password",
                    self.mount,
                    encode_path(username)
                ),
                Some(&body),
            )
            .await
    }
}
