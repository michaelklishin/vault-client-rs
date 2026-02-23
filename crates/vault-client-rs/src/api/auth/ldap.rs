use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::LdapAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::auth::{
    LdapConfig, LdapConfigRequest, LdapGroup, LdapGroupRequest, LdapUser, LdapUserRequest,
};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct LdapAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl LdapAuthOperations for LdapAuthHandler<'_> {
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

    async fn configure(&self, config: &LdapConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<LdapConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("auth/{}/config", self.mount), None)
            .await
    }

    async fn write_group(&self, name: &str, params: &LdapGroupRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/groups/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_group(&self, name: &str) -> Result<LdapGroup, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/groups/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_group(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("auth/{}/groups/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_groups(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("auth/{}/groups", self.mount))
            .await
    }

    async fn write_user(&self, name: &str, params: &LdapUserRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/users/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_user(&self, name: &str) -> Result<LdapUser, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/users/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn delete_user(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("auth/{}/users/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_users(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("auth/{}/users", self.mount))
            .await
    }
}
