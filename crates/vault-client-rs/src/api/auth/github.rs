use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::GithubAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::auth::{GithubConfig, GithubConfigRequest, GithubTeamInfo, GithubTeamMapping};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct GithubAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl GithubAuthOperations for GithubAuthHandler<'_> {
    async fn login(&self, token: &SecretString) -> Result<AuthInfo, VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
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

    async fn configure(&self, config: &GithubConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<GithubConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("auth/{}/config", self.mount), None)
            .await
    }

    async fn map_team(&self, team: &str, params: &GithubTeamMapping) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/map/teams/{}", self.mount, encode_path(team)),
                Some(&body),
            )
            .await
    }

    async fn read_team_mapping(&self, team: &str) -> Result<GithubTeamInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/map/teams/{}", self.mount, encode_path(team)),
                None,
            )
            .await
    }

    async fn list_teams(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("auth/{}/map/teams", self.mount))
            .await
    }
}
