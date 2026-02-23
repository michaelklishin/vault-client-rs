use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::KerberosAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::auth::{
    KerberosConfig, KerberosConfigRequest, KerberosGroup, KerberosGroupRequest, KerberosLdapConfig,
    KerberosLdapConfigRequest,
};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct KerberosAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl KerberosAuthOperations for KerberosAuthHandler<'_> {
    async fn login(&self, authorization: &str) -> Result<AuthInfo, VaultError> {
        let body = serde_json::json!({ "authorization": authorization });
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

    async fn configure(&self, config: &KerberosConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<KerberosConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("auth/{}/config", self.mount), None)
            .await
    }

    async fn configure_ldap(&self, config: &KerberosLdapConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config/ldap", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_ldap_config(&self) -> Result<KerberosLdapConfig, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("auth/{}/config/ldap", self.mount),
                None,
            )
            .await
    }

    async fn write_group(
        &self,
        name: &str,
        params: &KerberosGroupRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/groups/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_group(&self, name: &str) -> Result<KerberosGroup, VaultError> {
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
}
