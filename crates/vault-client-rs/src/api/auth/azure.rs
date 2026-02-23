use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};

use crate::VaultClient;
use crate::api::traits::AzureAuthOperations;
use crate::client::{encode_path, to_body};
use crate::types::azure::{
    AzureAuthConfig, AzureAuthConfigRequest, AzureAuthRoleInfo, AzureAuthRoleRequest,
};
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

#[derive(Debug)]
pub struct AzureAuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl AzureAuthOperations for AzureAuthHandler<'_> {
    async fn login(
        &self,
        role: &str,
        jwt: &SecretString,
        subscription_id: Option<&str>,
        resource_group_name: Option<&str>,
        vm_name: Option<&str>,
        vmss_name: Option<&str>,
    ) -> Result<AuthInfo, VaultError> {
        let mut body = serde_json::json!({
            "role": role,
            "jwt": jwt.expose_secret(),
        });
        if let Some(sub) = subscription_id {
            body["subscription_id"] = serde_json::Value::String(sub.to_owned());
        }
        if let Some(rg) = resource_group_name {
            body["resource_group_name"] = serde_json::Value::String(rg.to_owned());
        }
        if let Some(vm) = vm_name {
            body["vm_name"] = serde_json::Value::String(vm.to_owned());
        }
        if let Some(vmss) = vmss_name {
            body["vmss_name"] = serde_json::Value::String(vmss.to_owned());
        }
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

    async fn configure(&self, config: &AzureAuthConfigRequest) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_config(&self) -> Result<AzureAuthConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("auth/{}/config", self.mount), None)
            .await
    }

    async fn create_role(
        &self,
        name: &str,
        params: &AzureAuthRoleRequest,
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

    async fn read_role(&self, name: &str) -> Result<AzureAuthRoleInfo, VaultError> {
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
