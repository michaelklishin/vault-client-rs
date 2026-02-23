use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::SshOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::ssh::*;

#[derive(Debug)]
pub struct SshHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl SshOperations for SshHandler<'_> {
    async fn configure_ca(&self, params: &SshCaConfigRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/ca", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_public_key(&self) -> Result<SshCaPublicKey, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config/ca", self.mount), None)
            .await
    }

    async fn delete_ca(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("{}/config/ca", self.mount), None)
            .await
    }

    async fn create_role(&self, name: &str, params: &SshRoleRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<SshRole, VaultError> {
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

    async fn sign_key(
        &self,
        role: &str,
        params: &SshSignRequest,
    ) -> Result<SshSignedKey, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/sign/{}", self.mount, encode_path(role)),
                Some(&body),
            )
            .await
    }

    async fn verify_otp(&self, params: &SshVerifyRequest) -> Result<SshVerifyResponse, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(Method::POST, &format!("{}/verify", self.mount), Some(&body))
            .await
    }
}
