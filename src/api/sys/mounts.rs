use std::collections::HashMap;

use reqwest::Method;

use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::sys::{
    AuthMountInfo, AuthMountParams, MountConfig, MountInfo, MountParams, MountTuneParams,
};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_mounts(&self) -> Result<HashMap<String, MountInfo>, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/mounts", None)
            .await
    }

    pub async fn mount(&self, path: &str, params: &MountParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(Method::POST, &format!("sys/mounts/{}", encode_path(path)), Some(&body))
            .await
    }

    pub async fn unmount(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("sys/mounts/{}", encode_path(path)), None)
            .await
    }

    pub async fn tune_mount(&self, path: &str, params: &MountTuneParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("sys/mounts/{}/tune", encode_path(path)),
                Some(&body),
            )
            .await
    }

    pub async fn read_mount_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("sys/mounts/{}/tune", encode_path(path)),
                None,
            )
            .await
    }

    // --- Auth mounts ---

    pub async fn list_auth_mounts(&self) -> Result<HashMap<String, AuthMountInfo>, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/auth", None)
            .await
    }

    pub async fn enable_auth(
        &self,
        path: &str,
        params: &AuthMountParams,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(Method::POST, &format!("sys/auth/{}", encode_path(path)), Some(&body))
            .await
    }

    pub async fn disable_auth(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("sys/auth/{}", encode_path(path)), None)
            .await
    }

    pub async fn read_auth_tune(&self, path: &str) -> Result<MountConfig, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("sys/auth/{}/tune", encode_path(path)),
                None,
            )
            .await
    }
}
