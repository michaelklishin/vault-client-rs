use reqwest::Method;

use crate::client::encode_path;
use crate::types::error::VaultError;
use crate::types::sys::NamespaceInfo;

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_namespaces(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("sys/namespaces").await
    }

    pub async fn create_namespace(&self, path: &str) -> Result<NamespaceInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::POST,
                &format!("sys/namespaces/{}", encode_path(path)),
                None,
            )
            .await
    }

    pub async fn delete_namespace(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("sys/namespaces/{}", encode_path(path)),
                None,
            )
            .await
    }
}
