use reqwest::Method;

use crate::client::encode_path;
use crate::types::error::VaultError;
use crate::types::sys::PolicyInfo;

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_policies(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("sys/policies/acl").await
    }

    pub async fn read_policy(&self, name: &str) -> Result<PolicyInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("sys/policies/acl/{}", encode_path(name)),
                None,
            )
            .await
    }

    pub async fn write_policy(&self, name: &str, rules: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "policy": rules });
        self.client
            .exec_empty(
                Method::PUT,
                &format!("sys/policies/acl/{}", encode_path(name)),
                Some(&body),
            )
            .await
    }

    pub async fn delete_policy(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("sys/policies/acl/{}", encode_path(name)),
                None,
            )
            .await
    }
}
