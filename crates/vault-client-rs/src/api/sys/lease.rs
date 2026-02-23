use reqwest::Method;

use crate::client::encode_path;
use crate::types::error::VaultError;
use crate::types::sys::{LeaseInfo, LeaseRenewal};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn read_lease(&self, lease_id: &str) -> Result<LeaseInfo, VaultError> {
        let body = serde_json::json!({ "lease_id": lease_id });
        self.client
            .exec_with_data(Method::POST, "sys/leases/lookup", Some(&body))
            .await
    }

    pub async fn renew_lease(
        &self,
        lease_id: &str,
        increment: Option<&str>,
    ) -> Result<LeaseRenewal, VaultError> {
        let mut body = serde_json::json!({ "lease_id": lease_id });
        if let Some(inc) = increment {
            body["increment"] = serde_json::Value::String(inc.to_string());
        }
        self.client
            .exec_direct(Method::PUT, "sys/leases/renew", Some(&body))
            .await
    }

    pub async fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "lease_id": lease_id });
        self.client
            .exec_empty(Method::PUT, "sys/leases/revoke", Some(&body))
            .await
    }

    pub async fn revoke_prefix(&self, prefix: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::PUT,
                &format!("sys/leases/revoke-prefix/{}", encode_path(prefix)),
                None,
            )
            .await
    }
}
