use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::client::to_body;
use crate::types::error::VaultError;
use crate::types::response::WrapInfo;
use crate::types::sys::*;

use super::SysHandler;

#[derive(Deserialize)]
struct VersionHistoryResponse {
    #[allow(dead_code)]
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    key_info: std::collections::HashMap<String, VersionHistoryEntry>,
}

impl SysHandler<'_> {
    pub async fn rekey_init(&self, params: &RekeyInitRequest) -> Result<RekeyStatus, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_direct(Method::PUT, "sys/rekey/init", Some(&body))
            .await
    }

    pub async fn rekey_status(&self) -> Result<RekeyStatus, VaultError> {
        self.client
            .exec_direct(Method::GET, "sys/rekey/init", None)
            .await
    }

    pub async fn rekey_cancel(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, "sys/rekey/init", None)
            .await
    }

    pub async fn rekey_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> Result<RekeyStatus, VaultError> {
        let body = serde_json::json!({
            "key": key.expose_secret(),
            "nonce": nonce,
        });
        self.client
            .exec_direct(Method::PUT, "sys/rekey/update", Some(&body))
            .await
    }

    pub async fn generate_root_init(
        &self,
        params: &GenerateRootInitRequest,
    ) -> Result<GenerateRootStatus, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_direct(Method::PUT, "sys/generate-root/attempt", Some(&body))
            .await
    }

    pub async fn generate_root_status(&self) -> Result<GenerateRootStatus, VaultError> {
        self.client
            .exec_direct(Method::GET, "sys/generate-root/attempt", None)
            .await
    }

    pub async fn generate_root_cancel(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, "sys/generate-root/attempt", None)
            .await
    }

    pub async fn generate_root_update(
        &self,
        key: &SecretString,
        nonce: &str,
    ) -> Result<GenerateRootStatus, VaultError> {
        let body = serde_json::json!({
            "key": key.expose_secret(),
            "nonce": nonce,
        });
        self.client
            .exec_direct(Method::PUT, "sys/generate-root/update", Some(&body))
            .await
    }

    pub async fn remount(&self, from: &str, to: &str) -> Result<RemountStatus, VaultError> {
        let body = serde_json::json!({ "from": from, "to": to });
        self.client
            .exec_with_data(Method::POST, "sys/remount", Some(&body))
            .await
    }

    pub async fn metrics_json(&self) -> Result<serde_json::Value, VaultError> {
        self.client
            .exec_direct(Method::GET, "sys/metrics", None)
            .await
    }

    pub async fn host_info(&self) -> Result<HostInfo, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/host-info", None)
            .await
    }

    pub async fn internal_counters_activity(&self) -> Result<serde_json::Value, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/internal/counters/activity", None)
            .await
    }

    pub async fn version_history(&self) -> Result<Vec<VersionHistoryEntry>, VaultError> {
        let resp: VersionHistoryResponse = self
            .client
            .exec_with_data(Method::GET, "sys/version-history", None)
            .await?;
        let mut entries: Vec<VersionHistoryEntry> = resp
            .key_info
            .into_iter()
            .map(|(ver, mut entry)| {
                entry.version = ver;
                entry
            })
            .collect();
        entries.sort_by(|a, b| a.timestamp_installed.cmp(&b.timestamp_installed));
        Ok(entries)
    }

    pub async fn rewrap(&self, token: &SecretString) -> Result<WrapInfo, VaultError> {
        let body = serde_json::json!({ "token": token.expose_secret() });
        let resp: crate::types::response::VaultResponse<serde_json::Value> = self
            .client
            .exec_with_auth(Method::POST, "sys/wrapping/rewrap", Some(&body))
            .await?;
        resp.wrap_info.ok_or(VaultError::EmptyResponse)
    }
}
