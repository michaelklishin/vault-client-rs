use reqwest::Method;

use crate::types::error::VaultError;
use crate::types::sys::{AutopilotState, RaftConfig};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn raft_config(&self) -> Result<RaftConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/storage/raft/configuration", None)
            .await
    }

    pub async fn raft_autopilot_state(&self) -> Result<AutopilotState, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/storage/raft/autopilot/state", None)
            .await
    }

    pub async fn raft_remove_peer(&self, server_id: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "server_id": server_id });
        self.client
            .exec_empty(Method::POST, "sys/storage/raft/remove-peer", Some(&body))
            .await
    }

    /// Take a Raft snapshot, returning the raw snapshot bytes
    pub async fn raft_snapshot(&self) -> Result<Vec<u8>, VaultError> {
        let resp = self
            .client
            .execute(Method::GET, "sys/storage/raft/snapshot", None)
            .await?;
        Ok(resp.bytes().await.map_err(VaultError::Http)?.to_vec())
    }

    /// Restore a Raft snapshot from raw bytes
    pub async fn raft_snapshot_restore(&self, snapshot: &[u8]) -> Result<(), VaultError> {
        let url_str = format!("{}v1/sys/storage/raft/snapshot", self.client.inner.base_url);
        let url = url::Url::parse(&url_str)?;
        let req = self
            .client
            .inner
            .http
            .post(url)
            .header("X-Vault-Request", "true")
            .body(snapshot.to_vec());
        let req = self.client.inject_headers(req)?;
        let _resp: reqwest::Response = req.send().await.map_err(VaultError::Http)?;
        Ok(())
    }
}
