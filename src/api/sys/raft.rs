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
}
