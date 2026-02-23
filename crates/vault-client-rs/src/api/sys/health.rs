use reqwest::Method;

use crate::types::error::VaultError;
use crate::types::sys::{HealthResponse, LeaderResponse};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn health(&self) -> Result<HealthResponse, VaultError> {
        self.client
            .exec_direct(
                Method::GET,
                "sys/health?standbyok=true&perfstandbyok=true&drsecondarycode=200&sealedcode=200&uninitcode=200",
                None,
            )
            .await
    }

    pub async fn leader(&self) -> Result<LeaderResponse, VaultError> {
        self.client
            .exec_direct(Method::GET, "sys/leader", None)
            .await
    }
}
