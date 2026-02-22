use reqwest::Method;

use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::sys::{RateLimitQuota, RateLimitQuotaRequest};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_rate_limit_quotas(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("sys/quotas/rate-limit").await
    }

    pub async fn read_rate_limit_quota(&self, name: &str) -> Result<RateLimitQuota, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("sys/quotas/rate-limit/{}", encode_path(name)),
                None,
            )
            .await
    }

    pub async fn write_rate_limit_quota(
        &self,
        name: &str,
        params: &RateLimitQuotaRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("sys/quotas/rate-limit/{}", encode_path(name)),
                Some(&body),
            )
            .await
    }

    pub async fn delete_rate_limit_quota(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("sys/quotas/rate-limit/{}", encode_path(name)),
                None,
            )
            .await
    }
}
