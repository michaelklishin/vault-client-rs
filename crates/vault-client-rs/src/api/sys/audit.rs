use std::collections::HashMap;

use reqwest::Method;

use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::sys::{AuditDevice, AuditParams};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_audit_devices(&self) -> Result<HashMap<String, AuditDevice>, VaultError> {
        self.client
            .exec_with_data(Method::GET, "sys/audit", None)
            .await
    }

    pub async fn enable_audit(&self, path: &str, params: &AuditParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::PUT,
                &format!("sys/audit/{}", encode_path(path)),
                Some(&body),
            )
            .await
    }

    pub async fn disable_audit(&self, path: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("sys/audit/{}", encode_path(path)),
                None,
            )
            .await
    }
}
