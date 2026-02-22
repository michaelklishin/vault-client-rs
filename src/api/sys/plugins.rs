use reqwest::Method;

use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::sys::{PluginInfo, RegisterPluginRequest};

use super::SysHandler;

impl SysHandler<'_> {
    pub async fn list_plugins(&self, plugin_type: &str) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("sys/plugins/catalog/{}", encode_path(plugin_type)))
            .await
    }

    pub async fn read_plugin(
        &self,
        plugin_type: &str,
        name: &str,
    ) -> Result<PluginInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!(
                    "sys/plugins/catalog/{}/{}",
                    encode_path(plugin_type),
                    encode_path(name)
                ),
                None,
            )
            .await
    }

    pub async fn register_plugin(&self, params: &RegisterPluginRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!(
                    "sys/plugins/catalog/{}/{}",
                    encode_path(&params.plugin_type),
                    encode_path(&params.name)
                ),
                Some(&body),
            )
            .await
    }

    pub async fn deregister_plugin(&self, plugin_type: &str, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!(
                    "sys/plugins/catalog/{}/{}",
                    encode_path(plugin_type),
                    encode_path(name)
                ),
                None,
            )
            .await
    }

    pub async fn reload_plugin(&self, plugin: &str) -> Result<(), VaultError> {
        let body = serde_json::json!({ "plugin": plugin });
        self.client
            .exec_empty(Method::PUT, "sys/plugins/reload/backend", Some(&body))
            .await
    }
}
