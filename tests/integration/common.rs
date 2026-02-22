use std::sync::atomic::{AtomicU64, Ordering};

use secrecy::SecretString;

use vault_client_rs::types::sys::*;
use vault_client_rs::VaultClient;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique name for parallel-safe test isolation.
pub fn unique_name(prefix: &str) -> String {
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{pid}-{seq}")
}

pub fn vault_addr() -> String {
    std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string())
}

pub fn vault_token() -> SecretString {
    SecretString::new(
        std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "myroot".to_string()),
    )
}

pub fn build_client() -> VaultClient {
    VaultClient::builder()
        .address(&vault_addr())
        .token(vault_token())
        .max_retries(0)
        .build()
        .unwrap()
}

pub fn build_wrapping_client(ttl: &str) -> VaultClient {
    VaultClient::builder()
        .address(&vault_addr())
        .token(vault_token())
        .max_retries(0)
        .wrap_ttl(ttl)
        .build()
        .unwrap()
}

/// Idempotent secrets engine mount — swallows "path is already in use" errors.
pub async fn ensure_mount(client: &VaultClient, path: &str, mount_type: &str) {
    let _ = client
        .sys()
        .mount(
            path,
            &MountParams {
                mount_type: mount_type.into(),
                description: Some(format!("test {mount_type}")),
                config: None,
                options: None,
            },
        )
        .await;
}

/// Idempotent auth method enable — swallows "already in use" errors.
pub async fn ensure_auth(client: &VaultClient, path: &str, auth_type: &str) {
    let _ = client
        .sys()
        .enable_auth(
            path,
            &AuthMountParams {
                mount_type: auth_type.into(),
                description: Some(format!("test {auth_type}")),
                config: None,
            },
        )
        .await;
}

/// Mount a KV v1 engine at a unique path, returning the path.
pub async fn mount_kv1(client: &VaultClient) -> String {
    let path = unique_name("kv1");
    client
        .sys()
        .mount(
            &path,
            &MountParams {
                mount_type: "kv".into(),
                description: Some("test kv1".into()),
                config: None,
                options: Some([("version".to_string(), "1".to_string())].into()),
            },
        )
        .await
        .unwrap();
    path
}

/// Mount a PKI engine at a unique path, returning the path.
pub async fn mount_pki(client: &VaultClient) -> String {
    let path = unique_name("pki");
    client
        .sys()
        .mount(
            &path,
            &MountParams {
                mount_type: "pki".into(),
                description: Some("test pki".into()),
                config: None,
                options: None,
            },
        )
        .await
        .unwrap();
    path
}
