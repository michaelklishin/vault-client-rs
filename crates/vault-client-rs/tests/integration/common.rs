use std::sync::atomic::{AtomicU64, Ordering};

use secrecy::SecretString;

use vault_client_rs::VaultClient;
use vault_client_rs::types::sys::*;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique name for parallel-safe test isolation
pub fn unique_name(prefix: &str) -> String {
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{pid}-{seq}")
}

/// Read `VAULT_ADDR` and `VAULT_TOKEN` from the environment
///
/// Start a dev-mode Vault before running integration tests:
///
/// ```sh
/// podman run --rm -d -p 8200:8200 \
///   -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
///   -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
///   --name vault-test hashicorp/vault:1.18
/// export VAULT_ADDR=http://127.0.0.1:8200
/// export VAULT_TOKEN=myroot
/// cargo nextest run --all-features -p vault-client-rs --test integration
/// podman rm -f vault-test
/// ```
pub fn vault_addr() -> String {
    std::env::var("VAULT_ADDR")
        .expect("VAULT_ADDR must be set (see tests/integration/common.rs for instructions)")
}

pub fn vault_token() -> SecretString {
    SecretString::from(
        std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN must be set (see tests/integration/common.rs for instructions)"),
    )
}

pub fn build_client(addr: &str, token: SecretString) -> VaultClient {
    VaultClient::builder()
        .address(addr)
        .token(token)
        .max_retries(0)
        .build()
        .unwrap()
}

pub fn build_wrapping_client(addr: &str, token: SecretString, ttl: &str) -> VaultClient {
    VaultClient::builder()
        .address(addr)
        .token(token)
        .max_retries(0)
        .wrap_ttl(ttl)
        .build()
        .unwrap()
}

/// Idempotent secrets engine mount — swallows "path is already in use" errors
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

/// Idempotent auth method enable — swallows "already in use" errors
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

/// Mount a KV v1 engine at a unique path, returning the path
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

/// Mount a PKI engine at a unique path, returning the path
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
