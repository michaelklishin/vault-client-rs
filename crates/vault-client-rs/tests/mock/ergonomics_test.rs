use std::collections::HashMap;
use std::time::Duration;

use proptest::prelude::*;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::blocking::BlockingClientBuilder;
use vault_client_rs::blocking::VaultClient as BlockingVaultClient;
use vault_client_rs::{ClientBuilder, KvReadResponse, Kv2Operations, VaultClient, VaultError};

// ---------------------------------------------------------------------------
// Item 1: ~/.vault-token fallback — from_env() resolves the token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn from_env_can_be_built_with_address_override() {
    let server = MockServer::start().await;
    let result = ClientBuilder::from_env().address(&server.uri()).build();
    assert!(
        result.is_ok(),
        "from_env() + address override should succeed: {result:?}"
    );
}

#[tokio::test]
async fn from_env_without_address_fails_with_config_error() {
    // Without VAULT_ADDR set (and not overriding), build must return a Config error.
    // We can't guarantee the env var is absent in all CI environments, so we only
    // check the error type when it does fail.
    let result = ClientBuilder::from_env().build();
    match result {
        Err(VaultError::Config(msg)) => {
            assert!(msg.contains("address"), "expected address error, got: {msg}");
        }
        Ok(_) => {
            // VAULT_ADDR is set in this environment — acceptable
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Item 2: VaultError::Sealed carries the Vault address
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sealed_error_contains_url() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(0)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();

    match err {
        VaultError::Sealed { ref url } => {
            assert!(
                url.contains("127.0.0.1") || url.contains("localhost"),
                "url should contain the server address, got: {url}"
            );
        }
        other => panic!("expected Sealed, got: {other:?}"),
    }
}

#[tokio::test]
async fn sealed_display_includes_url() {
    let err = VaultError::Sealed {
        url: "http://vault.example.com:8200/v1/secret/data/x".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("vault.example.com"),
        "display should include the URL, got: {msg}"
    );
}

#[test]
fn sealed_is_still_retryable() {
    assert!(VaultError::Sealed { url: "http://vault:8200".into() }.is_retryable());
}

#[test]
fn sealed_status_code_is_503() {
    assert_eq!(
        VaultError::Sealed { url: "http://vault:8200".into() }.status_code(),
        Some(503)
    );
}

// After retry exhaustion on 503, Sealed is returned directly (not wrapped in RetryExhausted).
#[tokio::test]
async fn retry_exhausted_returns_sealed_directly() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/k"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(1)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("k")
        .await
        .unwrap_err();

    // With max_retries=1 we exhaust retries and get Sealed directly
    // (the last sealed error is returned, not RetryExhausted, for 503)
    assert!(
        matches!(err, VaultError::Sealed { .. }),
        "expected Sealed, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Item 3: cli_mode — Sealed is not retried
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_mode_does_not_retry_sealed() {
    let server = MockServer::start().await;

    // Exactly one 503 is served; cli_mode means no retry happens.
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    // cli_mode(true) + explicit max_retries override: sealed is still not retried
    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .cli_mode(true)
        .max_retries(3)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();

    assert!(
        matches!(err, VaultError::Sealed { .. }),
        "expected Sealed, got: {err:?}"
    );
    server.verify().await;
}

#[tokio::test]
async fn without_cli_mode_sealed_is_retried() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"ok": "yes"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z",
                             "deletion_time": "", "destroyed": false}
            }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(2)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
    assert_eq!(resp.data["ok"], "yes");
}

#[tokio::test]
async fn cli_mode_sets_max_retries_zero_by_default() {
    let server = MockServer::start().await;

    // 429: without cli_mode the client would retry; with cli_mode it fails fast.
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(429))
        .expect(1)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .cli_mode(true)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();

    assert!(
        matches!(err, VaultError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );
    // Only one request — no retry
    server.verify().await;
}

proptest! {
    #[test]
    fn prop_sealed_variant_is_always_marked_retryable(url in "[a-z]{3,20}://[a-z0-9.]{3,20}") {
        // The variant's is_retryable reports true; the client's cli_mode config
        // suppresses the retry at the call site, not at the variant level.
        let err = VaultError::Sealed { url };
        prop_assert!(err.is_retryable());
    }
}

// ---------------------------------------------------------------------------
// Item 4: Better blocking-in-async error message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocking_error_message_describes_nesting() {
    let err = BlockingVaultClient::builder()
        .address("http://127.0.0.1:8200")
        .token_str("t")
        .build()
        .unwrap_err();

    match err {
        VaultError::Config(msg) => {
            assert!(
                msg.contains("nested"),
                "message should explain nesting, got: {msg}"
            );
            assert!(
                msg.contains("std::thread"),
                "message should suggest std::thread workaround, got: {msg}"
            );
        }
        other => panic!("expected Config, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Item 5: tracing warn for danger_disable_tls_verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn danger_disable_tls_verify_builds_successfully() {
    // The tracing warn is a runtime side-effect; we verify the flag is accepted.
    let server = MockServer::start().await;
    let result = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .danger_disable_tls_verify(true)
        .build();
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Item 6: FieldNotFound includes the KV mount
// ---------------------------------------------------------------------------

#[tokio::test]
async fn field_not_found_includes_mount() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/ops/kv/data/app/cfg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"host": "db.internal"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z",
                             "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("ops/kv")
        .read_field("app/cfg", "missing")
        .await
        .unwrap_err();

    match err {
        VaultError::FieldNotFound { ref mount, ref path, ref field } => {
            assert_eq!(mount, "ops/kv");
            assert_eq!(path, "app/cfg");
            assert_eq!(field, "missing");
        }
        other => panic!("expected FieldNotFound, got: {other:?}"),
    }
}

#[test]
fn field_not_found_display_contains_mount_and_path() {
    let err = VaultError::FieldNotFound {
        mount: "secret".into(),
        path: "myapp/config".into(),
        field: "passphrase".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("secret/myapp/config"),
        "display should include mount/path, got: {msg}"
    );
    assert!(
        msg.contains("passphrase"),
        "display should include field name, got: {msg}"
    );
}

#[test]
fn field_not_found_display_with_nested_mount() {
    let err = VaultError::FieldNotFound {
        mount: "ops/kv".into(),
        path: "app/cfg".into(),
        field: "token".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("ops/kv/app/cfg"),
        "nested mount should render as mount/path, got: {msg}"
    );
    assert!(msg.contains("token"), "field name should appear, got: {msg}");
}

proptest! {
    #[test]
    fn prop_field_not_found_display_always_has_mount(
        mount in "[a-z]{2,10}",
        path in "[a-z]{2,10}",
        field in "[a-z]{2,10}",
    ) {
        let err = VaultError::FieldNotFound {
            mount: mount.clone(),
            path: path.clone(),
            field: field.clone(),
        };
        let msg = err.to_string();
        prop_assert!(msg.contains(&mount));
        prop_assert!(msg.contains(&path));
        prop_assert!(msg.contains(&field));
    }
}

// ---------------------------------------------------------------------------
// Item 7: BlockingClientBuilder::from_env()
// ---------------------------------------------------------------------------

#[test]
fn blocking_builder_from_env_chains_with_overrides() {
    // Override address + token so build() succeeds regardless of env.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    let result = BlockingClientBuilder::from_env()
        .address(&server.uri())
        .token_str("tok")
        .max_retries(0)
        .build();
    assert!(result.is_ok(), "from_env().build() should succeed: {result:?}");
}

#[test]
fn blocking_builder_from_env_namespace_override() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    let result = BlockingClientBuilder::from_env()
        .address(&server.uri())
        .token_str("tok")
        .namespace("ops")
        .max_retries(0)
        .build();
    assert!(result.is_ok());
}

#[test]
fn blocking_builder_cli_mode_passthrough() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    let result = BlockingClientBuilder::from_env()
        .address(&server.uri())
        .token_str("tok")
        .cli_mode(true)
        .build();
    assert!(result.is_ok());
}
