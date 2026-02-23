use std::collections::HashMap;

use serde::Deserialize;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{KvReadResponse, VaultClient, VaultError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kv2_read_response(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "data": data,
            "metadata": {
                "created_time": "2024-01-01T00:00:00Z",
                "custom_metadata": null,
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        }
    })
}

async fn build_client_with_token(server: &MockServer, token: &str) -> VaultClient {
    VaultClient::builder()
        .address(&server.uri())
        .token_str(token)
        .max_retries(0)
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// kv2::read_data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_data_returns_deserialized_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "db_host": "db.internal",
                "db_port": "5432"
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let data: HashMap<String, String> = client
        .kv2("secret")
        .read_data("myapp/config")
        .await
        .unwrap();

    assert_eq!(data["db_host"], "db.internal");
    assert_eq!(data["db_port"], "5432");
}

#[derive(Debug, Deserialize, PartialEq)]
struct DbConfig {
    db_host: String,
    db_port: u16,
}

#[tokio::test]
async fn kv2_read_data_deserializes_typed_struct() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "db_host": "db.internal",
                "db_port": 5432
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let config: DbConfig = client.kv2("secret").read_data("myapp/db").await.unwrap();

    assert_eq!(
        config,
        DbConfig {
            db_host: "db.internal".into(),
            db_port: 5432,
        }
    );
}

#[tokio::test]
async fn kv2_read_data_not_found_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let err = client
        .kv2("secret")
        .read_data::<HashMap<String, String>>("missing")
        .await
        .unwrap_err();

    assert!(
        matches!(err, VaultError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// ClientBuilder::token_str
// ---------------------------------------------------------------------------

#[tokio::test]
async fn builder_token_str_authenticates() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/hello"))
        .and(header("X-Vault-Token", "my-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "greeting": "world"
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "my-token").await;
    let data: HashMap<String, String> = client.kv2("secret").read_data("hello").await.unwrap();

    assert_eq!(data["greeting"], "world");
}

// ---------------------------------------------------------------------------
// kv2::read_field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_field_returns_single_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "db_host": "db.internal",
                "db_port": "5432"
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let value = client
        .kv2("secret")
        .read_field("myapp/config", "db_host")
        .await
        .unwrap();

    assert_eq!(value, "db.internal");
}

#[tokio::test]
async fn kv2_read_field_missing_field_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "db_host": "db.internal"
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let err = client
        .kv2("secret")
        .read_field("myapp/config", "nonexistent")
        .await
        .unwrap_err();

    assert!(
        matches!(err, VaultError::FieldNotFound { ref path, ref field }
            if path == "myapp/config" && field == "nonexistent"),
        "expected FieldNotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// kv2::read_field — non-string values
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_field_stringifies_non_string_values() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/mixed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "count": 42,
                "enabled": true,
                "nested": {"a": 1}
            }),
        )))
        .expect(3)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let kv = client.kv2("secret");

    assert_eq!(kv.read_field("myapp/mixed", "count").await.unwrap(), "42");
    assert_eq!(
        kv.read_field("myapp/mixed", "enabled").await.unwrap(),
        "true"
    );
    assert_eq!(
        kv.read_field("myapp/mixed", "nested").await.unwrap(),
        r#"{"a":1}"#
    );
}

// ---------------------------------------------------------------------------
// kv2::write_field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_write_field_sends_single_key() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/myapp/single"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "data": { "api_key": "secret123" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "created_time": "2024-01-01T00:00:00Z",
                "custom_metadata": null,
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let meta = client
        .kv2("secret")
        .write_field("myapp/single", "api_key", "secret123")
        .await
        .unwrap();

    assert_eq!(meta.version, 1);
}

// ---------------------------------------------------------------------------
// kv2::read_string_data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_string_data_returns_hashmap() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv2_read_response(
            serde_json::json!({
                "db_host": "db.internal",
                "db_port": "5432"
            }),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client_with_token(&server, "test-token").await;
    let data = client
        .kv2("secret")
        .read_string_data("myapp/config")
        .await
        .unwrap();

    assert_eq!(data.len(), 2);
    assert_eq!(data["db_host"], "db.internal");
    assert_eq!(data["db_port"], "5432");
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

mod prop {
    use super::*;
    use proptest::prelude::*;
    use vault_client_rs::Kv2Operations;

    proptest! {
        #[test]
        fn prop_read_data_matches_read(
            key in "[a-z]{1,8}",
            value in "[a-zA-Z0-9]{1,16}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server = MockServer::start().await;
                let payload = serde_json::json!({ &key: &value });

                Mock::given(method("GET"))
                    .and(path("/v1/secret/data/prop-key"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(kv2_read_response(payload)),
                    )
                    .expect(2)
                    .mount(&server)
                    .await;

                let client = build_client_with_token(&server, "t").await;
                let kv = client.kv2("secret");

                let full: KvReadResponse<HashMap<String, String>> =
                    kv.read("prop-key").await.unwrap();
                let data_only: HashMap<String, String> =
                    kv.read_data("prop-key").await.unwrap();

                prop_assert_eq!(full.data, data_only);
                Ok(())
            })?;
        }

        #[test]
        fn prop_read_field_matches_read_data(
            key in "[a-z]{1,8}",
            value in "[a-zA-Z0-9]{1,16}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server = MockServer::start().await;
                let payload = serde_json::json!({ &key: &value });

                Mock::given(method("GET"))
                    .and(path("/v1/secret/data/prop-field"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(kv2_read_response(payload)),
                    )
                    .expect(2)
                    .mount(&server)
                    .await;

                let client = build_client_with_token(&server, "t").await;
                let kv = client.kv2("secret");

                let data: HashMap<String, String> =
                    kv.read_data("prop-field").await.unwrap();
                let field_val = kv.read_field("prop-field", &key).await.unwrap();

                prop_assert_eq!(&data[&key], &field_val);
                Ok(())
            })?;
        }

        #[test]
        fn prop_token_str_round_trips(token in "[a-zA-Z0-9\\-._~]{1,64}") {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server = MockServer::start().await;

                Mock::given(method("GET"))
                    .and(path("/v1/secret/data/probe"))
                    .and(header("X-Vault-Token", token.as_str()))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(kv2_read_response(serde_json::json!({"ok": "1"}))),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;

                let client = build_client_with_token(&server, &token).await;
                let data: HashMap<String, String> =
                    client.kv2("secret").read_data("probe").await.unwrap();

                prop_assert_eq!(&data["ok"], "1");
                Ok(())
            })?;
        }
    }
}
