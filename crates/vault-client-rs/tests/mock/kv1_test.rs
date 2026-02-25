use std::collections::HashMap;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::{Kv1Operations, VaultError};

// ---------------------------------------------------------------------------
// KV v1: read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_read_returns_data() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "username": "admin",
                "password": "s3cret"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<String, String> = client.kv1("secret").read("my-secret").await.unwrap();
    assert_eq!(data.get("username").unwrap(), "admin");
    assert_eq!(data.get("password").unwrap(), "s3cret");
}

// ---------------------------------------------------------------------------
// KV v1: write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_write_posts_to_correct_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let mut data = HashMap::new();
    data.insert("username", "admin");
    data.insert("password", "s3cret");
    client
        .kv1("secret")
        .write("my-secret", &data)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// KV v1: delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_delete_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.kv1("secret").delete("my-secret").await.unwrap();
}

// ---------------------------------------------------------------------------
// KV v1: list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_list_returns_keys() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/secret/my-folder"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["key-a", "key-b", "key-c"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let keys = client.kv1("secret").list("my-folder").await.unwrap();
    assert_eq!(keys, vec!["key-a", "key-b", "key-c"]);
}

// ---------------------------------------------------------------------------
// KV v1: read_data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_read_data_returns_deserialized_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "host": "db.internal",
                "port": "5432"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<String, String> = client
        .kv1("secret")
        .read_data("my-secret")
        .await
        .unwrap();

    assert_eq!(data["host"], "db.internal");
    assert_eq!(data["port"], "5432");
}

// ---------------------------------------------------------------------------
// KV v1: read_field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_read_field_returns_single_value() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "passphrase": "hunter2",
                "hint": "animal+number"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let value = client
        .kv1("secret")
        .read_field("my-secret", "passphrase")
        .await
        .unwrap();

    assert_eq!(value, "hunter2");
}

#[tokio::test]
async fn kv1_read_field_stringifies_non_string_values() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "count": 42,
                "enabled": true,
                "nested": {"a": 1}
            }
        })))
        .expect(3)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let kv = client.kv1("secret");

    assert_eq!(kv.read_field("my-secret", "count").await.unwrap(), "42");
    assert_eq!(kv.read_field("my-secret", "enabled").await.unwrap(), "true");
    assert_eq!(
        kv.read_field("my-secret", "nested").await.unwrap(),
        r#"{"a":1}"#
    );
}

#[tokio::test]
async fn kv1_read_field_missing_field_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "host": "db.internal" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv1("secret")
        .read_field("my-secret", "nonexistent")
        .await
        .unwrap_err();

    assert!(
        matches!(err, VaultError::FieldNotFound { ref mount, ref path, ref field }
            if mount == "secret" && path == "my-secret" && field == "nonexistent"),
        "expected FieldNotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// KV v1: read_string_data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv1_read_string_data_returns_hashmap() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "host": "db.internal",
                "port": "5432"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data = client
        .kv1("secret")
        .read_string_data("my-secret")
        .await
        .unwrap();

    assert_eq!(data.len(), 2);
    assert_eq!(data["host"], "db.internal");
    assert_eq!(data["port"], "5432");
}

#[tokio::test]
async fn kv1_read_string_data_fails_for_non_string_values() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "host": "db.internal",
                "port": 5432
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv1("secret")
        .read_string_data("my-secret")
        .await
        .unwrap_err();

    match err {
        VaultError::Http(ref e) => {
            assert!(e.is_decode(), "expected a decode error, got: {e}");
        }
        other => panic!("expected Http decode error for non-string values, got: {other:?}"),
    }
}
