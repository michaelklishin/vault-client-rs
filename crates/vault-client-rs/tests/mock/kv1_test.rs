use std::collections::HashMap;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::Kv1Operations;

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
