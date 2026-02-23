use std::collections::HashMap;

use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;

#[tokio::test]
async fn unwrap_str_posts_and_deserializes() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
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
    let result: HashMap<String, String> = client
        .sys()
        .unwrap_str("s.wrapped-token-123")
        .await
        .unwrap();
    assert_eq!(result.get("username").unwrap(), "admin");
    assert_eq!(result.get("password").unwrap(), "s3cret");
}

#[tokio::test]
async fn unwrap_with_secret_string_posts_and_deserializes() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "value": "42"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let token = SecretString::from("s.wrapped-token-456");
    let result: HashMap<String, String> = client.sys().unwrap(&token).await.unwrap();
    assert_eq!(result.get("value").unwrap(), "42");
}

#[tokio::test]
async fn wrap_lookup_returns_wrap_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "s.wrapped-token-789",
                "accessor": "wrap-accessor-abc",
                "ttl": 300,
                "creation_time": "2024-06-01T12:00:00Z",
                "creation_path": "secret/data/myapp",
                "wrapped_accessor": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let token = SecretString::from("s.wrapped-token-789");
    let info = client.sys().wrap_lookup(&token).await.unwrap();
    assert_eq!(info.accessor, "wrap-accessor-abc");
    assert_eq!(info.ttl, 300);
    assert_eq!(info.creation_path, "secret/data/myapp");
}
