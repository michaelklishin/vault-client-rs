use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{Kv1Operations, TokenAuthOperations, VaultClient};

#[tokio::test]
async fn ensure_valid_token_skipped_for_auth_endpoints() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "accessor": "acc-123",
                "creation_time": 1700000000,
                "creation_ttl": 3600,
                "display_name": "token",
                "entity_id": "ent-1",
                "expire_time": null,
                "explicit_max_ttl": 0,
                "id": "s.my-token",
                "issue_time": "2025-01-01T00:00:00Z",
                "meta": null,
                "num_uses": 0,
                "orphan": false,
                "path": "auth/token/create",
                "policies": ["default"],
                "renewable": true,
                "ttl": 3500,
                "type": "service"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // No renewal mock needed; auth endpoints bypass the token lifecycle check
    let client = VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("test-token"))
        .max_retries(0)
        .build()
        .unwrap();

    let info = client.auth().token().lookup_self().await.unwrap();
    assert_eq!(info.accessor, "acc-123");
    assert!(info.renewable);
}

#[tokio::test]
async fn request_with_valid_token_does_not_renew() {
    let server = MockServer::start().await;

    // The renewal endpoint should never be called
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "s.renewed",
                "accessor": "acc-renewed",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": null,
                "lease_duration": 7200,
                "renewable": true,
                "entity_id": "ent-1",
                "token_type": "service",
                "orphan": false,
                "mfa_requirement": null,
                "num_uses": 0
            }
        })))
        .expect(0)
        .mount(&server)
        .await;

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

    // A fresh token without lease info has no expiry, so no renewal should trigger
    let client = VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("test-token"))
        .max_retries(0)
        .build()
        .unwrap();

    let data: HashMap<String, String> = client.kv1("secret").read("my-secret").await.unwrap();
    assert_eq!(data["username"], "admin");
    assert_eq!(data["password"], "s3cret");
}

#[tokio::test]
async fn on_token_changed_fires_on_renewal() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "s.new-token",
                "accessor": "acc-new",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": null,
                "lease_duration": 7200,
                "renewable": true,
                "entity_id": "ent-1",
                "token_type": "service",
                "orphan": false,
                "mfa_requirement": null,
                "num_uses": 0
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let tokens: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cb_tokens = Arc::clone(&tokens);

    let client = VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("old-token"))
        .max_retries(0)
        .on_token_changed(move |auth| {
            cb_tokens
                .lock()
                .unwrap()
                .push(auth.client_token.expose_secret().to_string());
        })
        .build()
        .unwrap();

    // Renew the token via the auth/token/renew-self endpoint
    let renewed = client.auth().token().renew_self(None).await.unwrap();
    assert_eq!(renewed.client_token.expose_secret(), "s.new-token");

    let captured = tokens.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], "s.new-token");
}
