use std::collections::HashMap;

use secrecy::SecretString;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn kv2_response(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "data": data,
            "metadata": {
                "version": 1,
                "created_time": "2025-01-01T00:00:00Z",
                "deletion_time": "",
                "destroyed": false
            }
        }
    })
}

#[test]
fn blocking_builder_works() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build();
    assert!(client.is_ok());
}

#[test]
fn blocking_kv2_read() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(kv2_response(serde_json::json!({"foo": "bar"}))),
            )
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("test-token"))
        .max_retries(0)
        .build()
        .unwrap();

    let resp: vault_client_rs::KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").unwrap();
    assert_eq!(resp.data["foo"], "bar");
}

#[test]
fn blocking_kv2_list() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("LIST"))
            .and(path("/v1/secret/metadata/apps/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"keys": ["app1", "app2"]}
            })))
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build()
        .unwrap();

    let keys = client.kv2("secret").list("apps/").unwrap();
    assert_eq!(keys, vec!["app1", "app2"]);
}

#[test]
fn blocking_kv2_write() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/newkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "version": 1,
                    "created_time": "2025-01-01T00:00:00Z",
                    "deletion_time": "",
                    "destroyed": false
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build()
        .unwrap();

    let meta = client
        .kv2("secret")
        .write("newkey", &serde_json::json!({"hello": "world"}))
        .unwrap();
    assert_eq!(meta.version, 1);
}

#[test]
fn blocking_sys_health() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/sys/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "initialized": true,
                "sealed": false,
                "standby": false,
                "version": "1.17.3"
            })))
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build()
        .unwrap();

    let health = client.sys().health().unwrap();
    assert!(health.initialized);
}

#[test]
fn blocking_set_token() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .and(header("X-Vault-Token", "updated"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(kv2_response(serde_json::json!({"v": "1"}))),
            )
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("initial"))
        .max_retries(0)
        .build()
        .unwrap();

    client.set_token(SecretString::from("updated")).unwrap();
    let _: vault_client_rs::KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").unwrap();
}

#[test]
fn blocking_transit_encrypt() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/my-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"ciphertext": "vault:v1:abc"}
            })))
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build()
        .unwrap();

    let ct = client
        .transit("transit")
        .encrypt("my-key", &SecretString::from("plaintext"))
        .unwrap();
    assert_eq!(ct, "vault:v1:abc");
}

#[test]
fn blocking_auth_token_lookup_self() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());

    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "accessor": "acc",
                    "creation_time": 1700000000,
                    "creation_ttl": 3600,
                    "display_name": "token",
                    "entity_id": "e",
                    "expire_time": null,
                    "explicit_max_ttl": 0,
                    "id": "s.tok",
                    "issue_time": "2025-01-01T00:00:00Z",
                    "meta": null,
                    "num_uses": 0,
                    "orphan": false,
                    "path": "auth/token/create",
                    "policies": ["default"],
                    "renewable": false,
                    "ttl": 3500,
                    "type": "service"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
    });

    let client = vault_client_rs::blocking::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from("t"))
        .max_retries(0)
        .build()
        .unwrap();

    let info = client.auth().token().lookup_self().unwrap();
    assert_eq!(info.accessor, "acc");
}

#[tokio::test]
async fn blocking_builder_rejects_inside_async_runtime() {
    // Calling BlockingClientBuilder::build() inside a tokio runtime should fail
    let err = vault_client_rs::blocking::VaultClient::builder()
        .address("http://127.0.0.1:8200")
        .token(SecretString::from("t"))
        .build()
        .unwrap_err();
    match err {
        vault_client_rs::VaultError::Config(msg) => {
            assert!(
                msg.contains("tokio runtime"),
                "expected tokio runtime error, got: {msg}"
            );
        }
        other => panic!("expected Config error, got: {other:?}"),
    }
}
