use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::consul::*;
use vault_client_rs::types::nomad::*;
use vault_client_rs::types::totp::*;
use vault_client_rs::{ConsulOperations, NomadOperations, TotpOperations};

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn totp_create_key_generated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/totp/keys/my-key"))
        .and(body_json(serde_json::json!({
            "generate": true,
            "issuer": "Vault",
            "account_name": "user@example.com"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "barcode": "iVBORw0KGgo...",
                "url": "otpauth://totp/Vault:user@example.com?secret=ABCDEF&issuer=Vault"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TotpKeyRequest {
        generate: true,
        issuer: Some("Vault".to_string()),
        account_name: Some("user@example.com".to_string()),
        exported: None,
        key_size: None,
        url: None,
        key: None,
        period: None,
        algorithm: None,
        digits: None,
        skew: None,
        qr_size: None,
    };
    let resp = client
        .totp("totp")
        .create_key("my-key", &params)
        .await
        .unwrap();
    let generated = resp.unwrap();
    assert_eq!(
        generated.barcode.as_ref().map(|s| s.expose_secret()),
        Some("iVBORw0KGgo...")
    );
    assert!(
        generated
            .url
            .as_ref()
            .unwrap()
            .expose_secret()
            .contains("otpauth://")
    );
}

#[tokio::test]
async fn totp_create_key_manual() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/totp/keys/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TotpKeyRequest {
        key: Some(SecretString::from("JBSWY3DPEHPK3PXP")),
        issuer: Some("Vault".to_string()),
        account_name: Some("user@example.com".to_string()),
        generate: false,
        exported: None,
        key_size: None,
        url: None,
        period: None,
        algorithm: None,
        digits: None,
        skew: None,
        qr_size: None,
    };
    let resp = client
        .totp("totp")
        .create_key("my-key", &params)
        .await
        .unwrap();
    assert!(resp.is_none());
}

#[tokio::test]
async fn totp_read_key() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/totp/keys/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "account_name": "user@example.com",
                "algorithm": "SHA1",
                "digits": 6,
                "issuer": "Vault",
                "period": 30
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = client.totp("totp").read_key("my-key").await.unwrap();
    assert_eq!(key.account_name, "user@example.com");
    assert_eq!(key.algorithm, "SHA1");
    assert_eq!(key.digits, 6);
    assert_eq!(key.issuer, "Vault");
    assert_eq!(key.period, 30);
}

#[tokio::test]
async fn totp_delete_key() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/totp/keys/my-key"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.totp("totp").delete_key("my-key").await.unwrap();
}

#[tokio::test]
async fn totp_list_keys() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/totp/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-key", "other-key"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let keys = client.totp("totp").list_keys().await.unwrap();
    assert_eq!(keys, vec!["my-key", "other-key"]);
}

#[tokio::test]
async fn totp_generate_code() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/totp/code/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "code": "123456"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let code = client.totp("totp").generate_code("my-key").await.unwrap();
    assert_eq!(code.code.expose_secret(), "123456");
}

#[tokio::test]
async fn totp_validate_code() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/totp/code/my-key"))
        .and(body_json(serde_json::json!({
            "code": "123456"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "valid": true
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let result = client
        .totp("totp")
        .validate_code("my-key", "123456")
        .await
        .unwrap();
    assert!(result.valid);
}

// ---------------------------------------------------------------------------
// Consul
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consul_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/consul/config/access"))
        .and(body_json(serde_json::json!({
            "address": "127.0.0.1:8500",
            "scheme": "http",
            "token": "consul-management-token"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = ConsulConfigRequest {
        address: "127.0.0.1:8500".to_string(),
        scheme: Some("http".to_string()),
        token: Some(SecretString::from("consul-management-token")),
    };
    client
        .consul_secrets("consul")
        .configure(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn consul_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/consul/config/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "address": "127.0.0.1:8500",
                "scheme": "http"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.consul_secrets("consul").read_config().await.unwrap();
    assert_eq!(config.address, "127.0.0.1:8500");
    assert_eq!(config.scheme, "http");
}

#[tokio::test]
async fn consul_delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/consul/config/access"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .consul_secrets("consul")
        .delete_config()
        .await
        .unwrap();
}

#[tokio::test]
async fn consul_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/consul/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = ConsulRoleRequest {
        consul_policies: Some(vec!["readonly".to_string()]),
        ttl: Some("1h".to_string()),
        max_ttl: Some("24h".to_string()),
        ..Default::default()
    };
    client
        .consul_secrets("consul")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn consul_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/consul/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "consul_policies": ["readonly"],
                "consul_roles": [],
                "service_identities": [],
                "node_identities": [],
                "ttl": 3600,
                "max_ttl": 86400,
                "local": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .consul_secrets("consul")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.consul_policies, vec!["readonly"]);
    assert!(role.consul_roles.is_empty());
    assert_eq!(role.ttl, 3600);
    assert_eq!(role.max_ttl, 86400);
    assert!(!role.local);
}

#[tokio::test]
async fn consul_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/consul/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .consul_secrets("consul")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn consul_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/consul/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.consul_secrets("consul").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn consul_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/consul/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "c6a16b6e-f7c4-4c4a-b9f0-a9a8c2e3f4d5"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .consul_secrets("consul")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(
        creds.token.expose_secret(),
        "c6a16b6e-f7c4-4c4a-b9f0-a9a8c2e3f4d5"
    );
}

// ---------------------------------------------------------------------------
// Nomad
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nomad_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/nomad/config/access"))
        .and(body_json(serde_json::json!({
            "address": "http://127.0.0.1:4646",
            "token": "nomad-management-token",
            "max_token_name_length": 256
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = NomadConfigRequest {
        address: "http://127.0.0.1:4646".to_string(),
        token: Some(SecretString::from("nomad-management-token")),
        max_token_name_length: Some(256),
    };
    client
        .nomad_secrets("nomad")
        .configure(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn nomad_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/nomad/config/access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "address": "http://127.0.0.1:4646",
                "max_token_name_length": 256
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.nomad_secrets("nomad").read_config().await.unwrap();
    assert_eq!(config.address, "http://127.0.0.1:4646");
    assert_eq!(config.max_token_name_length, 256);
}

#[tokio::test]
async fn nomad_delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/nomad/config/access"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.nomad_secrets("nomad").delete_config().await.unwrap();
}

#[tokio::test]
async fn nomad_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/nomad/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = NomadRoleRequest {
        policies: Some(vec!["readonly".to_string()]),
        token_type: Some("client".to_string()),
        global: Some(false),
    };
    client
        .nomad_secrets("nomad")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn nomad_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/nomad/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "policies": ["readonly"],
                "type": "client",
                "global": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .nomad_secrets("nomad")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.policies, vec!["readonly"]);
    assert_eq!(role.token_type, "client");
    assert!(!role.global);
}

#[tokio::test]
async fn nomad_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/nomad/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .nomad_secrets("nomad")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn nomad_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/nomad/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.nomad_secrets("nomad").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn nomad_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/nomad/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "secret_id": "abc123-secret-nomad-token",
                "accessor_id": "def456-accessor-id"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .nomad_secrets("nomad")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.secret_id.expose_secret(), "abc123-secret-nomad-token");
    assert_eq!(creds.accessor_id, "def456-accessor-id");
}
