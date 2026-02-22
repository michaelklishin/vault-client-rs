use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::auth::*;
use vault_client_rs::{
    AppRoleAuthOperations, K8sAuthOperations, Kv2Operations, TokenAuthOperations,
};

fn auth_response_json() -> serde_json::Value {
    serde_json::json!({
        "auth": {
            "client_token": "s.newtoken",
            "accessor": "acc-new",
            "policies": ["default"],
            "token_policies": ["default"],
            "metadata": null,
            "lease_duration": 3600,
            "renewable": true,
            "entity_id": "ent-1",
            "token_type": "service",
            "orphan": false,
            "mfa_requirement": null,
            "num_uses": 0
        }
    })
}

// ---------------------------------------------------------------------------
// Token auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_lookup_self() {
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
                "id": "s.mytoken",
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

    let client = build_test_client(&server).await;
    let info = client.auth().token().lookup_self().await.unwrap();
    assert_eq!(info.accessor, "acc-123");
    assert_eq!(info.policies, vec!["default"]);
    assert!(info.renewable);
}

#[tokio::test]
async fn token_create_returns_auth_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/create"))
        .and(body_json(
            serde_json::json!({"policies": ["default"], "ttl": "1h"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();
    assert_eq!(auth.accessor, "acc-new");
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
}

#[tokio::test]
async fn token_revoke_self() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/revoke-self"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().token().revoke_self().await.unwrap();
}

#[tokio::test]
async fn token_revoke_accessor() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/revoke-accessor"))
        .and(body_json(serde_json::json!({"accessor": "acc-123"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .token()
        .revoke_accessor("acc-123")
        .await
        .unwrap();
}

#[tokio::test]
async fn token_list_accessors() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/token/accessors"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["acc-1", "acc-2", "acc-3"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let accessors = client.auth().token().list_accessors().await.unwrap();
    assert_eq!(accessors.len(), 3);
}

// ---------------------------------------------------------------------------
// AppRole auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approle_login_updates_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(
            serde_json::json!({"role_id": "role-id", "secret_id": "secret-id"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .approle()
        .login("role-id", &SecretString::new("secret-id".into()))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
}

#[tokio::test]
async fn approle_login_at_custom_mount() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/my-approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .approle_at("my-approle")
        .login("role-id", &SecretString::new("secret-id".into()))
        .await
        .unwrap();
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn approle_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/role/my-role"))
        .and(body_json(
            serde_json::json!({"token_policies": ["default"]}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AppRoleCreateRequest {
        token_policies: Some(vec!["default".into()]),
        ..Default::default()
    };
    client
        .auth()
        .approle()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn approle_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/approle/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "bind_secret_id": true,
                "secret_id_bound_cidrs": [],
                "token_bound_cidrs": [],
                "token_policies": ["default"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "token_num_uses": 0,
                "token_type": "default"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.auth().approle().read_role("my-role").await.unwrap();
    assert!(info.bind_secret_id);
    assert_eq!(info.token_policies, vec!["default"]);
}

#[tokio::test]
async fn approle_read_role_id() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/approle/role/my-role/role-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"role_id": "role-id-123"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role_id = client
        .auth()
        .approle()
        .read_role_id("my-role")
        .await
        .unwrap();
    assert_eq!(role_id, "role-id-123");
}

#[tokio::test]
async fn approle_generate_secret_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/role/my-role/secret-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "secret_id": "s.mysecret",
                "secret_id_accessor": "acc-secret",
                "secret_id_num_uses": 0,
                "secret_id_ttl": 0
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let resp = client
        .auth()
        .approle()
        .generate_secret_id("my-role")
        .await
        .unwrap();
    assert_eq!(resp.secret_id.expose_secret(), "s.mysecret");
    assert_eq!(resp.secret_id_accessor, "acc-secret");
}

#[tokio::test]
async fn approle_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/approle/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .approle()
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn approle_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/approle/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["role-a", "role-b"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().approle().list_roles().await.unwrap();
    assert_eq!(roles, vec!["role-a", "role-b"]);
}

#[tokio::test]
async fn approle_destroy_secret_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/role/my-role/secret-id/destroy"))
        .and(body_json(serde_json::json!({"secret_id": "sec"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .approle()
        .destroy_secret_id("my-role", &SecretString::new("sec".into()))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Kubernetes auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn k8s_login_returns_auth_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .and(body_json(serde_json::json!({"role": "my-role", "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .kubernetes()
        .login(
            "my-role",
            &SecretString::new("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake".into()),
        )
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn k8s_configure_posts_to_config_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/config"))
        .and(body_json(serde_json::json!({
            "kubernetes_host": "https://k8s.example.com:6443",
            "kubernetes_ca_cert": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = K8sAuthConfigRequest {
        kubernetes_host: "https://k8s.example.com:6443".into(),
        kubernetes_ca_cert: Some(
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".into(),
        ),
        ..Default::default()
    };
    client.auth().kubernetes().configure(&config).await.unwrap();
}

#[tokio::test]
async fn k8s_create_role_posts_to_role_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/role/my-role"))
        .and(body_json(serde_json::json!({
            "bound_service_account_names": ["vault-auth"],
            "bound_service_account_namespaces": ["default"],
            "token_policies": ["my-policy"],
            "token_ttl": "1h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = K8sAuthRoleRequest {
        bound_service_account_names: vec!["vault-auth".into()],
        bound_service_account_namespaces: vec!["default".into()],
        token_policies: Some(vec!["my-policy".into()]),
        token_ttl: Some("1h".into()),
        ..Default::default()
    };
    client
        .auth()
        .kubernetes()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn k8s_read_role_returns_role_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/kubernetes/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "bound_service_account_names": ["vault-auth"],
                "bound_service_account_namespaces": ["default"],
                "token_policies": ["my-policy"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "token_type": "default"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .auth()
        .kubernetes()
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.bound_service_account_names, vec!["vault-auth"]);
    assert_eq!(role.bound_service_account_namespaces, vec!["default"]);
    assert_eq!(role.token_policies, vec!["my-policy"]);
    assert_eq!(role.token_ttl, 3600);
    assert_eq!(role.token_max_ttl, 7200);
}

#[tokio::test]
async fn k8s_delete_role_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/kubernetes/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .kubernetes()
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn k8s_list_roles_returns_keys() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/kubernetes/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["role-a", "role-b"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().kubernetes().list_roles().await.unwrap();
    assert_eq!(roles, vec!["role-a", "role-b"]);
}

// ---------------------------------------------------------------------------
// Token auth: create_orphan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_create_orphan_returns_auth_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/create-orphan"))
        .and(body_json(
            serde_json::json!({"policies": ["default"], "ttl": "2h"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("2h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create_orphan(&params).await.unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

// ---------------------------------------------------------------------------
// Token auth: lookup by token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_lookup_posts_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/lookup"))
        .and(body_json(serde_json::json!({"token": "s.targettoken"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "accessor": "acc-456",
                "creation_time": 1700000000,
                "creation_ttl": 7200,
                "display_name": "token",
                "entity_id": "ent-2",
                "expire_time": null,
                "explicit_max_ttl": 0,
                "id": "s.targettoken",
                "issue_time": "2025-01-01T00:00:00Z",
                "meta": null,
                "num_uses": 0,
                "orphan": false,
                "path": "auth/token/create",
                "policies": ["default", "admin"],
                "renewable": true,
                "ttl": 7100,
                "type": "service"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .auth()
        .token()
        .lookup(&SecretString::new("s.targettoken".into()))
        .await
        .unwrap();
    assert_eq!(info.accessor, "acc-456");
    assert_eq!(info.policies, vec!["default", "admin"]);
    assert!(info.renewable);
    assert_eq!(info.id.expose_secret(), "s.targettoken");
}

// ---------------------------------------------------------------------------
// Token auth: renew_self
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_renew_self_returns_auth_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client.auth().token().renew_self(Some("1h")).await.unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
    assert!(auth.renewable);
    assert_eq!(auth.lease_duration, 3600);
}

// ---------------------------------------------------------------------------
// Token auth: revoke by token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_revoke_posts_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/revoke"))
        .and(body_json(serde_json::json!({"token": "s.targettoken"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .token()
        .revoke(&SecretString::new("s.targettoken".into()))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Token auto-update: verify login updates the client's internal token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approle_login_updates_internal_token() {
    let server = MockServer::start().await;

    // Step 1: Mock the AppRole login endpoint
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    // Step 2: Mock a subsequent request that expects the NEW token
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/test"))
        .and(header("X-Vault-Token", "s.newtoken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"verified": "true"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;

    // Login should update the internal token from "test-token" to "s.newtoken"
    client
        .auth()
        .approle()
        .login("role-id", &SecretString::new("secret-id".into()))
        .await
        .unwrap();

    // This request should use the new token "s.newtoken"
    let resp: vault_client_rs::KvReadResponse<std::collections::HashMap<String, String>> =
        client.kv2("secret").read("test").await.unwrap();
    assert_eq!(resp.data["verified"], "true");
}

#[tokio::test]
async fn k8s_login_updates_internal_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/after-k8s"))
        .and(header("X-Vault-Token", "s.newtoken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"ok": "yes"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;

    client
        .auth()
        .kubernetes()
        .login("my-role", &SecretString::new("fake-jwt".into()))
        .await
        .unwrap();

    let resp: vault_client_rs::KvReadResponse<std::collections::HashMap<String, String>> =
        client.kv2("secret").read("after-k8s").await.unwrap();
    assert_eq!(resp.data["ok"], "yes");
}
