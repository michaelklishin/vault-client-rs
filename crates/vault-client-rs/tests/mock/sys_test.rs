use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;

#[tokio::test]
async fn health_returns_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "initialized": true,
            "sealed": false,
            "standby": false,
            "version": "1.17.3",
            "cluster_name": "vault-cluster-abc",
            "cluster_id": "id-123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let health = client.sys().health().await.unwrap();
    assert!(health.initialized);
    assert!(!health.sealed);
    assert_eq!(health.version, "1.17.3");
}

#[tokio::test]
async fn seal_status_returns_seal_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "shamir",
            "initialized": true,
            "sealed": false,
            "t": 1,
            "n": 1,
            "progress": 0,
            "nonce": "",
            "version": "1.17.3"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().seal_status().await.unwrap();
    assert_eq!(status.seal_type, "shamir");
    assert!(status.initialized);
    assert!(!status.sealed);
    assert_eq!(status.t, 1);
    assert_eq!(status.n, 1);
}

#[tokio::test]
async fn list_mounts_returns_map() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "secret/": {
                    "type": "kv",
                    "description": "key/value secret storage",
                    "accessor": "kv_abc",
                    "config": {"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false},
                    "options": {"version": "2"}
                },
                "sys/": {
                    "type": "system",
                    "description": "system endpoints",
                    "accessor": "sys_abc",
                    "config": {"default_lease_ttl": 0, "max_lease_ttl": 0}
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let mounts = client.sys().list_mounts().await.unwrap();
    assert!(mounts.contains_key("secret/"));
    assert_eq!(mounts["secret/"].mount_type, "kv");
}

#[tokio::test]
async fn mount_sends_post() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/mounts/new-kv"))
        .and(body_json(serde_json::json!({
            "type": "kv",
            "description": "test mount",
            "options": {"version": "2"}
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = vault_client_rs::types::sys::MountParams {
        mount_type: "kv".to_string(),
        description: Some("test mount".into()),
        config: None,
        options: Some([("version".to_string(), "2".to_string())].into()),
    };
    client.sys().mount("new-kv", &params).await.unwrap();
}

#[tokio::test]
async fn unmount_sends_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/mounts/old-kv"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().unmount("old-kv").await.unwrap();
}

#[tokio::test]
async fn list_policies_returns_vec() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/policies/acl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["default", "root"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let policies = client.sys().list_policies().await.unwrap();
    assert_eq!(policies, vec!["default", "root"]);
}

#[tokio::test]
async fn write_policy_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/my-policy"))
        .and(body_json(
            serde_json::json!({"policy": r#"path "secret/*" { capabilities = ["read"] }"#}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let rules = r#"path "secret/*" { capabilities = ["read"] }"#;
    client.sys().write_policy("my-policy", rules).await.unwrap();
}

#[tokio::test]
async fn delete_policy_sends_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/policies/acl/my-policy"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().delete_policy("my-policy").await.unwrap();
}

#[tokio::test]
async fn enable_auth_sends_post() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/auth/approle"))
        .and(body_json(serde_json::json!({"type": "approle"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = vault_client_rs::types::sys::AuthMountParams {
        mount_type: "approle".into(),
        description: None,
        config: None,
    };
    client.sys().enable_auth("approle", &params).await.unwrap();
}

#[tokio::test]
async fn disable_auth_sends_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/auth/approle"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().disable_auth("approle").await.unwrap();
}

#[tokio::test]
async fn seal_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/seal"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().seal().await.unwrap();
}

#[tokio::test]
async fn unseal_sends_key() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/unseal"))
        .and(body_json(serde_json::json!({"key": "unseal-key"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "shamir",
            "initialized": true,
            "sealed": false,
            "t": 1,
            "n": 1,
            "progress": 0,
            "nonce": "",
            "version": "1.17.3"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client
        .sys()
        .unseal(&SecretString::from("unseal-key"))
        .await
        .unwrap();
    assert!(!status.sealed);
}

#[tokio::test]
async fn leader_returns_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/leader"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ha_enabled": true,
            "is_self": true,
            "leader_address": "https://127.0.0.1:8200",
            "leader_cluster_address": "https://127.0.0.1:8201"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let leader = client.sys().leader().await.unwrap();
    assert!(leader.ha_enabled);
    assert!(leader.is_self);
}

#[tokio::test]
async fn unwrap_posts_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(body_json(serde_json::json!({"token": "s.wrapped"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"foo": "bar"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<String, String> = client
        .sys()
        .unwrap(&SecretString::from("s.wrapped"))
        .await
        .unwrap();
    assert_eq!(data["foo"], "bar");
}

#[tokio::test]
async fn step_down_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/step-down"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().step_down().await.unwrap();
}

#[tokio::test]
async fn init_returns_keys_and_root_token() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/init"))
        .and(body_json(serde_json::json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": ["key1hex", "key2hex", "key3hex", "key4hex", "key5hex"],
            "keys_base64": ["key1b64", "key2b64", "key3b64", "key4b64", "key5b64"],
            "root_token": "s.root-token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = vault_client_rs::types::sys::InitParams {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: None,
        root_token_pgp_key: None,
        recovery_shares: None,
        recovery_threshold: None,
    };
    let resp = client.sys().init(&params).await.unwrap();
    assert_eq!(resp.keys.len(), 5);
    assert_eq!(resp.keys[0].expose_secret(), "key1hex");
    assert_eq!(resp.keys_base64.len(), 5);
    assert_eq!(resp.keys_base64[0].expose_secret(), "key1b64");
    assert_eq!(resp.root_token.expose_secret(), "s.root-token");
}

#[tokio::test]
async fn tune_mount_sends_post() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/mounts/secret/tune"))
        .and(body_json(serde_json::json!({
            "default_lease_ttl": "30m",
            "max_lease_ttl": "1h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = vault_client_rs::types::sys::MountTuneParams {
        default_lease_ttl: Some("30m".into()),
        max_lease_ttl: Some("1h".into()),
        description: None,
    };
    client.sys().tune_mount("secret", &params).await.unwrap();
}

#[tokio::test]
async fn read_mount_tune_returns_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret/tune"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "default_lease_ttl": 2764800,
                "max_lease_ttl": 2764800,
                "force_no_cache": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.sys().read_mount_tune("secret").await.unwrap();
    assert_eq!(config.default_lease_ttl, 2764800);
    assert_eq!(config.max_lease_ttl, 2764800);
}

#[tokio::test]
async fn read_auth_tune_returns_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth/token/tune"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "default_lease_ttl": 2764800,
                "max_lease_ttl": 2764800,
                "force_no_cache": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.sys().read_auth_tune("token").await.unwrap();
    assert_eq!(config.default_lease_ttl, 2764800);
}

#[tokio::test]
async fn list_auth_mounts_returns_map() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token/": {
                    "type": "token",
                    "description": "token based credentials",
                    "accessor": "auth_token_abc",
                    "config": {"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false}
                },
                "approle/": {
                    "type": "approle",
                    "description": "approle auth",
                    "accessor": "auth_approle_abc",
                    "config": {"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false}
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let mounts = client.sys().list_auth_mounts().await.unwrap();
    assert!(mounts.contains_key("token/"));
    assert_eq!(mounts["token/"].mount_type, "token");
    assert!(mounts.contains_key("approle/"));
    assert_eq!(mounts["approle/"].mount_type, "approle");
}

#[tokio::test]
async fn read_policy_returns_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/my-policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "my-policy",
                "policy": "path \"secret/*\" { capabilities = [\"read\"] }"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let policy = client.sys().read_policy("my-policy").await.unwrap();
    assert_eq!(policy.name, "my-policy");
    assert_eq!(
        policy.policy,
        "path \"secret/*\" { capabilities = [\"read\"] }"
    );
}

#[tokio::test]
async fn read_lease_returns_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/leases/lookup"))
        .and(body_json(
            serde_json::json!({"lease_id": "auth/token/create/abc123"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "auth/token/create/abc123",
                "issue_time": "2025-01-01T00:00:00Z",
                "expire_time": "2025-01-02T00:00:00Z",
                "last_renewal": null,
                "renewable": true,
                "ttl": 86400
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let lease = client
        .sys()
        .read_lease("auth/token/create/abc123")
        .await
        .unwrap();
    assert_eq!(lease.id, "auth/token/create/abc123");
    assert!(lease.renewable);
    assert_eq!(lease.ttl, 86400);
}

#[tokio::test]
async fn renew_lease_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .and(body_json(
            serde_json::json!({"lease_id": "auth/token/create/abc123", "increment": "1h"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req-123",
            "lease_id": "auth/token/create/abc123",
            "lease_duration": 3600,
            "renewable": true,
            "data": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let lease = client
        .sys()
        .renew_lease("auth/token/create/abc123", Some("1h"))
        .await
        .unwrap();
    assert_eq!(lease.lease_id, "auth/token/create/abc123");
    assert_eq!(lease.lease_duration, 3600);
    assert!(lease.renewable);
}

#[tokio::test]
async fn renew_lease_without_increment() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .and(body_json(
            serde_json::json!({"lease_id": "auth/token/create/abc123"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "lease_id": "auth/token/create/abc123",
            "lease_duration": 7200,
            "renewable": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let lease = client
        .sys()
        .renew_lease("auth/token/create/abc123", None)
        .await
        .unwrap();
    assert_eq!(lease.lease_duration, 7200);
}

#[tokio::test]
async fn revoke_lease_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/revoke"))
        .and(body_json(
            serde_json::json!({"lease_id": "auth/token/create/abc123"}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .revoke_lease("auth/token/create/abc123")
        .await
        .unwrap();
}

#[tokio::test]
async fn revoke_prefix_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/revoke-prefix/aws/creds"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().revoke_prefix("aws/creds").await.unwrap();
}

#[tokio::test]
async fn list_audit_devices_returns_map() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "file/": {
                    "type": "file",
                    "description": "file audit device",
                    "options": {"file_path": "/var/log/vault_audit.log"},
                    "path": "file/",
                    "local": false
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let devices = client.sys().list_audit_devices().await.unwrap();
    assert!(devices.contains_key("file/"));
    assert_eq!(devices["file/"].audit_type, "file");
    assert_eq!(
        devices["file/"].options["file_path"],
        "/var/log/vault_audit.log"
    );
}

#[tokio::test]
async fn enable_audit_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/audit/file-audit"))
        .and(body_json(serde_json::json!({
            "type": "file",
            "description": "file audit device",
            "options": {"file_path": "/var/log/vault_audit.log"}
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = vault_client_rs::types::sys::AuditParams {
        audit_type: "file".into(),
        description: Some("file audit device".into()),
        options: [(
            "file_path".to_string(),
            "/var/log/vault_audit.log".to_string(),
        )]
        .into(),
        local: None,
    };
    client
        .sys()
        .enable_audit("file-audit", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn disable_audit_sends_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/audit/file-audit"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().disable_audit("file-audit").await.unwrap();
}

#[tokio::test]
async fn wrap_lookup_returns_wrap_info() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/lookup"))
        .and(body_json(serde_json::json!({"token": "s.wrapped-token"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "s.wrapped-token",
                "accessor": "accessor-abc",
                "ttl": 600,
                "creation_time": "2025-01-01T00:00:00Z",
                "creation_path": "sys/wrapping/wrap"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .sys()
        .wrap_lookup(&SecretString::from("s.wrapped-token"))
        .await
        .unwrap();
    assert_eq!(info.accessor, "accessor-abc");
    assert_eq!(info.ttl, 600);
    assert_eq!(info.creation_path, "sys/wrapping/wrap");
}

#[tokio::test]
async fn capabilities_returns_map() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/capabilities"))
        .and(body_json(serde_json::json!({
            "token": "s.my-token",
            "paths": ["secret/data/foo", "secret/data/bar"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "secret/data/foo": ["read", "list"],
                "secret/data/bar": ["deny"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let caps = client
        .sys()
        .capabilities(
            &SecretString::from("s.my-token"),
            &["secret/data/foo", "secret/data/bar"],
        )
        .await
        .unwrap();
    assert_eq!(caps["secret/data/foo"], vec!["read", "list"]);
    assert_eq!(caps["secret/data/bar"], vec!["deny"]);
}

#[tokio::test]
async fn capabilities_self_returns_map() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/capabilities-self"))
        .and(body_json(serde_json::json!({
            "paths": ["secret/data/foo"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "secret/data/foo": ["read", "create", "update"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let caps = client
        .sys()
        .capabilities_self(&["secret/data/foo"])
        .await
        .unwrap();
    assert_eq!(caps["secret/data/foo"], vec!["read", "create", "update"]);
}

#[tokio::test]
async fn key_status_returns_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/key-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "term": 3,
                "install_time": "2025-01-01T00:00:00Z",
                "encryptions": 1024
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().key_status().await.unwrap();
    assert_eq!(status.term, 3);
    assert_eq!(status.install_time, "2025-01-01T00:00:00Z");
    assert_eq!(status.encryptions, Some(1024));
}

#[tokio::test]
async fn rotate_encryption_key_sends_put() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rotate"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().rotate_encryption_key().await.unwrap();
}
