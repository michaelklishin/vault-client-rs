use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::sys::*;

#[tokio::test]
async fn list_plugins() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/plugins/catalog/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["approle", "token", "userpass"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let plugins = client.sys().list_plugins("auth").await.unwrap();
    assert_eq!(plugins, vec!["approle", "token", "userpass"]);
}

#[tokio::test]
async fn read_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/plugins/catalog/auth/approle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "approle",
                "command": "approle",
                "args": [],
                "sha256": "abc123def456",
                "version": "v1.0.0",
                "builtin": true
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.sys().read_plugin("auth", "approle").await.unwrap();
    assert_eq!(info.name, "approle");
    assert_eq!(info.command, "approle");
    assert_eq!(info.sha256, "abc123def456");
    assert!(info.builtin);
}

#[tokio::test]
async fn register_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/plugins/catalog/auth/my-plugin"))
        .and(body_json(serde_json::json!({
            "name": "my-plugin",
            "type": "auth",
            "command": "my-plugin-bin",
            "sha256": "deadbeef1234567890"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RegisterPluginRequest {
        name: "my-plugin".into(),
        plugin_type: "auth".into(),
        command: "my-plugin-bin".into(),
        sha256: "deadbeef1234567890".into(),
        args: None,
        env: None,
        version: None,
    };
    client.sys().register_plugin(&params).await.unwrap();
}

#[tokio::test]
async fn deregister_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/plugins/catalog/auth/my-plugin"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .deregister_plugin("auth", "my-plugin")
        .await
        .unwrap();
}

#[tokio::test]
async fn reload_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/plugins/reload/backend"))
        .and(body_json(serde_json::json!({"plugin": "my-plugin"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().reload_plugin("my-plugin").await.unwrap();
}

#[tokio::test]
async fn raft_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/storage/raft/configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "servers": [
                    {"node_id": "node1", "address": "10.0.0.1:8201", "leader": true, "voter": true},
                    {"node_id": "node2", "address": "10.0.0.2:8201", "leader": false, "voter": true}
                ],
                "index": 42
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.sys().raft_config().await.unwrap();
    assert_eq!(config.servers.len(), 2);
    assert_eq!(config.servers[0].node_id, "node1");
    assert!(config.servers[0].leader);
    assert_eq!(config.index, 42);
}

#[tokio::test]
async fn raft_autopilot_state() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/storage/raft/autopilot/state"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "healthy": true,
                "failure_tolerance": 1,
                "leader": "node1",
                "voters": ["node1", "node2"],
                "servers": {
                    "node1": {
                        "id": "node1",
                        "name": "node1",
                        "address": "10.0.0.1:8201",
                        "node_status": "alive",
                        "status": "leader",
                        "healthy": true,
                        "last_contact": "0s",
                        "last_index": 100,
                        "last_term": 3,
                        "voter": true,
                        "leader": true
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let state = client.sys().raft_autopilot_state().await.unwrap();
    assert!(state.healthy);
    assert_eq!(state.leader, "node1");
}

#[tokio::test]
async fn raft_remove_peer() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/storage/raft/remove-peer"))
        .and(body_json(serde_json::json!({"server_id": "node1"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().raft_remove_peer("node1").await.unwrap();
}

#[tokio::test]
async fn list_namespaces() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/namespaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["child-ns/", "another-ns/"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let namespaces = client.sys().list_namespaces().await.unwrap();
    assert_eq!(namespaces, vec!["child-ns/", "another-ns/"]);
}

#[tokio::test]
async fn create_namespace() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/namespaces/child-ns"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "ns-id-123",
                "path": "child-ns/"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let ns = client.sys().create_namespace("child-ns").await.unwrap();
    assert_eq!(ns.id, "ns-id-123");
    assert_eq!(ns.path, "child-ns/");
}

#[tokio::test]
async fn delete_namespace() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/namespaces/child-ns"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().delete_namespace("child-ns").await.unwrap();
}

#[tokio::test]
async fn list_rate_limit_quotas() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/quotas/rate-limit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-quota", "global-quota"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let quotas = client.sys().list_rate_limit_quotas().await.unwrap();
    assert_eq!(quotas, vec!["my-quota", "global-quota"]);
}

#[tokio::test]
async fn read_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "my-quota",
                "rate": 100.0,
                "burst": 200,
                "path": "",
                "interval": null,
                "block_interval": null,
                "role": null,
                "type": "rate-limit"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let quota = client
        .sys()
        .read_rate_limit_quota("my-quota")
        .await
        .unwrap();
    assert_eq!(quota.name, "my-quota");
    assert_eq!(quota.rate, 100.0);
}

#[tokio::test]
async fn write_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .and(body_json(serde_json::json!({
            "name": "my-quota",
            "rate": 50.0
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RateLimitQuotaRequest {
        name: "my-quota".into(),
        rate: 50.0,
        ..Default::default()
    };
    client
        .sys()
        .write_rate_limit_quota("my-quota", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .delete_rate_limit_quota("my-quota")
        .await
        .unwrap();
}

#[tokio::test]
async fn rekey_init() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/init"))
        .and(body_json(serde_json::json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "abc-nonce-123",
            "t": 3,
            "n": 5,
            "progress": 0,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": false,
            "keys": null,
            "keys_base64": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RekeyInitRequest {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: None,
        backup: None,
    };
    let status = client.sys().rekey_init(&params).await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "abc-nonce-123");
    assert_eq!(status.n, 5);
    assert_eq!(status.t, 3);
}

#[tokio::test]
async fn rekey_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/rekey/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": false,
            "nonce": "",
            "t": 0,
            "n": 0,
            "progress": 0,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": false,
            "keys": null,
            "keys_base64": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().rekey_status().await.unwrap();
    assert!(!status.started);
    assert_eq!(status.nonce, "");
}

#[tokio::test]
async fn rekey_cancel() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/rekey/init"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().rekey_cancel().await.unwrap();
}

#[tokio::test]
async fn generate_root_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/generate-root/attempt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "root-nonce-456",
            "progress": 1,
            "required": 3,
            "complete": false,
            "encoded_token": null,
            "encoded_root_token": null,
            "otp_length": 24,
            "otp": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().generate_root_status().await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "root-nonce-456");
    assert_eq!(status.progress, 1);
    assert_eq!(status.required, 3);
}

#[tokio::test]
async fn remount() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/remount"))
        .and(body_json(serde_json::json!({"from": "old/", "to": "new/"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "migration_id": "mig-abc-123"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().remount("old/", "new/").await.unwrap();
    assert_eq!(status.migration_id, "mig-abc-123");
}

#[tokio::test]
async fn host_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/host-info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "timestamp": "2025-06-15T10:30:00Z",
                "cpu": [{"cpu": 0, "vendorId": "GenuineIntel"}],
                "disk": null,
                "host": null,
                "memory": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.sys().host_info().await.unwrap();
    assert_eq!(info.timestamp, "2025-06-15T10:30:00Z");
    assert!(info.cpu.is_some());
}

#[tokio::test]
async fn version_history() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/version-history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "keys": ["1.16.0", "1.17.3"],
                "key_info": {
                    "1.16.0": {
                        "timestamp_installed": "2025-01-01T00:00:00Z",
                        "build_date": "2024-12-15T00:00:00Z",
                        "previous_version": null
                    },
                    "1.17.3": {
                        "timestamp_installed": "2025-06-01T00:00:00Z",
                        "build_date": "2025-05-20T00:00:00Z",
                        "previous_version": "1.16.0"
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let history = client.sys().version_history().await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version, "1.16.0");
    assert_eq!(history[1].version, "1.17.3");
}

#[tokio::test]
async fn rewrap() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/rewrap"))
        .and(body_json(serde_json::json!({"token": "s.original-wrap"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wrap_info": {
                "token": "s.new-wrap-token",
                "accessor": "acc-rewrap",
                "ttl": 300,
                "creation_time": "2025-06-15T10:30:00Z",
                "creation_path": "sys/wrapping/rewrap"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .sys()
        .rewrap(&SecretString::new("s.original-wrap".into()))
        .await
        .unwrap();
    assert_eq!(info.accessor, "acc-rewrap");
    assert_eq!(info.ttl, 300);
    assert_eq!(info.token.expose_secret(), "s.new-wrap-token");
}
