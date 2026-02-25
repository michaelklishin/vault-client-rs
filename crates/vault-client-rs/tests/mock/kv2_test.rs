use std::collections::HashMap;

use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::{Kv2Operations, KvConfig, KvMetadataParams, KvReadResponse};

fn kv_metadata_json() -> serde_json::Value {
    serde_json::json!({
        "data": {
            "created_time": "2024-01-01T00:00:00Z",
            "custom_metadata": null,
            "deletion_time": "",
            "destroyed": false,
            "version": 1
        }
    })
}

// ---------------------------------------------------------------------------
// KV v2: read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_returns_data_and_metadata() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/myapp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"db_host": "db.internal", "db_port": "5432"},
                "metadata": {
                    "created_time": "2024-01-01T00:00:00Z",
                    "custom_metadata": null,
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 3
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("myapp/config").await.unwrap();
    assert_eq!(resp.data["db_host"], "db.internal");
    assert_eq!(resp.data["db_port"], "5432");
    assert_eq!(resp.metadata.version, 3);
}

// ---------------------------------------------------------------------------
// KV v2: write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_write_wraps_data_in_envelope() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/my-secret"))
        .and(body_json(serde_json::json!({
            "data": {"username": "admin", "password": "s3cret"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_metadata_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<&str, &str> = [("username", "admin"), ("password", "s3cret")].into();
    let meta = client
        .kv2("secret")
        .write("my-secret", &data)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);
}

// ---------------------------------------------------------------------------
// KV v2: write_cas
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_write_cas_includes_cas_option() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/my-secret"))
        .and(body_json(serde_json::json!({
            "options": {"cas": 3},
            "data": {"key": "value"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_metadata_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<&str, &str> = [("key", "value")].into();
    let meta = client
        .kv2("secret")
        .write_cas("my-secret", &data, 3)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);
}

// ---------------------------------------------------------------------------
// KV v2: delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_delete_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/secret/data/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.kv2("secret").delete("my-secret").await.unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: read_version (with query_param matcher)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_version_appends_query_parameter() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/my-secret"))
        .and(query_param("version", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {
                    "username": "admin",
                    "password": "s3cret"
                },
                "metadata": {
                    "created_time": "2024-01-01T00:00:00Z",
                    "custom_metadata": null,
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 2
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let resp = client
        .kv2("secret")
        .read_version::<HashMap<String, String>>("my-secret", 2)
        .await
        .unwrap();
    assert_eq!(resp.data.get("username").unwrap(), "admin");
    assert_eq!(resp.metadata.version, 2);
}

// ---------------------------------------------------------------------------
// KV v2: delete_versions (with body matcher)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_delete_versions_posts_version_list() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/delete/my-secret"))
        .and(body_json(serde_json::json!({"versions": [1, 2]})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .kv2("secret")
        .delete_versions("my-secret", &[1, 2])
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: undelete_versions (with body matcher)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_undelete_versions_posts_version_list() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/undelete/my-secret"))
        .and(body_json(serde_json::json!({"versions": [1, 2]})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .kv2("secret")
        .undelete_versions("my-secret", &[1, 2])
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: destroy_versions (with body matcher)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_destroy_versions_posts_version_list() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/destroy/my-secret"))
        .and(body_json(serde_json::json!({"versions": [1, 2]})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .kv2("secret")
        .destroy_versions("my-secret", &[1, 2])
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: read_subkeys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_subkeys_returns_structure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/subkeys/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "subkeys": {
                    "username": null,
                    "password": null,
                    "nested": {
                        "key": null
                    }
                },
                "metadata": {
                    "created_time": "2024-01-01T00:00:00Z",
                    "custom_metadata": null,
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 1
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let subkeys = client
        .kv2("secret")
        .read_subkeys("my-secret", None)
        .await
        .unwrap();
    assert!(subkeys.get("subkeys").is_some());
    assert!(subkeys.get("subkeys").unwrap().get("username").is_some());
    assert!(subkeys.get("subkeys").unwrap().get("nested").is_some());
}

#[tokio::test]
async fn kv2_read_subkeys_with_depth() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/subkeys/my-secret"))
        .and(query_param("depth", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "subkeys": {
                    "username": null,
                    "nested": null
                },
                "metadata": {
                    "created_time": "2024-01-01T00:00:00Z",
                    "custom_metadata": null,
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 1
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let subkeys = client
        .kv2("secret")
        .read_subkeys("my-secret", Some(1))
        .await
        .unwrap();
    assert!(subkeys.get("subkeys").unwrap().get("username").is_some());
}

// ---------------------------------------------------------------------------
// KV v2: config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_config_returns_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "cas_required": false,
                "max_versions": 10,
                "delete_version_after": "0s"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.kv2("secret").read_config().await.unwrap();
    assert_eq!(config.max_versions, Some(10));
}

#[tokio::test]
async fn kv2_write_config_posts_config() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/config"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = KvConfig {
        max_versions: Some(20),
        cas_required: Some(true),
        delete_version_after: None,
    };
    client.kv2("secret").write_config(&config).await.unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_read_metadata_returns_full_metadata() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "cas_required": false,
                "created_time": "2024-01-01T00:00:00Z",
                "current_version": 3,
                "delete_version_after": "0s",
                "max_versions": 0,
                "oldest_version": 1,
                "updated_time": "2024-06-01T00:00:00Z",
                "custom_metadata": null,
                "versions": {
                    "1": {"created_time": "2024-01-01T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "2": {"created_time": "2024-03-01T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "3": {"created_time": "2024-06-01T00:00:00Z", "deletion_time": "", "destroyed": false}
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let meta = client
        .kv2("secret")
        .read_metadata("my-secret")
        .await
        .unwrap();
    assert_eq!(meta.current_version, 3);
    assert_eq!(meta.versions.len(), 3);
}

#[tokio::test]
async fn kv2_write_metadata_posts_params() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/metadata/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = KvMetadataParams {
        max_versions: Some(5),
        cas_required: Some(true),
        delete_version_after: None,
        custom_metadata: None,
    };
    client
        .kv2("secret")
        .write_metadata("my-secret", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn kv2_delete_metadata_sends_delete() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/secret/metadata/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .kv2("secret")
        .delete_metadata("my-secret")
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// KV v2: patch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_patch_sends_patch_method() {
    let server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/secret/data/my-secret"))
        .and(body_json(serde_json::json!({
            "data": {"password": "new-password"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_metadata_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let data: HashMap<&str, &str> = [("password", "new-password")].into();
    let meta = client
        .kv2("secret")
        .patch("my-secret", &data)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);
}

// ---------------------------------------------------------------------------
// KV v2: patch_metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv2_patch_metadata_sends_patch_method() {
    let server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/secret/metadata/my-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = KvMetadataParams {
        max_versions: Some(10),
        cas_required: None,
        delete_version_after: None,
        custom_metadata: None,
    };
    client
        .kv2("secret")
        .patch_metadata("my-secret", &params)
        .await
        .unwrap();
}
