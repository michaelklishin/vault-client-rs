use std::collections::HashMap;

use vault_client_rs::types::kv::*;
use vault_client_rs::{Kv2Operations, VaultClient};

use crate::common::*;

fn client() -> VaultClient {
    build_client(&vault_addr(), vault_token())
}

// ---------------------------------------------------------------------------
// Migrated from live_test.rs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_read_delete() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-wrd");

    let data: HashMap<String, String> = [
        ("hello".into(), "world".into()),
        ("foo".into(), "bar".into()),
    ]
    .into();

    let meta = kv.write(&path, &data).await.unwrap();
    assert!(meta.version >= 1);

    let resp: KvReadResponse<HashMap<String, String>> = kv.read(&path).await.unwrap();
    assert_eq!(resp.data["hello"], "world");
    assert_eq!(resp.data["foo"], "bar");

    kv.delete_metadata(&path).await.unwrap();
    let err = kv.read::<serde_json::Value>(&path).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn list() {
    let client = client();
    let kv = client.kv2("secret");
    let prefix = unique_name("kv2-list");

    kv.write(&format!("{prefix}/a"), &serde_json::json!({"v": "1"}))
        .await
        .unwrap();
    kv.write(&format!("{prefix}/b"), &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    let keys = kv.list(&format!("{prefix}/")).await.unwrap();
    assert!(keys.contains(&"a".to_string()));
    assert!(keys.contains(&"b".to_string()));

    kv.delete_metadata(&format!("{prefix}/a")).await.unwrap();
    kv.delete_metadata(&format!("{prefix}/b")).await.unwrap();
}

#[tokio::test]
async fn versioning() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-ver");

    kv.write(&path, &serde_json::json!({"v": "1"}))
        .await
        .unwrap();
    kv.write(&path, &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    let v1: KvReadResponse<HashMap<String, String>> = kv.read_version(&path, 1).await.unwrap();
    assert_eq!(v1.data["v"], "1");

    let v2: KvReadResponse<HashMap<String, String>> = kv.read_version(&path, 2).await.unwrap();
    assert_eq!(v2.data["v"], "2");

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn metadata() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-meta");

    kv.write(&path, &serde_json::json!({"a": "b"}))
        .await
        .unwrap();

    let meta = kv.read_metadata(&path).await.unwrap();
    assert!(meta.current_version >= 1);

    kv.delete_metadata(&path).await.unwrap();
}

// ---------------------------------------------------------------------------
// New tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_cas() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-cas");

    // Initial write with CAS 0 (create)
    let meta = kv
        .write_cas(&path, &serde_json::json!({"v": "1"}), 0)
        .await
        .unwrap();
    assert_eq!(meta.version, 1);

    // CAS with correct version succeeds
    let meta2 = kv
        .write_cas(&path, &serde_json::json!({"v": "2"}), 1)
        .await
        .unwrap();
    assert_eq!(meta2.version, 2);

    // CAS with stale version fails
    let err = kv.write_cas(&path, &serde_json::json!({"v": "3"}), 1).await;
    assert!(err.is_err());

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn patch() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-patch");

    kv.write(&path, &serde_json::json!({"a": "1", "b": "2"}))
        .await
        .unwrap();

    // Patch merges — update b, add c, leave a
    let meta = kv
        .patch(&path, &serde_json::json!({"b": "updated", "c": "3"}))
        .await
        .unwrap();
    assert_eq!(meta.version, 2);

    let resp: KvReadResponse<HashMap<String, String>> = kv.read(&path).await.unwrap();
    assert_eq!(resp.data["a"], "1");
    assert_eq!(resp.data["b"], "updated");
    assert_eq!(resp.data["c"], "3");

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn delete_versions() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-delv");

    kv.write(&path, &serde_json::json!({"v": "1"}))
        .await
        .unwrap();
    kv.write(&path, &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    // Soft-delete version 1
    kv.delete_versions(&path, &[1]).await.unwrap();

    // Version 1 should show deletion_time in metadata
    let meta = kv.read_metadata(&path).await.unwrap();
    let v1_meta = meta.versions.get("1").unwrap();
    assert!(!v1_meta.deletion_time.is_empty());

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn undelete_versions() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-undel");

    kv.write(&path, &serde_json::json!({"v": "1"}))
        .await
        .unwrap();

    // Soft-delete then undelete
    kv.delete_versions(&path, &[1]).await.unwrap();
    kv.undelete_versions(&path, &[1]).await.unwrap();

    // Should be readable again
    let resp: KvReadResponse<HashMap<String, String>> = kv.read(&path).await.unwrap();
    assert_eq!(resp.data["v"], "1");

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn destroy_versions() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-dest");

    kv.write(&path, &serde_json::json!({"v": "1"}))
        .await
        .unwrap();
    kv.write(&path, &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    // Permanently destroy version 1
    kv.destroy_versions(&path, &[1]).await.unwrap();

    let meta = kv.read_metadata(&path).await.unwrap();
    let v1_meta = meta.versions.get("1").unwrap();
    assert!(v1_meta.destroyed);

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn read_subkeys() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-subk");

    kv.write(
        &path,
        &serde_json::json!({"top": {"nested": "val"}, "flat": "x"}),
    )
    .await
    .unwrap();

    // Without depth — returns full structure with null leaves
    let subkeys = kv.read_subkeys(&path, None).await.unwrap();
    assert!(subkeys.get("subkeys").is_some() || subkeys.get("top").is_some());

    // With depth=1
    let subkeys_d1 = kv.read_subkeys(&path, Some(1)).await.unwrap();
    assert!(subkeys_d1.is_object());

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn write_metadata() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-wmeta");

    kv.write(&path, &serde_json::json!({"k": "v"}))
        .await
        .unwrap();

    kv.write_metadata(
        &path,
        &KvMetadataParams {
            max_versions: Some(5),
            cas_required: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let meta = kv.read_metadata(&path).await.unwrap();
    assert_eq!(meta.max_versions, 5);
    assert!(meta.cas_required);

    kv.delete_metadata(&path).await.unwrap();
}

#[tokio::test]
async fn read_write_config() {
    let client = client();
    let kv = client.kv2("secret");

    let original = kv.read_config().await.unwrap();

    // Write a new config
    kv.write_config(&KvConfig {
        max_versions: Some(10),
        ..Default::default()
    })
    .await
    .unwrap();

    let updated = kv.read_config().await.unwrap();
    assert_eq!(updated.max_versions, Some(10));

    // Restore original
    kv.write_config(&KvConfig {
        max_versions: original.max_versions,
        cas_required: original.cas_required,
        delete_version_after: original.delete_version_after,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn soft_delete_and_read() {
    let client = client();
    let kv = client.kv2("secret");
    let path = unique_name("kv2-sdel");

    kv.write(&path, &serde_json::json!({"v": "1"}))
        .await
        .unwrap();

    // Soft-delete the latest version
    kv.delete(&path).await.unwrap();

    // Reading latest should fail
    let err = kv.read::<serde_json::Value>(&path).await;
    assert!(err.is_err());

    // Metadata should show deletion_time for v1
    let meta = kv.read_metadata(&path).await.unwrap();
    let v1 = meta.versions.get("1").unwrap();
    assert!(!v1.deletion_time.is_empty());

    kv.delete_metadata(&path).await.unwrap();
}
