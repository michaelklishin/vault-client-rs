use std::collections::HashMap;

use vault_client_rs::{Kv1Operations, VaultClient};

use crate::common::*;

#[tokio::test]
async fn write_read() {
    let client = build_client();
    let mount = mount_kv1(&client).await;

    let data: HashMap<String, String> = [("hello".into(), "world".into())].into();

    client.kv1(&mount).write("mykey", &data).await.unwrap();

    let resp: HashMap<String, String> = client.kv1(&mount).read("mykey").await.unwrap();
    assert_eq!(resp["hello"], "world");

    client.sys().unmount(&mount).await.unwrap();
}

#[tokio::test]
async fn delete() {
    let client = build_client();
    let mount = mount_kv1(&client).await;

    client
        .kv1(&mount)
        .write("delme", &serde_json::json!({"a": "b"}))
        .await
        .unwrap();

    client.kv1(&mount).delete("delme").await.unwrap();

    let err = client.kv1(&mount).read::<serde_json::Value>("delme").await;
    assert!(err.is_err());

    client.sys().unmount(&mount).await.unwrap();
}

#[tokio::test]
async fn list() {
    let client = build_client();
    let mount = mount_kv1(&client).await;

    client
        .kv1(&mount)
        .write("list/a", &serde_json::json!({"v": "1"}))
        .await
        .unwrap();
    client
        .kv1(&mount)
        .write("list/b", &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    let keys = client.kv1(&mount).list("list/").await.unwrap();
    assert!(keys.contains(&"a".to_string()));
    assert!(keys.contains(&"b".to_string()));

    client.sys().unmount(&mount).await.unwrap();
}

#[tokio::test]
async fn overwrite() {
    let client = build_client();
    let mount = mount_kv1(&client).await;

    client
        .kv1(&mount)
        .write("ow", &serde_json::json!({"v": "1"}))
        .await
        .unwrap();

    client
        .kv1(&mount)
        .write("ow", &serde_json::json!({"v": "2"}))
        .await
        .unwrap();

    let resp: HashMap<String, String> = client.kv1(&mount).read("ow").await.unwrap();
    assert_eq!(resp["v"], "2");

    client.sys().unmount(&mount).await.unwrap();
}
