use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};

use vault_client_rs::types::transit::*;
use vault_client_rs::{TransitOperations, VaultClient};

use crate::common::*;

fn client() -> VaultClient {
    build_client(&vault_addr(), vault_token())
}

/// Helper: ensure transit engine is mounted and create a named key, returning the key name
async fn create_transit_key(
    client: &VaultClient,
    prefix: &str,
    params: &TransitKeyParams,
) -> String {
    ensure_mount(client, "transit", "transit").await;
    let name = unique_name(prefix);
    client
        .transit("transit")
        .create_key(&name, params)
        .await
        .unwrap();
    name
}

/// Helper: mark key deletable and delete it
async fn cleanup_key(client: &VaultClient, name: &str) {
    let transit = client.transit("transit");
    let _ = transit
        .update_key_config(
            name,
            &TransitKeyConfig {
                deletion_allowed: Some(true),
                ..Default::default()
            },
        )
        .await;
    let _ = transit.delete_key(name).await;
}

// ---------------------------------------------------------------------------
// Migrated from live_test.rs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn encrypt_decrypt() {
    let client = client();
    let name = create_transit_key(&client, "enc", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let ct = transit
        .encrypt(&name, &SecretString::from("sensitive data"))
        .await
        .unwrap();
    assert!(ct.starts_with("vault:v1:"));

    let pt = transit.decrypt(&name, &ct).await.unwrap();
    assert_eq!(pt.expose_secret(), "sensitive data");

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn rotate_and_rewrap() {
    let client = client();
    let name = create_transit_key(&client, "rot", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let ct_v1 = transit
        .encrypt(&name, &SecretString::from("hello"))
        .await
        .unwrap();
    assert!(ct_v1.starts_with("vault:v1:"));

    transit.rotate_key(&name).await.unwrap();

    let ct_v2 = transit.rewrap(&name, &ct_v1).await.unwrap();
    assert!(ct_v2.starts_with("vault:v2:"));

    let pt = transit.decrypt(&name, &ct_v2).await.unwrap();
    assert_eq!(pt.expose_secret(), "hello");

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn hash() {
    let client = client();
    ensure_mount(&client, "transit", "transit").await;

    let sum = client
        .transit("transit")
        .hash(b"hello world", "sha2-256")
        .await
        .unwrap();
    assert!(!sum.is_empty());
}

// ---------------------------------------------------------------------------
// New tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_read_list_delete_key() {
    let client = client();
    let name = create_transit_key(&client, "crud", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let info = transit.read_key(&name).await.unwrap();
    assert_eq!(info.name, name);
    assert!(info.latest_version >= 1);

    let keys = transit.list_keys().await.unwrap();
    assert!(keys.contains(&name));

    cleanup_key(&client, &name).await;

    // After deletion, read should fail
    let err = transit.read_key(&name).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn update_key_config() {
    let client = client();
    let name = create_transit_key(&client, "cfg", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    transit
        .update_key_config(
            &name,
            &TransitKeyConfig {
                min_decryption_version: Some(1),
                min_encryption_version: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let info = transit.read_key(&name).await.unwrap();
    assert_eq!(info.min_decryption_version, 1);
    assert_eq!(info.min_encryption_version, 1);

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn batch_encrypt_decrypt() {
    let client = client();
    let name = create_transit_key(&client, "batch", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let items = vec![
        TransitBatchPlaintext {
            plaintext: SecretString::from(B64.encode("first")),
            context: None,
        },
        TransitBatchPlaintext {
            plaintext: SecretString::from(B64.encode("second")),
            context: None,
        },
    ];

    let encrypted = transit.batch_encrypt(&name, &items).await.unwrap();
    assert_eq!(encrypted.len(), 2);
    assert!(encrypted[0].ciphertext.starts_with("vault:v1:"));
    assert!(encrypted[1].ciphertext.starts_with("vault:v1:"));

    let decrypted = transit.batch_decrypt(&name, &encrypted).await.unwrap();
    assert_eq!(decrypted.len(), 2);

    let pt0 = B64
        .decode(decrypted[0].plaintext.as_ref().unwrap().expose_secret())
        .unwrap();
    assert_eq!(std::str::from_utf8(&pt0).unwrap(), "first");

    let pt1 = B64
        .decode(decrypted[1].plaintext.as_ref().unwrap().expose_secret())
        .unwrap();
    assert_eq!(std::str::from_utf8(&pt1).unwrap(), "second");

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn sign_verify_ecdsa() {
    let client = client();
    let name = create_transit_key(
        &client,
        "ecdsa",
        &TransitKeyParams {
            key_type: Some("ecdsa-p256".into()),
            ..Default::default()
        },
    )
    .await;
    let transit = client.transit("transit");

    let sig = transit
        .sign(&name, b"test message", &TransitSignParams::default())
        .await
        .unwrap();
    assert!(sig.starts_with("vault:v1:"));

    let valid = transit.verify(&name, b"test message", &sig).await.unwrap();
    assert!(valid);

    // Tampered message should fail
    let invalid = transit.verify(&name, b"wrong message", &sig).await.unwrap();
    assert!(!invalid);

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn sign_verify_rsa() {
    let client = client();
    let name = create_transit_key(
        &client,
        "rsa",
        &TransitKeyParams {
            key_type: Some("rsa-2048".into()),
            ..Default::default()
        },
    )
    .await;
    let transit = client.transit("transit");

    let sig = transit
        .sign(
            &name,
            b"rsa test",
            &TransitSignParams {
                signature_algorithm: Some("pss".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(sig.starts_with("vault:v1:"));

    let valid = transit.verify(&name, b"rsa test", &sig).await.unwrap();
    assert!(valid);

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn hmac() {
    let client = client();
    let name = create_transit_key(&client, "hmac", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let result = transit.hmac(&name, b"hmac me", "sha2-256").await.unwrap();
    assert!(result.starts_with("vault:v1:"));

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn random() {
    let client = client();
    ensure_mount(&client, "transit", "transit").await;
    let transit = client.transit("transit");

    let b64 = transit.random(32, "base64").await.unwrap();
    assert!(!b64.is_empty());

    let hex = transit.random(32, "hex").await.unwrap();
    assert!(!hex.is_empty());
    assert_ne!(b64, hex);
}

#[tokio::test]
async fn generate_data_key() {
    let client = client();
    let name = create_transit_key(&client, "dkey", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    // Plaintext variant — returns both plaintext and ciphertext
    let dk = transit.generate_data_key(&name, "plaintext").await.unwrap();
    assert!(!dk.ciphertext.is_empty());
    assert!(dk.plaintext.is_some());

    // Wrapped variant — only ciphertext
    let dk_wrapped = transit.generate_data_key(&name, "wrapped").await.unwrap();
    assert!(!dk_wrapped.ciphertext.is_empty());
    assert!(dk_wrapped.plaintext.is_none());

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn export_key() {
    let client = client();
    let name = create_transit_key(
        &client,
        "export",
        &TransitKeyParams {
            exportable: Some(true),
            ..Default::default()
        },
    )
    .await;
    let transit = client.transit("transit");

    let exported = transit
        .export_key(&name, "encryption-key", None)
        .await
        .unwrap();
    assert_eq!(exported.name, name);
    assert!(!exported.keys.is_empty());

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn backup_restore() {
    let client = client();
    let name = create_transit_key(
        &client,
        "backup",
        &TransitKeyParams {
            exportable: Some(true),
            allow_plaintext_backup: Some(true),
            ..Default::default()
        },
    )
    .await;
    let transit = client.transit("transit");

    let backup = transit.backup_key(&name).await.unwrap();
    assert!(!backup.expose_secret().is_empty());

    // Delete the key, then restore
    cleanup_key(&client, &name).await;

    transit.restore_key(&name, &backup).await.unwrap();

    // Verify restored key works
    let info = transit.read_key(&name).await.unwrap();
    assert_eq!(info.name, name);

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn trim_key() {
    let client = client();
    let name = create_transit_key(&client, "trim", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    // Rotate 3 times to get to v4
    transit.rotate_key(&name).await.unwrap();
    transit.rotate_key(&name).await.unwrap();
    transit.rotate_key(&name).await.unwrap();

    let info = transit.read_key(&name).await.unwrap();
    assert_eq!(info.latest_version, 4);

    // Set min_decryption_version so we can trim
    transit
        .update_key_config(
            &name,
            &TransitKeyConfig {
                min_decryption_version: Some(3),
                min_encryption_version: Some(3),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Trim old versions
    transit.trim_key(&name, 3).await.unwrap();

    let info_after = transit.read_key(&name).await.unwrap();
    // Keys should only have versions 3 and 4
    assert!(!info_after.keys.contains_key("1"));
    assert!(!info_after.keys.contains_key("2"));

    cleanup_key(&client, &name).await;
}

#[tokio::test]
async fn read_write_cache_config() {
    let client = client();
    ensure_mount(&client, "transit", "transit").await;
    let transit = client.transit("transit");

    let original = transit.read_cache_config().await.unwrap();

    transit.write_cache_config(500).await.unwrap();

    let updated = transit.read_cache_config().await.unwrap();
    assert_eq!(updated.size, 500);

    // Restore
    transit.write_cache_config(original.size).await.unwrap();
}

#[tokio::test]
async fn rewrap_preserves_plaintext() {
    let client = client();
    let name = create_transit_key(&client, "rwpt", &TransitKeyParams::default()).await;
    let transit = client.transit("transit");

    let original = "preserve me across rewrap";
    let ct = transit
        .encrypt(&name, &SecretString::from(original))
        .await
        .unwrap();

    transit.rotate_key(&name).await.unwrap();

    let ct_rewrapped = transit.rewrap(&name, &ct).await.unwrap();
    assert!(ct_rewrapped.starts_with("vault:v2:"));

    let pt = transit.decrypt(&name, &ct_rewrapped).await.unwrap();
    assert_eq!(pt.expose_secret(), original);

    cleanup_key(&client, &name).await;
}
