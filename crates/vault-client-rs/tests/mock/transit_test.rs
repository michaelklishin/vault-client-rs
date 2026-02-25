use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::transit::*;
use vault_client_rs::{TransitOperations, VaultError};

#[tokio::test]
async fn create_key_posts_to_correct_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/my-key"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TransitKeyParams {
        key_type: Some("aes256-gcm96".to_string()),
        ..Default::default()
    };
    client
        .transit("transit")
        .create_key("my-key", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_key_returns_key_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "aes256-gcm96",
                "deletion_allowed": false,
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "keys": {"1": "2025-01-01T00:00:00Z"},
                "min_decryption_version": 1,
                "min_encryption_version": 0,
                "name": "my-key",
                "supports_encryption": true,
                "supports_decryption": true,
                "supports_derivation": true,
                "supports_signing": false,
                "latest_version": 1
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.transit("transit").read_key("my-key").await.unwrap();
    assert_eq!(info.name, "my-key");
    assert_eq!(info.key_type, "aes256-gcm96");
    assert!(info.supports_encryption);
}

#[tokio::test]
async fn list_keys_uses_list_method() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/transit/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["key1", "key2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let keys = client.transit("transit").list_keys().await.unwrap();
    assert_eq!(keys, vec!["key1", "key2"]);
}

#[tokio::test]
async fn encrypt_base64_encodes_plaintext() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/my-key"))
        .and(body_json(serde_json::json!({"plaintext": "aGVsbG8="})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"ciphertext": "vault:v1:abcdef"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let ct = client
        .transit("transit")
        .encrypt("my-key", &SecretString::from("hello"))
        .await
        .unwrap();
    assert_eq!(ct, "vault:v1:abcdef");
}

#[tokio::test]
async fn decrypt_base64_decodes_plaintext() {
    let server = MockServer::start().await;

    // "hello" in base64 is "aGVsbG8="
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/my-key"))
        .and(body_json(
            serde_json::json!({"ciphertext": "vault:v1:abcdef"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"plaintext": "aGVsbG8="}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let pt = client
        .transit("transit")
        .decrypt("my-key", "vault:v1:abcdef")
        .await
        .unwrap();
    assert_eq!(secrecy::ExposeSecret::expose_secret(&pt), "hello");
}

#[tokio::test]
async fn rewrap_returns_new_ciphertext() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/rewrap/my-key"))
        .and(body_json(
            serde_json::json!({"ciphertext": "vault:v1:oldct"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"ciphertext": "vault:v2:newct"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let ct = client
        .transit("transit")
        .rewrap("my-key", "vault:v1:oldct")
        .await
        .unwrap();
    assert_eq!(ct, "vault:v2:newct");
}

#[tokio::test]
async fn rotate_key_posts_to_rotate_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/my-key/rotate"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .transit("transit")
        .rotate_key("my-key")
        .await
        .unwrap();
}

#[tokio::test]
async fn hash_returns_sum() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/hash"))
        .and(body_json(
            serde_json::json!({"input": "aGVsbG8=", "algorithm": "sha2-256"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"sum": "vault:sha2-256:abc123"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let sum = client
        .transit("transit")
        .hash(b"hello", "sha2-256")
        .await
        .unwrap();
    assert_eq!(sum, "vault:sha2-256:abc123");
}

#[tokio::test]
async fn random_returns_bytes() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/random"))
        .and(body_json(
            serde_json::json!({"bytes": 32, "format": "base64"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"random_bytes": "dGVzdA=="}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let rand = client
        .transit("transit")
        .random(32, "base64")
        .await
        .unwrap();
    assert_eq!(rand, "dGVzdA==");
}

#[tokio::test]
async fn sign_sends_base64_input() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/my-key"))
        .and(body_partial_json(
            serde_json::json!({"input": "ZGF0YSB0byBzaWdu"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"signature": "vault:v1:MEUCIQDx..."}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let sig = client
        .transit("transit")
        .sign("my-key", b"data to sign", &TransitSignParams::default())
        .await
        .unwrap();
    assert!(sig.starts_with("vault:v1:"));
}

#[tokio::test]
async fn verify_returns_valid_flag() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/verify/my-key"))
        .and(body_json(
            serde_json::json!({"input": "ZGF0YQ==", "signature": "vault:v1:sig"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"valid": true}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let valid = client
        .transit("transit")
        .verify("my-key", b"data", "vault:v1:sig")
        .await
        .unwrap();
    assert!(valid);
}

#[tokio::test]
async fn delete_key_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/transit/keys/my-key"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .transit("transit")
        .delete_key("my-key")
        .await
        .unwrap();
}

#[tokio::test]
async fn custom_mount_path_is_used() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/my-transit/keys/testkey"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "aes256-gcm96",
                "deletion_allowed": false,
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "keys": {"1": "2025-01-01T00:00:00Z"},
                "min_decryption_version": 1,
                "min_encryption_version": 0,
                "name": "testkey",
                "supports_encryption": true,
                "supports_decryption": true,
                "supports_derivation": true,
                "supports_signing": false,
                "latest_version": 1
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .transit("my-transit")
        .read_key("testkey")
        .await
        .unwrap();
    assert_eq!(info.name, "testkey");
}

#[tokio::test]
async fn update_key_config_posts_to_config_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/my-key/config"))
        .and(body_partial_json(serde_json::json!({
            "deletion_allowed": true,
            "min_decryption_version": 2
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let cfg = TransitKeyConfig {
        deletion_allowed: Some(true),
        min_decryption_version: Some(2),
        ..Default::default()
    };
    client
        .transit("transit")
        .update_key_config("my-key", &cfg)
        .await
        .unwrap();
}

#[tokio::test]
async fn export_key_returns_exported_key() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transit/export/encryption-key/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "my-key",
                "keys": {"1": "dGVzdGtleQ=="},
                "type": "aes256-gcm96"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let exported = client
        .transit("transit")
        .export_key("my-key", "encryption-key", None)
        .await
        .unwrap();
    assert_eq!(exported.name, "my-key");
    assert_eq!(exported.key_type, "aes256-gcm96");
    assert_eq!(exported.keys.len(), 1);
    assert_eq!(exported.keys["1"].expose_secret(), "dGVzdGtleQ==");
}

#[tokio::test]
async fn export_key_with_version() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transit/export/encryption-key/my-key/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "my-key",
                "keys": {"2": "dmVyc2lvbjI="},
                "type": "aes256-gcm96"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let exported = client
        .transit("transit")
        .export_key("my-key", "encryption-key", Some(2))
        .await
        .unwrap();
    assert_eq!(exported.keys.len(), 1);
    assert_eq!(exported.keys["2"].expose_secret(), "dmVyc2lvbjI=");
}

#[tokio::test]
async fn batch_encrypt_returns_ciphertexts() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/my-key"))
        .and(body_json(serde_json::json!({
            "batch_input": [
                {"plaintext": "aGVsbG8="},
                {"plaintext": "d29ybGQ="}
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "batch_results": [
                    {"ciphertext": "vault:v1:ct1"},
                    {"ciphertext": "vault:v1:ct2"}
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items = vec![
        TransitBatchPlaintext {
            plaintext: SecretString::from("aGVsbG8="),
            context: None,
        },
        TransitBatchPlaintext {
            plaintext: SecretString::from("d29ybGQ="),
            context: None,
        },
    ];
    let results = client
        .transit("transit")
        .batch_encrypt("my-key", &items)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].ciphertext, "vault:v1:ct1");
    assert_eq!(results[1].ciphertext, "vault:v1:ct2");
}

#[tokio::test]
async fn batch_decrypt_returns_plaintexts() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/my-key"))
        .and(body_json(serde_json::json!({
            "batch_input": [
                {"ciphertext": "vault:v1:ct1"},
                {"ciphertext": "vault:v1:ct2"}
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "batch_results": [
                    {"plaintext": "aGVsbG8="},
                    {"plaintext": "d29ybGQ="}
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items: Vec<TransitBatchCiphertext> = serde_json::from_value(serde_json::json!([
        {"ciphertext": "vault:v1:ct1"},
        {"ciphertext": "vault:v1:ct2"}
    ]))
    .unwrap();
    let results = client
        .transit("transit")
        .batch_decrypt("my-key", &items)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].plaintext.as_ref().unwrap().expose_secret(),
        "aGVsbG8="
    );
    assert_eq!(
        results[1].plaintext.as_ref().unwrap().expose_secret(),
        "d29ybGQ="
    );
}

#[tokio::test]
async fn hmac_returns_hmac_value() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/hmac/my-key"))
        .and(body_json(
            serde_json::json!({"input": "aGVsbG8=", "algorithm": "sha2-256"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"hmac": "vault:v1:hmacvalue123"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let hmac = client
        .transit("transit")
        .hmac("my-key", b"hello", "sha2-256")
        .await
        .unwrap();
    assert_eq!(hmac, "vault:v1:hmacvalue123");
}

#[tokio::test]
async fn generate_data_key_returns_key() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/plaintext/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ciphertext": "vault:v1:encrypteddatakey",
                "plaintext": "dGVzdGRhdGFrZXk="
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let dk = client
        .transit("transit")
        .generate_data_key("my-key", "plaintext")
        .await
        .unwrap();
    assert_eq!(dk.ciphertext, "vault:v1:encrypteddatakey");
    assert_eq!(
        dk.plaintext.as_ref().unwrap().expose_secret(),
        "dGVzdGRhdGFrZXk="
    );
}

#[tokio::test]
async fn generate_data_key_wrapped_has_no_plaintext() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/wrapped/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ciphertext": "vault:v1:wrappeddatakey"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let dk = client
        .transit("transit")
        .generate_data_key("my-key", "wrapped")
        .await
        .unwrap();
    assert_eq!(dk.ciphertext, "vault:v1:wrappeddatakey");
    assert!(dk.plaintext.is_none());
}

#[tokio::test]
async fn trim_key_posts_min_version() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/my-key/trim"))
        .and(body_json(serde_json::json!({"min_available_version": 3})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .transit("transit")
        .trim_key("my-key", 3)
        .await
        .unwrap();
}

#[tokio::test]
async fn backup_key_returns_backup_string() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transit/backup/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"backup": "base64encodedbackupdata"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let backup = client
        .transit("transit")
        .backup_key("my-key")
        .await
        .unwrap();
    assert_eq!(backup.expose_secret(), "base64encodedbackupdata");
}

#[tokio::test]
async fn restore_key_posts_backup_data() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/restore/my-key"))
        .and(body_json(
            serde_json::json!({"backup": "base64encodedbackupdata"}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .transit("transit")
        .restore_key("my-key", &SecretString::from("base64encodedbackupdata"))
        .await
        .unwrap();
}

#[tokio::test]
async fn read_cache_config_returns_size() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/transit/cache-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"size": 500}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.transit("transit").read_cache_config().await.unwrap();
    assert_eq!(config.size, 500);
}

#[tokio::test]
async fn write_cache_config_posts_size() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/cache-config"))
        .and(body_json(serde_json::json!({"size": 1000})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .transit("transit")
        .write_cache_config(1000)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Batch decrypt with per-item error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_decrypt_handles_per_item_errors() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "batch_results": [
                    {"plaintext": "aGVsbG8="},
                    {"error": "encryption key version is disallowed"}
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items: Vec<TransitBatchCiphertext> = serde_json::from_value(serde_json::json!([
        {"ciphertext": "vault:v1:ct1"},
        {"ciphertext": "vault:v1:ct_bad"}
    ]))
    .unwrap();
    let results = client
        .transit("transit")
        .batch_decrypt("my-key", &items)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    // First item: successful decrypt
    assert_eq!(
        results[0].plaintext.as_ref().unwrap().expose_secret(),
        "aGVsbG8="
    );
    assert!(results[0].error.is_empty());
    // Second item: error, no plaintext
    assert!(results[1].plaintext.is_none());
    assert_eq!(results[1].error, "encryption key version is disallowed");
}

#[tokio::test]
async fn decrypt_invalid_base64_returns_error() {
    let server = MockServer::start().await;

    // Vault returns plaintext that isn't valid base64
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"plaintext": "!!!not-base64!!!"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .transit("transit")
        .decrypt("my-key", "vault:v1:ct")
        .await
        .unwrap_err();
    match err {
        VaultError::Config(msg) => {
            assert!(msg.contains("base64"), "expected base64 error, got: {msg}");
        }
        other => panic!("expected Config error, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Batch sign
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_sign_posts_batch_input_with_params() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/my-key"))
        .and(body_partial_json(serde_json::json!({
            "hash_algorithm": "sha2-256",
            "batch_input": [
                {"input": "aGVsbG8="},
                {"input": "d29ybGQ="}
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "batch_results": [
                    {"signature": "vault:v1:sig1"},
                    {"signature": "vault:v1:sig2"}
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items = vec![
        TransitBatchSignInput {
            input: "aGVsbG8=".to_string(),
            context: None,
        },
        TransitBatchSignInput {
            input: "d29ybGQ=".to_string(),
            context: None,
        },
    ];
    let params = TransitSignParams {
        hash_algorithm: Some("sha2-256".to_string()),
        ..Default::default()
    };
    let results = client
        .transit("transit")
        .batch_sign("my-key", &items, &params)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].signature, "vault:v1:sig1");
    assert_eq!(results[1].signature, "vault:v1:sig2");
    assert!(results[0].error.is_empty());
}

// ---------------------------------------------------------------------------
// Batch verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_verify_posts_batch_input() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/transit/verify/my-key"))
        .and(body_json(serde_json::json!({
            "batch_input": [
                {"input": "aGVsbG8=", "signature": "vault:v1:sig1"},
                {"input": "d29ybGQ=", "signature": "vault:v1:sig2"}
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "batch_results": [
                    {"valid": true},
                    {"valid": false}
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items = vec![
        TransitBatchVerifyInput {
            input: "aGVsbG8=".to_string(),
            signature: "vault:v1:sig1".to_string(),
            context: None,
        },
        TransitBatchVerifyInput {
            input: "d29ybGQ=".to_string(),
            signature: "vault:v1:sig2".to_string(),
            context: None,
        },
    ];
    let results = client
        .transit("transit")
        .batch_verify("my-key", &items)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].valid);
    assert!(!results[1].valid);
    assert!(results[0].error.is_empty());
    assert!(results[1].error.is_empty());
}
