use std::collections::HashMap;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{CircuitBreakerConfig, Kv1Operations, VaultClient, VaultError};

#[tokio::test]
async fn circuit_opens_after_threshold() {
    let server = MockServer::start().await;

    // Always return 500 to trigger retry exhaustion
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal error"]
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .circuit_breaker(CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(60),
        })
        .build()
        .unwrap();

    // First 3 requests fail normally and increment the failure counter
    for _ in 0..3 {
        let err = client.kv1("secret").read::<serde_json::Value>("test").await;
        assert!(err.is_err());
        // These should be Api errors, not CircuitOpen
        let err = err.unwrap_err();
        assert!(
            !matches!(err, VaultError::CircuitOpen),
            "expected non-circuit error, got: {err}"
        );
    }

    // The 4th request should be short-circuited
    let err = client
        .kv1("secret")
        .read::<serde_json::Value>("test")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::CircuitOpen),
        "expected CircuitOpen, got: {err}"
    );
}

#[tokio::test]
async fn circuit_resets_after_timeout() {
    let server = MockServer::start().await;

    // Start with 500 errors
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal error"]
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .circuit_breaker(CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        })
        .build()
        .unwrap();

    // Trip the circuit breaker
    for _ in 0..2 {
        let _ = client.kv1("secret").read::<serde_json::Value>("test").await;
    }

    // Circuit should be open
    let err = client
        .kv1("secret")
        .read::<serde_json::Value>("test")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::CircuitOpen));

    // Wait for reset timeout
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Replace mock with a success response
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "key": "value" }
        })))
        .mount(&server)
        .await;

    // The probe request should succeed (half-open -> closed)
    let data: HashMap<String, String> =
        client.kv1("secret").read("test").await.unwrap();
    assert_eq!(data["key"], "value");

    // Subsequent requests should also succeed
    let data2: HashMap<String, String> =
        client.kv1("secret").read("test").await.unwrap();
    assert_eq!(data2["key"], "value");
}

#[tokio::test]
async fn failed_probe_sends_circuit_back_to_open() {
    let server = MockServer::start().await;

    // Always fail to trip the circuit and fail the probe
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal error"]
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .circuit_breaker(CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        })
        .build()
        .unwrap();

    // Trip the circuit
    for _ in 0..2 {
        let _ = client.kv1("secret").read::<serde_json::Value>("test").await;
    }

    // Wait for reset timeout — circuit enters HalfOpen on next check
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Probe goes through (HalfOpen allows it) but fails — circuit back to Open
    let probe_err = client
        .kv1("secret")
        .read::<serde_json::Value>("test")
        .await
        .unwrap_err();
    assert!(
        !matches!(probe_err, VaultError::CircuitOpen),
        "probe should not be short-circuited, got: {probe_err}"
    );

    // Immediately after the failed probe, circuit is back to Open
    let err = client
        .kv1("secret")
        .read::<serde_json::Value>("test")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::CircuitOpen),
        "circuit should be open after failed probe, got: {err}"
    );
}

#[tokio::test]
async fn success_resets_failure_counter() {
    let server = MockServer::start().await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .circuit_breaker(CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(60),
        })
        .build()
        .unwrap();

    // Two failures
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["error"]
        })))
        .expect(2)
        .mount(&server)
        .await;

    for _ in 0..2 {
        let _ = client.kv1("secret").read::<serde_json::Value>("test").await;
    }

    // One success — should reset counter
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "key": "value" }
        })))
        .mount(&server)
        .await;

    let _: HashMap<String, String> =
        client.kv1("secret").read("test").await.unwrap();

    // Two more failures — counter should have been reset, so circuit stays closed
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/test"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["error"]
        })))
        .mount(&server)
        .await;

    for _ in 0..2 {
        let err = client
            .kv1("secret")
            .read::<serde_json::Value>("test")
            .await
            .unwrap_err();
        // Should NOT be CircuitOpen since counter was reset
        assert!(
            !matches!(err, VaultError::CircuitOpen),
            "circuit should still be closed"
        );
    }
}
