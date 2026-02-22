use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::PkiOperations;
use vault_client_rs::types::pki::*;

// --- CA management ---

#[tokio::test]
async fn generate_root_posts_with_generate_type_in_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
                "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
                "serial_number": "3a:b1:c2:d3:e4:f5",
                "expiration": 1893456000,
                "private_key": null,
                "private_key_type": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiRootParams {
        generate_type: "internal".to_string(),
        common_name: "My Root CA".to_string(),
        ttl: Some("87600h".to_string()),
        ..Default::default()
    };
    let cert = client.pki("pki").generate_root(&params).await.unwrap();
    assert_eq!(cert.serial_number, "3a:b1:c2:d3:e4:f5");
    assert!(cert.certificate.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn generate_root_exported_includes_private_key() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/exported"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
                "ca_chain": [],
                "serial_number": "aa:bb:cc:dd",
                "expiration": 1893456000,
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",
                "private_key_type": "rsa"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiRootParams {
        generate_type: "exported".to_string(),
        common_name: "Exported Root CA".to_string(),
        ..Default::default()
    };
    let cert = client.pki("pki").generate_root(&params).await.unwrap();
    assert!(cert.private_key.is_some());
    assert_eq!(cert.private_key_type.as_deref(), Some("rsa"));
}

// --- Roles ---

#[tokio::test]
async fn create_role_posts_to_correct_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/roles/web-server"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiRoleParams {
        allowed_domains: Some(vec!["example.com".to_string()]),
        allow_subdomains: Some(true),
        max_ttl: Some("72h".to_string()),
        ..Default::default()
    };
    client
        .pki("pki")
        .create_role("web-server", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_role_returns_role_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pki/roles/web-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ttl": "24h",
                "max_ttl": "72h",
                "allow_localhost": true,
                "allowed_domains": ["example.com"],
                "allow_bare_domains": false,
                "allow_subdomains": true,
                "allow_any_name": false,
                "enforce_hostnames": true,
                "allow_ip_sans": true,
                "server_flag": true,
                "client_flag": true,
                "key_type": "rsa",
                "key_bits": 2048,
                "generate_lease": false,
                "no_store": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.pki("pki").read_role("web-server").await.unwrap();
    assert_eq!(role.ttl, "24h");
    assert_eq!(role.max_ttl, "72h");
    assert!(role.allow_subdomains);
    assert!(!role.allow_any_name);
    assert!(role.enforce_hostnames);
    assert!(role.allow_ip_sans);
    assert!(role.server_flag);
    assert!(role.client_flag);
    assert_eq!(role.allowed_domains, vec!["example.com"]);
    assert_eq!(role.key_type, "rsa");
    assert_eq!(role.key_bits, 2048);
    assert!(!role.generate_lease);
    assert!(!role.no_store);
}

#[tokio::test]
async fn list_roles_uses_list_method() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/pki/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["web-server", "client-cert"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.pki("pki").list_roles().await.unwrap();
    assert_eq!(roles, vec!["web-server", "client-cert"]);
}

#[tokio::test]
async fn delete_role_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/pki/roles/web-server"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.pki("pki").delete_role("web-server").await.unwrap();
}

// --- Certificate issuance ---

#[tokio::test]
async fn issue_posts_to_role_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/issue/web-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nISSUED\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                "ca_chain": [
                    "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"
                ],
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",
                "private_key_type": "rsa",
                "serial_number": "11:22:33:44:55",
                "expiration": 1893456000
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiIssueParams {
        common_name: "app.example.com".to_string(),
        ttl: Some("24h".to_string()),
        ..Default::default()
    };
    let cert = client
        .pki("pki")
        .issue("web-server", &params)
        .await
        .unwrap();
    assert_eq!(cert.serial_number, "11:22:33:44:55");
    assert_eq!(cert.private_key_type, "rsa");
    assert_eq!(cert.expiration, 1893456000);
    assert!(cert.certificate.contains("ISSUED"));
}

#[tokio::test]
async fn sign_posts_csr_to_role_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/sign/web-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nSIGNED\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                "ca_chain": [],
                "serial_number": "aa:bb:cc:dd:ee",
                "expiration": 1893456000
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiSignParams {
        csr: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----"
            .to_string(),
        common_name: "signed.example.com".to_string(),
        ttl: Some("12h".to_string()),
        ..Default::default()
    };
    let cert = client.pki("pki").sign("web-server", &params).await.unwrap();
    assert_eq!(cert.serial_number, "aa:bb:cc:dd:ee");
    assert!(cert.certificate.contains("SIGNED"));
}

// --- Certificates ---

#[tokio::test]
async fn list_certs_returns_serial_numbers() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/pki/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["11:22:33:44:55", "aa:bb:cc:dd:ee"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let serials = client.pki("pki").list_certs().await.unwrap();
    assert_eq!(serials, vec!["11:22:33:44:55", "aa:bb:cc:dd:ee"]);
}

#[tokio::test]
async fn read_cert_returns_certificate_entry() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pki/cert/11:22:33:44:55"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----",
                "revocation_time": 0,
                "revocation_time_rfc3339": ""
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let entry = client.pki("pki").read_cert("11:22:33:44:55").await.unwrap();
    assert!(entry.certificate.contains("BEGIN CERTIFICATE"));
    assert_eq!(entry.revocation_time, 0);
}

// --- URLs config ---

#[tokio::test]
async fn set_urls_posts_config() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/config/urls"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = vault_client_rs::PkiUrlsConfig {
        issuing_certificates: vec!["https://vault.example.com/v1/pki/ca".into()],
        crl_distribution_points: vec!["https://vault.example.com/v1/pki/crl".into()],
        ocsp_servers: vec![],
    };
    client.pki("pki").set_urls(&config).await.unwrap();
}

#[tokio::test]
async fn read_urls_returns_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pki/config/urls"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "issuing_certificates": ["https://vault.example.com/v1/pki/ca"],
                "crl_distribution_points": ["https://vault.example.com/v1/pki/crl"],
                "ocsp_servers": []
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.pki("pki").read_urls().await.unwrap();
    assert_eq!(
        config.issuing_certificates,
        vec!["https://vault.example.com/v1/pki/ca"]
    );
    assert_eq!(
        config.crl_distribution_points,
        vec!["https://vault.example.com/v1/pki/crl"]
    );
    assert!(config.ocsp_servers.is_empty());
}

// --- Revocation / CRL ---

#[tokio::test]
async fn revoke_posts_serial_number() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/revoke"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "revocation_time": 1700000000,
                "revocation_time_rfc3339": "2023-11-14T22:13:20Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.pki("pki").revoke("11:22:33:44:55").await.unwrap();
    assert_eq!(info.revocation_time, 1700000000);
    assert_eq!(info.revocation_time_rfc3339, "2023-11-14T22:13:20Z");
}

#[tokio::test]
async fn rotate_crl_uses_post_method() {
    let server = MockServer::start().await;

    // This specifically tests that rotate_crl uses POST, not GET.
    Mock::given(method("POST"))
        .and(path("/v1/pki/crl/rotate"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.pki("pki").rotate_crl().await.unwrap();
}

// --- Issuers ---

#[tokio::test]
async fn list_issuers_uses_list_method() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/pki/issuers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["issuer-id-1", "issuer-id-2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let issuers = client.pki("pki").list_issuers().await.unwrap();
    assert_eq!(issuers, vec!["issuer-id-1", "issuer-id-2"]);
}

// --- Tidy ---

#[tokio::test]
async fn tidy_status_returns_state() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pki/tidy-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "state": "Finished",
                "error": null,
                "time_started": "2024-01-01T00:00:00Z",
                "time_finished": "2024-01-01T00:05:00Z",
                "cert_store_deleted_count": 3,
                "revoked_cert_deleted_count": 1
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.pki("pki").tidy_status().await.unwrap();
    assert_eq!(status.state, "Finished");
    assert!(status.error.is_none());
    assert_eq!(status.time_started.as_deref(), Some("2024-01-01T00:00:00Z"));
    assert_eq!(
        status.time_finished.as_deref(),
        Some("2024-01-01T00:05:00Z")
    );
    assert_eq!(status.cert_store_deleted_count, Some(3));
    assert_eq!(status.revoked_cert_deleted_count, Some(1));
}

// --- Custom mount path ---

#[tokio::test]
async fn custom_mount_path_is_used() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/custom-pki/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ttl": "48h",
                "max_ttl": "96h",
                "allow_localhost": false,
                "allowed_domains": ["custom.io"],
                "allow_bare_domains": true,
                "allow_subdomains": false,
                "allow_any_name": false,
                "enforce_hostnames": true,
                "allow_ip_sans": false,
                "server_flag": true,
                "client_flag": false,
                "key_type": "ec",
                "key_bits": 256,
                "generate_lease": false,
                "no_store": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.pki("custom-pki").read_role("my-role").await.unwrap();
    assert_eq!(role.ttl, "48h");
    assert_eq!(role.allowed_domains, vec!["custom.io"]);
    assert_eq!(role.key_type, "ec");
}

// --- Intermediate CA ---

#[tokio::test]
async fn generate_intermediate_csr_posts_with_generate_type_in_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/intermediate/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
                "private_key": null,
                "private_key_type": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiIntermediateParams {
        generate_type: "internal".to_string(),
        common_name: "My Intermediate CA".to_string(),
        ..Default::default()
    };
    let csr = client
        .pki("pki")
        .generate_intermediate_csr(&params)
        .await
        .unwrap();
    assert!(csr.csr.contains("CERTIFICATE REQUEST"));
    assert!(csr.private_key.is_none());
}

#[tokio::test]
async fn set_signed_intermediate_posts_certificate() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/intermediate/set-signed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "imported_issuers": ["issuer-id-1"],
                "imported_keys": ["key-id-1"],
                "mapping": {"issuer-id-1": "key-id-1"}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let cert = "-----BEGIN CERTIFICATE-----\nSIGNED-INTERMEDIATE\n-----END CERTIFICATE-----";
    let result = client
        .pki("pki")
        .set_signed_intermediate(cert)
        .await
        .unwrap();
    assert_eq!(
        result.imported_issuers.as_deref(),
        Some(&["issuer-id-1".to_string()][..])
    );
    assert_eq!(
        result.imported_keys.as_deref(),
        Some(&["key-id-1".to_string()][..])
    );
}

#[tokio::test]
async fn delete_root_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/pki/root"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.pki("pki").delete_root().await.unwrap();
}

// --- Issuers (read / delete) ---

#[tokio::test]
async fn read_issuer_returns_issuer_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pki/issuer/issuer-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "issuer_id": "issuer-id-1",
                "issuer_name": "my-issuer",
                "certificate": "-----BEGIN CERTIFICATE-----\nISSUER\n-----END CERTIFICATE-----",
                "ca_chain": [
                    "-----BEGIN CERTIFICATE-----\nISSUER\n-----END CERTIFICATE-----"
                ],
                "leaf_not_after_behavior": "err",
                "usage": "read-only,issuing-certificates,crl-signing"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.pki("pki").read_issuer("issuer-id-1").await.unwrap();
    assert_eq!(info.issuer_id, "issuer-id-1");
    assert_eq!(info.issuer_name.as_deref(), Some("my-issuer"));
    assert!(info.certificate.contains("ISSUER"));
    assert_eq!(info.ca_chain.len(), 1);
    assert_eq!(info.leaf_not_after_behavior, "err");
    assert!(info.usage.contains("issuing-certificates"));
}

#[tokio::test]
async fn delete_issuer_sends_delete_method() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/pki/issuer/issuer-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .pki("pki")
        .delete_issuer("issuer-id-1")
        .await
        .unwrap();
}

// --- Sign verbatim ---

#[tokio::test]
async fn sign_verbatim_posts_csr_to_sign_verbatim_path() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/sign-verbatim/web-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nVERBATIM\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                "ca_chain": [],
                "serial_number": "ff:ee:dd:cc:bb",
                "expiration": 1893456000
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----";
    let cert = client
        .pki("pki")
        .sign_verbatim("web-server", csr)
        .await
        .unwrap();
    assert_eq!(cert.serial_number, "ff:ee:dd:cc:bb");
    assert!(cert.certificate.contains("VERBATIM"));
    assert_eq!(cert.expiration, 1893456000);
}

// --- Revoke with key ---

#[tokio::test]
async fn revoke_with_key_posts_serial_and_private_key() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/revoke-with-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "revocation_time": 1700000000,
                "revocation_time_rfc3339": "2023-11-14T22:13:20Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let private_key = SecretString::new(
        "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----".into(),
    );
    let info = client
        .pki("pki")
        .revoke_with_key("11:22:33:44:55", &private_key)
        .await
        .unwrap();
    assert_eq!(info.revocation_time, 1700000000);
    assert_eq!(info.revocation_time_rfc3339, "2023-11-14T22:13:20Z");
}

// --- Tidy ---

#[tokio::test]
async fn tidy_posts_params() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/tidy"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = PkiTidyParams {
        tidy_cert_store: Some(true),
        tidy_revoked_certs: Some(true),
        safety_buffer: Some("72h".to_string()),
    };
    client.pki("pki").tidy(&params).await.unwrap();
}
