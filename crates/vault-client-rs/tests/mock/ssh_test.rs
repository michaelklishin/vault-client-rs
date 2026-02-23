use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::SshOperations;
use vault_client_rs::types::ssh::*;

#[tokio::test]
async fn configure_ca() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/ssh/config/ca"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = SshCaConfigRequest {
        generate_signing_key: Some(true),
        private_key: None,
        public_key: None,
        key_type: Some("ssh-rsa".to_string()),
        key_bits: Some(4096),
    };
    client.ssh("ssh").configure_ca(&params).await.unwrap();
}

#[tokio::test]
async fn read_public_key() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/ssh/config/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAA..."
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let ca = client.ssh("ssh").read_public_key().await.unwrap();
    assert_eq!(ca.public_key, "ssh-rsa AAAAB3NzaC1yc2EAAAA...");
}

#[tokio::test]
async fn delete_ca() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/ssh/config/ca"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.ssh("ssh").delete_ca().await.unwrap();
}

#[tokio::test]
async fn create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/ssh/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = SshRoleRequest {
        key_type: "ca".to_string(),
        default_user: Some("ubuntu".to_string()),
        ..Default::default()
    };
    client
        .ssh("ssh")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/ssh/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "key_type": "ca",
                "default_user": "ubuntu",
                "allowed_users": "*",
                "ttl": "30m",
                "max_ttl": "24h",
                "allowed_critical_options": "",
                "allowed_extensions": "permit-pty",
                "allow_user_certificates": true,
                "allow_host_certificates": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.ssh("ssh").read_role("my-role").await.unwrap();
    assert_eq!(role.key_type, "ca");
    assert_eq!(role.default_user, "ubuntu");
    assert_eq!(role.allowed_users, "*");
    assert!(role.allow_user_certificates);
    assert!(!role.allow_host_certificates);
}

#[tokio::test]
async fn list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/ssh/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.ssh("ssh").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn sign_key() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/ssh/sign/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "serial_number": "c73f3662a...",
                "signed_key": "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2E..."
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = SshSignRequest {
        public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host".to_string(),
        valid_principals: Some("ubuntu".to_string()),
        ..Default::default()
    };
    let signed = client
        .ssh("ssh")
        .sign_key("my-role", &params)
        .await
        .unwrap();
    assert_eq!(signed.serial_number, "c73f3662a...");
    assert!(signed.signed_key.expose_secret().contains("ssh-rsa-cert"));
}

#[tokio::test]
async fn verify_otp() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/ssh/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ip": "10.0.0.5",
                "username": "ubuntu"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = SshVerifyRequest {
        otp: SecretString::from("7d2e7f0a-1234-5678-abcd-ef1234567890"),
    };
    let resp = client.ssh("ssh").verify_otp(&params).await.unwrap();
    assert_eq!(resp.ip, "10.0.0.5");
    assert_eq!(resp.username, "ubuntu");
}

#[tokio::test]
async fn delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/ssh/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.ssh("ssh").delete_role("my-role").await.unwrap();
}
