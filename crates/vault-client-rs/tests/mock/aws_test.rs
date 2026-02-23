use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::aws::*;
use vault_client_rs::{AwsAuthOperations, AwsSecretsOperations};

fn auth_response_json() -> serde_json::Value {
    serde_json::json!({
        "auth": {
            "client_token": "s.awstoken",
            "accessor": "acc-aws",
            "policies": ["default"],
            "token_policies": ["default"],
            "metadata": null,
            "lease_duration": 3600,
            "renewable": true,
            "entity_id": "ent-1",
            "token_type": "service",
            "orphan": false,
            "mfa_requirement": null,
            "num_uses": 0
        }
    })
}

// ---------------------------------------------------------------------------
// AWS Secrets Engine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aws_configure_root() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/aws/config/root"))
        .and(body_json(serde_json::json!({
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AwsConfigRootRequest {
        access_key: Some("AKIAIOSFODNN7EXAMPLE".into()),
        secret_key: Some(SecretString::from(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )),
        region: Some("us-east-1".into()),
        iam_endpoint: None,
        sts_endpoint: None,
        max_retries: None,
    };
    client
        .aws_secrets("aws")
        .configure_root(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn aws_read_config_root() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/aws/config/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "region": "us-east-1",
                "iam_endpoint": "https://iam.amazonaws.com",
                "sts_endpoint": "https://sts.amazonaws.com",
                "max_retries": 3
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.aws_secrets("aws").read_config_root().await.unwrap();
    assert_eq!(config.access_key, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(config.region, "us-east-1");
    assert_eq!(config.iam_endpoint, "https://iam.amazonaws.com");
    assert_eq!(config.sts_endpoint, "https://sts.amazonaws.com");
    assert_eq!(config.max_retries, 3);
}

#[tokio::test]
async fn aws_rotate_root() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/aws/config/rotate-root"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.aws_secrets("aws").rotate_root().await.unwrap();
}

#[tokio::test]
async fn aws_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/aws/roles/my-role"))
        .and(body_json(serde_json::json!({
            "credential_type": "iam_user",
            "policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AwsRoleRequest {
        credential_type: Some("iam_user".into()),
        policy_arns: Some(vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".into()]),
        ..Default::default()
    };
    client
        .aws_secrets("aws")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn aws_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/aws/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "credential_type": "iam_user",
                "role_arns": [],
                "policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                "policy_document": "",
                "iam_groups": [],
                "default_sts_ttl": 3600,
                "max_sts_ttl": 7200
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .aws_secrets("aws")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.credential_type, "iam_user");
    assert_eq!(
        role.policy_arns,
        vec!["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    );
    assert_eq!(role.default_sts_ttl, 3600);
    assert_eq!(role.max_sts_ttl, 7200);
}

#[tokio::test]
async fn aws_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/aws/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .aws_secrets("aws")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn aws_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/aws/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.aws_secrets("aws").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn aws_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/aws/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "security_token": "AQoDYXdzEJr...",
                "arn": "arn:aws:iam::123456789012:user/my-role-1234"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .aws_secrets("aws")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.access_key, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(
        creds.secret_key.expose_secret(),
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    );
    assert_eq!(
        creds.security_token.as_ref().unwrap().expose_secret(),
        "AQoDYXdzEJr..."
    );
    assert_eq!(
        creds.arn.as_deref(),
        Some("arn:aws:iam::123456789012:user/my-role-1234")
    );
}

#[tokio::test]
async fn aws_get_sts_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/aws/sts/my-role"))
        .and(body_json(serde_json::json!({
            "role_arn": "arn:aws:iam::123456789012:role/my-assumed-role",
            "ttl": "1h"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "access_key": "ASIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSTSKEY",
                "security_token": "FwoGZXIvYXdzEBY...",
                "arn": "arn:aws:sts::123456789012:assumed-role/my-assumed-role/vault-1234"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AwsStsRequest {
        role_arn: Some("arn:aws:iam::123456789012:role/my-assumed-role".into()),
        ttl: Some("1h".into()),
    };
    let creds = client
        .aws_secrets("aws")
        .get_sts_credentials("my-role", &params)
        .await
        .unwrap();
    assert_eq!(creds.access_key, "ASIAIOSFODNN7EXAMPLE");
    assert_eq!(
        creds.secret_key.expose_secret(),
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSTSKEY"
    );
    assert_eq!(
        creds.security_token.as_ref().unwrap().expose_secret(),
        "FwoGZXIvYXdzEBY..."
    );
    assert_eq!(
        creds.arn.as_deref(),
        Some("arn:aws:sts::123456789012:assumed-role/my-assumed-role/vault-1234")
    );
}

// ---------------------------------------------------------------------------
// AWS Auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aws_auth_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/login"))
        .and(body_json(serde_json::json!({
            "role": "my-role",
            "iam_http_request_method": "POST",
            "iam_request_url": "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
            "iam_request_headers": "eyJDb250ZW50LVR5cGUiOlsiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkIl19",
            "iam_request_body": "QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNQ=="
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AwsAuthLoginRequest {
        role: Some("my-role".into()),
        iam_http_request_method: Some("POST".into()),
        iam_request_url: Some("aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=".into()),
        iam_request_headers: Some(
            "eyJDb250ZW50LVR5cGUiOlsiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkIl19".into(),
        ),
        iam_request_body: Some(
            "QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNQ==".into(),
        ),
        identity: None,
        signature: None,
        pkcs7: None,
        nonce: None,
    };
    let auth = client.auth().aws().login(&params).await.unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.awstoken");
    assert_eq!(auth.accessor, "acc-aws");
}

#[tokio::test]
async fn aws_auth_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/config/client"))
        .and(body_json(serde_json::json!({
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "sts_endpoint": "https://sts.us-east-1.amazonaws.com",
            "sts_region": "us-east-1"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = AwsAuthConfigRequest {
        access_key: Some("AKIAIOSFODNN7EXAMPLE".into()),
        secret_key: Some(SecretString::from(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )),
        sts_endpoint: Some("https://sts.us-east-1.amazonaws.com".into()),
        sts_region: Some("us-east-1".into()),
        endpoint: None,
        iam_endpoint: None,
        max_retries: None,
    };
    client.auth().aws().configure(&config).await.unwrap();
}

#[tokio::test]
async fn aws_auth_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/aws/config/client"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "endpoint": "",
                "iam_endpoint": "https://iam.amazonaws.com",
                "sts_endpoint": "https://sts.us-east-1.amazonaws.com",
                "sts_region": "us-east-1",
                "max_retries": 3
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().aws().read_config().await.unwrap();
    assert_eq!(config.access_key, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(config.iam_endpoint, "https://iam.amazonaws.com");
    assert_eq!(config.sts_endpoint, "https://sts.us-east-1.amazonaws.com");
    assert_eq!(config.sts_region, "us-east-1");
    assert_eq!(config.max_retries, 3);
}

#[tokio::test]
async fn aws_auth_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/role/my-role"))
        .and(body_json(serde_json::json!({
            "auth_type": "iam",
            "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/my-iam-role"],
            "token_policies": ["prod", "dev"],
            "token_ttl": "1h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AwsAuthRoleRequest {
        auth_type: Some("iam".into()),
        bound_iam_principal_arn: Some(vec!["arn:aws:iam::123456789012:role/my-iam-role".into()]),
        token_policies: Some(vec!["prod".into(), "dev".into()]),
        token_ttl: Some("1h".into()),
        ..Default::default()
    };
    client
        .auth()
        .aws()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn aws_auth_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/aws/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "auth_type": "iam",
                "bound_ami_id": [],
                "bound_account_id": ["123456789012"],
                "bound_region": ["us-east-1"],
                "bound_iam_role_arn": [],
                "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/my-iam-role"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "token_policies": ["prod", "dev"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.auth().aws().read_role("my-role").await.unwrap();
    assert_eq!(role.auth_type, "iam");
    assert_eq!(role.bound_account_id, vec!["123456789012"]);
    assert_eq!(role.bound_region, vec!["us-east-1"]);
    assert_eq!(
        role.bound_iam_principal_arn,
        vec!["arn:aws:iam::123456789012:role/my-iam-role"]
    );
    assert_eq!(role.token_ttl, 3600);
    assert_eq!(role.token_max_ttl, 7200);
    assert_eq!(role.token_policies, vec!["prod", "dev"]);
}

#[tokio::test]
async fn aws_auth_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/aws/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().aws().delete_role("my-role").await.unwrap();
}

#[tokio::test]
async fn aws_auth_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/aws/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().aws().list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}
