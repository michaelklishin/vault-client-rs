use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::rabbitmq::*;
use vault_client_rs::types::terraform::*;
use vault_client_rs::{RabbitmqOperations, TerraformCloudOperations};

// ---------------------------------------------------------------------------
// RabbitMQ
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rabbitmq_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/rabbitmq/config/connection"))
        .and(body_json(serde_json::json!({
            "connection_uri": "amqp://guest:guest@localhost:5672",
            "username": "admin",
            "password": "secret"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RabbitmqConfigRequest {
        connection_uri: "amqp://guest:guest@localhost:5672".to_string(),
        username: "admin".to_string(),
        password: Some(SecretString::from("secret")),
        ..Default::default()
    };
    client
        .rabbitmq("rabbitmq")
        .configure(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn rabbitmq_configure_lease() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/rabbitmq/config/lease"))
        .and(body_json(serde_json::json!({
            "ttl": "1h",
            "max_ttl": "24h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .rabbitmq("rabbitmq")
        .configure_lease("1h", "24h")
        .await
        .unwrap();
}

#[tokio::test]
async fn rabbitmq_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/rabbitmq/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RabbitmqRoleRequest {
        tags: Some("administrator".to_string()),
        ..Default::default()
    };
    client
        .rabbitmq("rabbitmq")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn rabbitmq_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/rabbitmq/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "vhosts": {"/": {"write": ".*", "read": ".*"}},
                "vhost_topics": {"/": {"amq.topic": {"write": ".*", "read": ".*"}}},
                "tags": "administrator"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .rabbitmq("rabbitmq")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.tags, "administrator");
    assert!(role.vhosts.is_object());
    assert!(role.vhost_topics.is_object());
}

#[tokio::test]
async fn rabbitmq_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/rabbitmq/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .rabbitmq("rabbitmq")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn rabbitmq_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/rabbitmq/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.rabbitmq("rabbitmq").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn rabbitmq_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/rabbitmq/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "username": "root-a]fc-58a8",
                "password": "eOkIfTn3DO7uAx29ALo5"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .rabbitmq("rabbitmq")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.username, "root-a]fc-58a8");
    assert_eq!(creds.password.expose_secret(), "eOkIfTn3DO7uAx29ALo5");
}

// ---------------------------------------------------------------------------
// Terraform Cloud
// ---------------------------------------------------------------------------

#[tokio::test]
async fn terraform_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/terraform/config"))
        .and(body_json(serde_json::json!({
            "token": "my-tfc-token",
            "address": "https://app.terraform.io"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TerraformCloudConfigRequest {
        token: SecretString::from("my-tfc-token"),
        address: Some("https://app.terraform.io".to_string()),
    };
    client
        .terraform_cloud("terraform")
        .configure(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn terraform_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/terraform/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "address": "https://app.terraform.io"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client
        .terraform_cloud("terraform")
        .read_config()
        .await
        .unwrap();
    assert_eq!(config.address, "https://app.terraform.io");
}

#[tokio::test]
async fn terraform_delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/terraform/config"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .terraform_cloud("terraform")
        .delete_config()
        .await
        .unwrap();
}

#[tokio::test]
async fn terraform_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/terraform/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = TerraformCloudRoleRequest {
        organization: Some("my-org".to_string()),
        team_id: Some("team-abc123".to_string()),
        ..Default::default()
    };
    client
        .terraform_cloud("terraform")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn terraform_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/terraform/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "organization": "my-org",
                "team_id": "team-abc123",
                "user_id": "",
                "ttl": 3600,
                "max_ttl": 86400
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .terraform_cloud("terraform")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.organization, "my-org");
    assert_eq!(role.team_id, "team-abc123");
    assert_eq!(role.user_id, "");
    assert_eq!(role.ttl, 3600);
    assert_eq!(role.max_ttl, 86400);
}

#[tokio::test]
async fn terraform_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/terraform/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .terraform_cloud("terraform")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn terraform_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/terraform/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client
        .terraform_cloud("terraform")
        .list_roles()
        .await
        .unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn terraform_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/terraform/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "tfc-abc123def456",
                "token_id": "at-abc123"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .terraform_cloud("terraform")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.token.expose_secret(), "tfc-abc123def456");
    assert_eq!(creds.token_id, "at-abc123");
}
