use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::DatabaseOperations;
use vault_client_rs::types::database::*;

#[tokio::test]
async fn configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/database/config/my-db"))
        .and(body_json(serde_json::json!({
            "plugin_name": "mysql-database-plugin",
            "connection_url": "{{username}}:{{password}}@tcp(127.0.0.1:3306)/"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = DatabaseConfigRequest {
        plugin_name: "mysql-database-plugin".to_string(),
        connection_url: SecretString::from("{{username}}:{{password}}@tcp(127.0.0.1:3306)/"),
        allowed_roles: None,
        username: None,
        password: None,
        max_open_connections: None,
        max_idle_connections: None,
        max_connection_lifetime: None,
        username_template: None,
        verify_connection: None,
    };
    client
        .database("database")
        .configure("my-db", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/database/config/my-db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "plugin_name": "mysql-database-plugin",
                "connection_details": {
                    "connection_url": "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
                    "username": "vaultuser"
                },
                "allowed_roles": ["my-role"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client
        .database("database")
        .read_config("my-db")
        .await
        .unwrap();
    assert_eq!(config.plugin_name, "mysql-database-plugin");
    assert_eq!(config.allowed_roles, vec!["my-role"]);
    assert!(config.connection_details.is_object());
}

#[tokio::test]
async fn delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/database/config/my-db"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .database("database")
        .delete_config("my-db")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_connections() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/database/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-db", "other-db"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let connections = client
        .database("database")
        .list_connections()
        .await
        .unwrap();
    assert_eq!(connections, vec!["my-db", "other-db"]);
}

#[tokio::test]
async fn reset_connection() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/database/reset/my-db"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .database("database")
        .reset_connection("my-db")
        .await
        .unwrap();
}

#[tokio::test]
async fn create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/database/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = DatabaseRoleRequest {
        db_name: "my-db".to_string(),
        creation_statements: Some(vec![
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';".to_string(),
        ]),
        ..Default::default()
    };
    client
        .database("database")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/database/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "db_name": "my-db",
                "creation_statements": ["CREATE USER ..."],
                "revocation_statements": [],
                "rollback_statements": [],
                "renew_statements": [],
                "default_ttl": 3600,
                "max_ttl": 86400
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .database("database")
        .read_role("my-role")
        .await
        .unwrap();
    assert_eq!(role.db_name, "my-db");
    assert_eq!(role.creation_statements, vec!["CREATE USER ..."]);
    assert_eq!(role.default_ttl, 3600);
    assert_eq!(role.max_ttl, 86400);
}

#[tokio::test]
async fn list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/database/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.database("database").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/database/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "username": "v-token-my-role-abc123",
                "password": "A1B2c3d4-e5f6"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .database("database")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.username.expose_secret(), "v-token-my-role-abc123");
    assert_eq!(creds.password.expose_secret(), "A1B2c3d4-e5f6");
}

#[tokio::test]
async fn create_static_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/database/static-roles/my-static"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = DatabaseStaticRoleRequest {
        db_name: "my-db".to_string(),
        username: "static-user".to_string(),
        rotation_period: Some("86400".to_string()),
        ..Default::default()
    };
    client
        .database("database")
        .create_static_role("my-static", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn get_static_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/database/static-creds/my-static"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "username": "static-user",
                "password": "Z9Y8x7w6",
                "last_vault_rotation": "2024-01-01T00:00:00Z",
                "rotation_period": 86400,
                "ttl": 43100
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .database("database")
        .get_static_credentials("my-static")
        .await
        .unwrap();
    assert_eq!(creds.username.expose_secret(), "static-user");
    assert_eq!(creds.password.expose_secret(), "Z9Y8x7w6");
    assert_eq!(creds.rotation_period, 86400);
    assert_eq!(creds.ttl, 43100);
}

#[tokio::test]
async fn rotate_static_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/database/rotate-role/my-static"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .database("database")
        .rotate_static_role("my-static")
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/database/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .database("database")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn read_static_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/database/static-roles/my-static"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "db_name": "my-db",
                "username": "static-user",
                "rotation_statements": ["ALTER USER ..."],
                "rotation_period": 86400,
                "last_vault_rotation": "2024-01-01T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .database("database")
        .read_static_role("my-static")
        .await
        .unwrap();
    assert_eq!(role.db_name, "my-db");
    assert_eq!(role.username, "static-user");
    assert_eq!(role.rotation_period, 86400);
}

#[tokio::test]
async fn delete_static_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/database/static-roles/my-static"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .database("database")
        .delete_static_role("my-static")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_static_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/database/static-roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-static", "other-static"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client
        .database("database")
        .list_static_roles()
        .await
        .unwrap();
    assert_eq!(roles, vec!["my-static", "other-static"]);
}
