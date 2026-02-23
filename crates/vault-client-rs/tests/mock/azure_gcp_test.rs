use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::azure::*;
use vault_client_rs::types::gcp::*;
use vault_client_rs::{
    AzureAuthOperations, AzureSecretsOperations, GcpAuthOperations, GcpSecretsOperations,
};

fn auth_response_json() -> serde_json::Value {
    serde_json::json!({
        "auth": {
            "client_token": "s.newtoken",
            "accessor": "acc-new",
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
// Azure Secrets Engine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn azure_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/azure/config"))
        .and(body_json(serde_json::json!({
            "subscription_id": "sub-123",
            "tenant_id": "tenant-456",
            "client_id": "client-789",
            "client_secret": "s3cret",
            "environment": "AzurePublicCloud"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AzureConfigRequest {
        subscription_id: Some("sub-123".into()),
        tenant_id: Some("tenant-456".into()),
        client_id: Some("client-789".into()),
        client_secret: Some(SecretString::from("s3cret")),
        environment: Some("AzurePublicCloud".into()),
    };
    client
        .azure_secrets("azure")
        .configure(&params)
        .await
        .unwrap();
}

#[tokio::test]
async fn azure_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/azure/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "subscription_id": "sub-123",
                "tenant_id": "tenant-456",
                "client_id": "client-789",
                "environment": "AzurePublicCloud"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.azure_secrets("azure").read_config().await.unwrap();
    assert_eq!(config.subscription_id, "sub-123");
    assert_eq!(config.tenant_id, "tenant-456");
    assert_eq!(config.client_id, "client-789");
    assert_eq!(config.environment, "AzurePublicCloud");
}

#[tokio::test]
async fn azure_delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/azure/config"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.azure_secrets("azure").delete_config().await.unwrap();
}

#[tokio::test]
async fn azure_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/azure/roles/my-role"))
        .and(body_json(serde_json::json!({
            "azure_roles": [{"role_name": "Contributor", "scope": "/subscriptions/sub-123"}],
            "ttl": "1h",
            "max_ttl": "24h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AzureRoleRequest {
        azure_roles: Some(serde_json::json!([
            {"role_name": "Contributor", "scope": "/subscriptions/sub-123"}
        ])),
        ttl: Some("1h".into()),
        max_ttl: Some("24h".into()),
        ..Default::default()
    };
    client
        .azure_secrets("azure")
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn azure_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/azure/roles/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "azure_roles": [{"role_name": "Contributor", "scope": "/subscriptions/sub-123"}],
                "azure_groups": [],
                "application_object_id": "",
                "ttl": 3600,
                "max_ttl": 86400
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client
        .azure_secrets("azure")
        .read_role("my-role")
        .await
        .unwrap();
    assert!(role.azure_roles.is_array());
    assert_eq!(role.ttl, 3600);
    assert_eq!(role.max_ttl, 86400);
}

#[tokio::test]
async fn azure_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/azure/roles/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .azure_secrets("azure")
        .delete_role("my-role")
        .await
        .unwrap();
}

#[tokio::test]
async fn azure_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/azure/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.azure_secrets("azure").list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

#[tokio::test]
async fn azure_get_credentials() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/azure/creds/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "client_id": "app-client-id",
                "client_secret": "app-client-secret"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let creds = client
        .azure_secrets("azure")
        .get_credentials("my-role")
        .await
        .unwrap();
    assert_eq!(creds.client_id, "app-client-id");
    assert_eq!(creds.client_secret.expose_secret(), "app-client-secret");
}

// ---------------------------------------------------------------------------
// Azure Auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn azure_auth_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/azure/login"))
        .and(body_json(serde_json::json!({
            "role": "my-role",
            "jwt": "eyJhbGciOiJSUzI1NiJ9.test"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .azure()
        .login(
            "my-role",
            &SecretString::from("eyJhbGciOiJSUzI1NiJ9.test"),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
}

#[tokio::test]
async fn azure_auth_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/azure/config"))
        .and(body_json(serde_json::json!({
            "tenant_id": "tenant-456",
            "resource": "https://management.azure.com/",
            "client_id": "client-789",
            "client_secret": "auth-secret"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = AzureAuthConfigRequest {
        tenant_id: Some("tenant-456".into()),
        resource: Some("https://management.azure.com/".into()),
        client_id: Some("client-789".into()),
        client_secret: Some(SecretString::from("auth-secret")),
        environment: None,
    };
    client.auth().azure().configure(&config).await.unwrap();
}

#[tokio::test]
async fn azure_auth_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/azure/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "tenant_id": "tenant-456",
                "resource": "https://management.azure.com/",
                "environment": "AzurePublicCloud",
                "client_id": "client-789"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().azure().read_config().await.unwrap();
    assert_eq!(config.tenant_id, "tenant-456");
    assert_eq!(config.resource, "https://management.azure.com/");
    assert_eq!(config.environment, "AzurePublicCloud");
    assert_eq!(config.client_id, "client-789");
}

#[tokio::test]
async fn azure_auth_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/azure/role/my-role"))
        .and(body_json(serde_json::json!({
            "bound_service_principal_ids": ["sp-111"],
            "bound_group_ids": ["grp-222"],
            "bound_subscription_ids": ["sub-123"],
            "token_policies": ["default", "dev"],
            "token_ttl": "1h",
            "token_max_ttl": "24h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = AzureAuthRoleRequest {
        bound_service_principal_ids: Some(vec!["sp-111".into()]),
        bound_group_ids: Some(vec!["grp-222".into()]),
        bound_subscription_ids: Some(vec!["sub-123".into()]),
        token_policies: Some(vec!["default".into(), "dev".into()]),
        token_ttl: Some("1h".into()),
        token_max_ttl: Some("24h".into()),
        ..Default::default()
    };
    client
        .auth()
        .azure()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn azure_auth_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/azure/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "bound_service_principal_ids": ["sp-111"],
                "bound_group_ids": ["grp-222"],
                "bound_locations": [],
                "bound_subscription_ids": ["sub-123"],
                "bound_resource_groups": [],
                "token_ttl": 3600,
                "token_max_ttl": 86400,
                "token_policies": ["default", "dev"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.auth().azure().read_role("my-role").await.unwrap();
    assert_eq!(role.bound_service_principal_ids, vec!["sp-111"]);
    assert_eq!(role.bound_group_ids, vec!["grp-222"]);
    assert_eq!(role.bound_subscription_ids, vec!["sub-123"]);
    assert_eq!(role.token_policies, vec!["default", "dev"]);
    assert_eq!(role.token_ttl, 3600);
    assert_eq!(role.token_max_ttl, 86400);
}

#[tokio::test]
async fn azure_auth_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/azure/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().azure().delete_role("my-role").await.unwrap();
}

#[tokio::test]
async fn azure_auth_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/azure/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().azure().list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

// ---------------------------------------------------------------------------
// GCP Secrets Engine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gcp_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/gcp/config"))
        .and(body_json(serde_json::json!({
            "credentials": "{\"type\":\"service_account\"}",
            "ttl": "1h",
            "max_ttl": "24h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GcpConfigRequest {
        credentials: Some(SecretString::from("{\"type\":\"service_account\"}")),
        ttl: Some("1h".into()),
        max_ttl: Some("24h".into()),
    };
    client.gcp_secrets("gcp").configure(&params).await.unwrap();
}

#[tokio::test]
async fn gcp_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/gcp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "ttl": 3600,
                "max_ttl": 86400
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.gcp_secrets("gcp").read_config().await.unwrap();
    assert_eq!(config.ttl, 3600);
    assert_eq!(config.max_ttl, 86400);
}

#[tokio::test]
async fn gcp_delete_config() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/gcp/config"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.gcp_secrets("gcp").delete_config().await.unwrap();
}

#[tokio::test]
async fn gcp_create_roleset() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/gcp/roleset/my-roleset"))
        .and(body_json(serde_json::json!({
            "project": "my-project",
            "bindings": "resource \"//cloudresourcemanager.googleapis.com/projects/my-project\" {\n  roles = [\"roles/viewer\"]\n}",
            "secret_type": "service_account_key",
            "token_scopes": ["https://www.googleapis.com/auth/cloud-platform"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GcpRolesetRequest {
        project: Some("my-project".into()),
        bindings: Some("resource \"//cloudresourcemanager.googleapis.com/projects/my-project\" {\n  roles = [\"roles/viewer\"]\n}".into()),
        secret_type: Some("service_account_key".into()),
        token_scopes: Some(vec!["https://www.googleapis.com/auth/cloud-platform".into()]),
    };
    client
        .gcp_secrets("gcp")
        .create_roleset("my-roleset", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn gcp_read_roleset() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/gcp/roleset/my-roleset"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "project": "my-project",
                "bindings": {"//cloudresourcemanager.googleapis.com/projects/my-project": ["roles/viewer"]},
                "secret_type": "service_account_key",
                "token_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "service_account_email": "vault-my-roleset@my-project.iam.gserviceaccount.com"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roleset = client
        .gcp_secrets("gcp")
        .read_roleset("my-roleset")
        .await
        .unwrap();
    assert_eq!(roleset.project, "my-project");
    assert_eq!(roleset.secret_type, "service_account_key");
    assert_eq!(
        roleset.token_scopes,
        vec!["https://www.googleapis.com/auth/cloud-platform"]
    );
    assert_eq!(
        roleset.service_account_email,
        "vault-my-roleset@my-project.iam.gserviceaccount.com"
    );
}

#[tokio::test]
async fn gcp_delete_roleset() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/gcp/roleset/my-roleset"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .gcp_secrets("gcp")
        .delete_roleset("my-roleset")
        .await
        .unwrap();
}

#[tokio::test]
async fn gcp_list_rolesets() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/gcp/rolesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-roleset", "other-roleset"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let rolesets = client.gcp_secrets("gcp").list_rolesets().await.unwrap();
    assert_eq!(rolesets, vec!["my-roleset", "other-roleset"]);
}

#[tokio::test]
async fn gcp_get_service_account_key() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/gcp/key/my-roleset"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "private_key_data": "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50In0=",
                "key_algorithm": "KEY_ALG_RSA_2048",
                "key_type": "TYPE_GOOGLE_CREDENTIALS_FILE"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = client
        .gcp_secrets("gcp")
        .get_service_account_key("my-roleset")
        .await
        .unwrap();
    assert_eq!(
        key.private_key_data.expose_secret(),
        "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50In0="
    );
    assert_eq!(key.key_algorithm, "KEY_ALG_RSA_2048");
    assert_eq!(key.key_type, "TYPE_GOOGLE_CREDENTIALS_FILE");
}

#[tokio::test]
async fn gcp_get_oauth_token() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/gcp/token/my-roleset"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "ya29.c.abc123-fake-token",
                "expires_at_seconds": 1700000000,
                "token_ttl": 3600
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let token = client
        .gcp_secrets("gcp")
        .get_oauth_token("my-roleset")
        .await
        .unwrap();
    assert_eq!(token.token.expose_secret(), "ya29.c.abc123-fake-token");
    assert_eq!(token.expires_at_seconds, 1700000000);
    assert_eq!(token.token_ttl, 3600);
}

#[tokio::test]
async fn gcp_rotate_roleset() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/gcp/roleset/my-roleset/rotate"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .gcp_secrets("gcp")
        .rotate_roleset("my-roleset")
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// GCP Auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gcp_auth_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/gcp/login"))
        .and(body_json(serde_json::json!({
            "role": "my-role",
            "jwt": "eyJhbGciOiJSUzI1NiJ9.gcp-test"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .gcp()
        .login(
            "my-role",
            &SecretString::from("eyJhbGciOiJSUzI1NiJ9.gcp-test"),
        )
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
}

#[tokio::test]
async fn gcp_auth_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/gcp/config"))
        .and(body_json(serde_json::json!({
            "credentials": "{\"type\":\"service_account\"}",
            "iam_alias": "unique_id",
            "gce_alias": "instance_id"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = GcpAuthConfigRequest {
        credentials: Some(SecretString::from("{\"type\":\"service_account\"}")),
        iam_alias: Some("unique_id".into()),
        gce_alias: Some("instance_id".into()),
    };
    client.auth().gcp().configure(&config).await.unwrap();
}

#[tokio::test]
async fn gcp_auth_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/gcp/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "iam_alias": "unique_id",
                "gce_alias": "instance_id"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().gcp().read_config().await.unwrap();
    assert_eq!(config.iam_alias, "unique_id");
    assert_eq!(config.gce_alias, "instance_id");
}

#[tokio::test]
async fn gcp_auth_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/gcp/role/my-role"))
        .and(body_json(serde_json::json!({
            "type": "iam",
            "bound_service_accounts": ["sa@my-project.iam.gserviceaccount.com"],
            "bound_projects": ["my-project"],
            "token_policies": ["default", "dev"],
            "token_ttl": "1h",
            "token_max_ttl": "24h"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GcpAuthRoleRequest {
        role_type: "iam".into(),
        bound_service_accounts: Some(vec!["sa@my-project.iam.gserviceaccount.com".into()]),
        bound_projects: Some(vec!["my-project".into()]),
        token_policies: Some(vec!["default".into(), "dev".into()]),
        token_ttl: Some("1h".into()),
        token_max_ttl: Some("24h".into()),
        ..Default::default()
    };
    client
        .auth()
        .gcp()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn gcp_auth_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/gcp/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "type": "iam",
                "bound_service_accounts": ["sa@my-project.iam.gserviceaccount.com"],
                "bound_projects": ["my-project"],
                "bound_zones": [],
                "bound_regions": [],
                "token_ttl": 3600,
                "token_max_ttl": 86400,
                "token_policies": ["default", "dev"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.auth().gcp().read_role("my-role").await.unwrap();
    assert_eq!(role.role_type, "iam");
    assert_eq!(
        role.bound_service_accounts,
        vec!["sa@my-project.iam.gserviceaccount.com"]
    );
    assert_eq!(role.bound_projects, vec!["my-project"]);
    assert_eq!(role.token_policies, vec!["default", "dev"]);
    assert_eq!(role.token_ttl, 3600);
    assert_eq!(role.token_max_ttl, 86400);
}

#[tokio::test]
async fn gcp_auth_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/gcp/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().gcp().delete_role("my-role").await.unwrap();
}

#[tokio::test]
async fn gcp_auth_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/gcp/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().gcp().list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}
