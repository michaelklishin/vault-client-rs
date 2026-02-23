use secrecy::{ExposeSecret, SecretString};

use vault_client_rs::types::auth::*;
use vault_client_rs::{AppRoleAuthOperations, K8sAuthOperations, TokenAuthOperations, VaultClient};

use crate::common::*;

fn client() -> VaultClient {
    build_client(&vault_addr(), vault_token())
}

// ---------------------------------------------------------------------------
// Migrated from live_test.rs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_lookup_self() {
    let client = client();
    let info = client.auth().token().lookup_self().await.unwrap();
    assert!(info.policies.contains(&"root".to_string()));
}

#[tokio::test]
async fn token_create_and_revoke() {
    let client = client();

    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();
    assert!(!auth.client_token.expose_secret().is_empty());

    client
        .auth()
        .token()
        .revoke(&auth.client_token)
        .await
        .unwrap();
}

#[tokio::test]
async fn approle_full_workflow() {
    let client = client();
    ensure_auth(&client, "approle", "approle").await;

    let role_name = unique_name("arole");
    let approle = client.auth().approle();

    approle
        .create_role(
            &role_name,
            &AppRoleCreateRequest {
                token_policies: Some(vec!["default".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let role_id = approle.read_role_id(&role_name).await.unwrap();
    assert!(!role_id.is_empty());

    let secret = approle.generate_secret_id(&role_name).await.unwrap();
    assert!(!secret.secret_id.expose_secret().is_empty());

    // Login with a fresh client
    let addr = vault_addr();
    let login_client = VaultClient::builder()
        .address(&addr)
        .token(SecretString::from("placeholder"))
        .max_retries(0)
        .build()
        .unwrap();

    let auth = login_client
        .auth()
        .approle()
        .login(&role_id, &secret.secret_id)
        .await
        .unwrap();
    assert!(!auth.client_token.expose_secret().is_empty());

    // Cleanup
    approle.delete_role(&role_name).await.unwrap();
}

// ---------------------------------------------------------------------------
// New token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_lookup() {
    let client = client();

    // Create a token, then look it up
    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();

    let info = client
        .auth()
        .token()
        .lookup(&auth.client_token)
        .await
        .unwrap();
    assert!(info.policies.contains(&"default".to_string()));
    assert_eq!(info.token_type, "service");

    client
        .auth()
        .token()
        .revoke(&auth.client_token)
        .await
        .unwrap();
}

#[tokio::test]
async fn token_create_orphan() {
    let client = client();

    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create_orphan(&params).await.unwrap();
    assert!(auth.orphan);
    assert!(!auth.client_token.expose_secret().is_empty());

    client
        .auth()
        .token()
        .revoke(&auth.client_token)
        .await
        .unwrap();
}

#[tokio::test]
async fn token_revoke_accessor() {
    let client = client();

    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();
    let accessor = auth.accessor.clone();

    client
        .auth()
        .token()
        .revoke_accessor(&accessor)
        .await
        .unwrap();

    // Looking up the revoked token should fail
    let err = client.auth().token().lookup(&auth.client_token).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn token_list_accessors() {
    let client = client();

    let accessors = client.auth().token().list_accessors().await.unwrap();
    // At minimum the root token's accessor should be present
    assert!(!accessors.is_empty());
}

#[tokio::test]
async fn token_renew_self() {
    let client = client();

    // Create a renewable token
    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        renewable: Some(true),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();

    // Build a client with the new token
    let addr = vault_addr();
    let renewable_client = VaultClient::builder()
        .address(&addr)
        .token(auth.client_token.clone())
        .max_retries(0)
        .build()
        .unwrap();

    let renewed = renewable_client
        .auth()
        .token()
        .renew_self(Some("2h"))
        .await
        .unwrap();
    assert!(renewed.renewable);
    assert!(!renewed.client_token.expose_secret().is_empty());

    client
        .auth()
        .token()
        .revoke(&auth.client_token)
        .await
        .unwrap();
}

#[tokio::test]
async fn token_revoke_self() {
    let client = client();

    let params = TokenCreateRequest {
        policies: Some(vec!["default".into()]),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    let auth = client.auth().token().create(&params).await.unwrap();

    // Build a client with the new token and revoke itself
    let addr = vault_addr();
    let self_client = VaultClient::builder()
        .address(&addr)
        .token(auth.client_token.clone())
        .max_retries(0)
        .build()
        .unwrap();

    self_client.auth().token().revoke_self().await.unwrap();

    // The token should now be invalid
    let err = client.auth().token().lookup(&auth.client_token).await;
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// New approle tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approle_read_role() {
    let client = client();
    ensure_auth(&client, "approle", "approle").await;

    let name = unique_name("arrole");
    let approle = client.auth().approle();

    approle
        .create_role(
            &name,
            &AppRoleCreateRequest {
                token_policies: Some(vec!["default".into()]),
                token_ttl: Some("1h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let info = approle.read_role(&name).await.unwrap();
    assert!(info.token_policies.contains(&"default".to_string()));

    approle.delete_role(&name).await.unwrap();
}

#[tokio::test]
async fn approle_list_roles() {
    let client = client();
    ensure_auth(&client, "approle", "approle").await;

    let name = unique_name("arlst");
    let approle = client.auth().approle();

    approle
        .create_role(
            &name,
            &AppRoleCreateRequest {
                token_policies: Some(vec!["default".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let roles = approle.list_roles().await.unwrap();
    assert!(roles.contains(&name));

    approle.delete_role(&name).await.unwrap();
}

#[tokio::test]
async fn approle_destroy_secret_id() {
    let client = client();
    ensure_auth(&client, "approle", "approle").await;

    let name = unique_name("ardst");
    let approle = client.auth().approle();

    approle
        .create_role(
            &name,
            &AppRoleCreateRequest {
                token_policies: Some(vec!["default".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let secret = approle.generate_secret_id(&name).await.unwrap();

    // Destroy the secret ID
    approle
        .destroy_secret_id(&name, &secret.secret_id)
        .await
        .unwrap();

    // Login with destroyed secret should fail
    let role_id = approle.read_role_id(&name).await.unwrap();
    let addr = vault_addr();
    let login_client = VaultClient::builder()
        .address(&addr)
        .token(SecretString::from("placeholder"))
        .max_retries(0)
        .build()
        .unwrap();

    let err = login_client
        .auth()
        .approle()
        .login(&role_id, &secret.secret_id)
        .await;
    assert!(err.is_err());

    approle.delete_role(&name).await.unwrap();
}

// ---------------------------------------------------------------------------
// Kubernetes auth tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn k8s_configure() {
    let client = client();
    let path = unique_name("k8s");
    ensure_auth(&client, &path, "kubernetes").await;

    client
        .auth()
        .kubernetes_at(&path)
        .configure(&K8sAuthConfigRequest {
            kubernetes_host: "https://kubernetes.default.svc".into(),
            disable_local_ca_jwt: Some(true),
            kubernetes_ca_cert: None,
            token_reviewer_jwt: None,
        })
        .await
        .unwrap();

    client.sys().disable_auth(&path).await.unwrap();
}

#[tokio::test]
async fn k8s_role_crud() {
    let client = client();
    let path = unique_name("k8sr");
    ensure_auth(&client, &path, "kubernetes").await;

    // Must configure first
    client
        .auth()
        .kubernetes_at(&path)
        .configure(&K8sAuthConfigRequest {
            kubernetes_host: "https://kubernetes.default.svc".into(),
            disable_local_ca_jwt: Some(true),
            kubernetes_ca_cert: None,
            token_reviewer_jwt: None,
        })
        .await
        .unwrap();

    let k8s = client.auth().kubernetes_at(&path);
    let role = unique_name("k8role");

    k8s.create_role(
        &role,
        &K8sAuthRoleRequest {
            bound_service_account_names: vec!["default".into()],
            bound_service_account_namespaces: vec!["default".into()],
            token_policies: Some(vec!["default".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let info = k8s.read_role(&role).await.unwrap();
    assert!(
        info.bound_service_account_names
            .contains(&"default".to_string())
    );

    let roles = k8s.list_roles().await.unwrap();
    assert!(roles.contains(&role));

    k8s.delete_role(&role).await.unwrap();

    client.sys().disable_auth(&path).await.unwrap();
}

#[tokio::test]
async fn approle_login_at_custom_mount() {
    let client = client();
    let mount = unique_name("arcust");
    ensure_auth(&client, &mount, "approle").await;

    let approle = client.auth().approle_at(&mount);
    let role_name = unique_name("custrole");

    approle
        .create_role(
            &role_name,
            &AppRoleCreateRequest {
                token_policies: Some(vec!["default".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let role_id = approle.read_role_id(&role_name).await.unwrap();
    let secret = approle.generate_secret_id(&role_name).await.unwrap();

    // Login using the custom mount path
    let addr = vault_addr();
    let login_client = VaultClient::builder()
        .address(&addr)
        .token(SecretString::from("placeholder"))
        .max_retries(0)
        .build()
        .unwrap();

    let auth = login_client
        .auth()
        .approle_at(&mount)
        .login(&role_id, &secret.secret_id)
        .await
        .unwrap();
    assert!(!auth.client_token.expose_secret().is_empty());

    // Cleanup
    approle.delete_role(&role_name).await.unwrap();
    client.sys().disable_auth(&mount).await.unwrap();
}
