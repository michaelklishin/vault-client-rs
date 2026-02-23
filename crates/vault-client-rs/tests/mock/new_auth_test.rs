use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::auth::*;
use vault_client_rs::{
    CertAuthOperations, GithubAuthOperations, LdapAuthOperations, OidcAuthOperations,
    UserpassAuthOperations,
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
// Userpass auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn userpass_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/userpass/login/alice"))
        .and(body_json(serde_json::json!({"password": "s3cret"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .userpass()
        .login("alice", &SecretString::from("s3cret"))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn userpass_create_user() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/userpass/users/bob"))
        .and(body_json(serde_json::json!({
            "password": "pass123",
            "token_policies": ["dev"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = UserpassUserRequest {
        password: Some(SecretString::from("pass123")),
        token_policies: Some(vec!["dev".into()]),
        token_ttl: None,
        token_max_ttl: None,
        token_bound_cidrs: None,
        token_num_uses: None,
    };
    client
        .auth()
        .userpass()
        .create_user("bob", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn userpass_read_user() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/userpass/users/bob"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token_policies": ["dev", "staging"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "token_bound_cidrs": [],
                "token_num_uses": 0
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.auth().userpass().read_user("bob").await.unwrap();
    assert_eq!(info.token_policies, vec!["dev", "staging"]);
    assert_eq!(info.token_ttl, 3600);
    assert_eq!(info.token_max_ttl, 7200);
}

#[tokio::test]
async fn userpass_delete_user() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/userpass/users/bob"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().userpass().delete_user("bob").await.unwrap();
}

#[tokio::test]
async fn userpass_list_users() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/userpass/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["alice", "bob"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let users = client.auth().userpass().list_users().await.unwrap();
    assert_eq!(users, vec!["alice", "bob"]);
}

#[tokio::test]
async fn userpass_update_password() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/userpass/users/alice/password"))
        .and(body_json(serde_json::json!({"password": "newpass"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .userpass()
        .update_password("alice", &SecretString::from("newpass"))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// LDAP auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ldap_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/ldap/login/jdoe"))
        .and(body_json(serde_json::json!({"password": "ldappass"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .ldap()
        .login("jdoe", &SecretString::from("ldappass"))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn ldap_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/ldap/config"))
        .and(body_json(serde_json::json!({
            "url": "ldap://ldap.example.com",
            "userdn": "ou=Users,dc=example,dc=com",
            "groupdn": "ou=Groups,dc=example,dc=com"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = LdapConfigRequest {
        url: "ldap://ldap.example.com".into(),
        userdn: Some("ou=Users,dc=example,dc=com".into()),
        groupdn: Some("ou=Groups,dc=example,dc=com".into()),
        userattr: None,
        groupattr: None,
        groupfilter: None,
        binddn: None,
        bindpass: None,
        starttls: None,
        insecure_tls: None,
        certificate: None,
        token_policies: None,
        token_ttl: None,
        token_max_ttl: None,
    };
    client.auth().ldap().configure(&config).await.unwrap();
}

#[tokio::test]
async fn ldap_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/ldap/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "url": "ldap://ldap.example.com",
                "userdn": "ou=Users,dc=example,dc=com",
                "userattr": "cn",
                "groupdn": "ou=Groups,dc=example,dc=com",
                "groupattr": "cn",
                "groupfilter": "(|(memberUid={{.Username}}))",
                "starttls": false,
                "insecure_tls": false
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().ldap().read_config().await.unwrap();
    assert_eq!(config.url, "ldap://ldap.example.com");
    assert_eq!(config.userdn, "ou=Users,dc=example,dc=com");
    assert_eq!(config.userattr, "cn");
}

#[tokio::test]
async fn ldap_write_group() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/ldap/groups/engineers"))
        .and(body_json(
            serde_json::json!({"policies": ["dev", "staging"]}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = LdapGroupRequest {
        policies: Some(vec!["dev".into(), "staging".into()]),
    };
    client
        .auth()
        .ldap()
        .write_group("engineers", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn ldap_read_group() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/ldap/groups/engineers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "policies": ["dev", "staging"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let group = client.auth().ldap().read_group("engineers").await.unwrap();
    assert_eq!(group.policies, vec!["dev", "staging"]);
}

#[tokio::test]
async fn ldap_delete_group() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/ldap/groups/engineers"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .ldap()
        .delete_group("engineers")
        .await
        .unwrap();
}

#[tokio::test]
async fn ldap_list_groups() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/ldap/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["engineers", "admins"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let groups = client.auth().ldap().list_groups().await.unwrap();
    assert_eq!(groups, vec!["engineers", "admins"]);
}

#[tokio::test]
async fn ldap_write_user() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/ldap/users/jdoe"))
        .and(body_json(serde_json::json!({
            "policies": ["dev"],
            "groups": ["engineers"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = LdapUserRequest {
        policies: Some(vec!["dev".into()]),
        groups: Some(vec!["engineers".into()]),
    };
    client
        .auth()
        .ldap()
        .write_user("jdoe", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn ldap_list_users() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/ldap/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["jdoe", "asmith"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let users = client.auth().ldap().list_users().await.unwrap();
    assert_eq!(users, vec!["jdoe", "asmith"]);
}

#[tokio::test]
async fn ldap_read_user() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/ldap/users/jdoe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "policies": ["dev", "staging"],
                "groups": ["engineers", "ops"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let user = client.auth().ldap().read_user("jdoe").await.unwrap();
    assert_eq!(user.policies, vec!["dev", "staging"]);
    assert_eq!(user.groups, vec!["engineers", "ops"]);
}

#[tokio::test]
async fn ldap_delete_user() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/ldap/users/jdoe"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().ldap().delete_user("jdoe").await.unwrap();
}

// ---------------------------------------------------------------------------
// Cert auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cert_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/cert/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client.auth().cert().login(None).await.unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn cert_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/cert/certs/web"))
        .and(body_json(serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            "token_policies": ["web-policy"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = CertRoleRequest {
        certificate: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".into(),
        token_policies: Some(vec!["web-policy".into()]),
        ..Default::default()
    };
    client
        .auth()
        .cert()
        .create_role("web", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn cert_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/cert/certs/web"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                "allowed_common_names": ["web.example.com"],
                "allowed_dns_sans": [],
                "token_policies": ["web-policy"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "display_name": "web"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.auth().cert().read_role("web").await.unwrap();
    assert_eq!(role.token_policies, vec!["web-policy"]);
    assert_eq!(role.display_name, "web");
    assert_eq!(role.token_ttl, 3600);
}

#[tokio::test]
async fn cert_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/cert/certs/web"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().cert().delete_role("web").await.unwrap();
}

#[tokio::test]
async fn cert_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/cert/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["web", "api"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().cert().list_roles().await.unwrap();
    assert_eq!(roles, vec!["web", "api"]);
}

// ---------------------------------------------------------------------------
// GitHub auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn github_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .and(body_json(serde_json::json!({"token": "ghp_abc123"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .github()
        .login(&SecretString::from("ghp_abc123"))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn github_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/config"))
        .and(body_json(serde_json::json!({
            "organization": "my-org",
            "token_policies": ["default"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = GithubConfigRequest {
        organization: "my-org".into(),
        token_policies: Some(vec!["default".into()]),
        ..Default::default()
    };
    client.auth().github().configure(&config).await.unwrap();
}

#[tokio::test]
async fn github_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/github/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "organization": "my-org",
                "base_url": "https://api.github.com/",
                "token_policies": ["default"],
                "token_ttl": 1800,
                "token_max_ttl": 3600
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().github().read_config().await.unwrap();
    assert_eq!(config.organization, "my-org");
    assert_eq!(config.base_url, "https://api.github.com/");
    assert_eq!(config.token_ttl, 1800);
}

#[tokio::test]
async fn github_map_team() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/map/teams/backend"))
        .and(body_json(serde_json::json!({"value": "dev-policy"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GithubTeamMapping {
        value: Some("dev-policy".into()),
    };
    client
        .auth()
        .github()
        .map_team("backend", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn github_list_teams() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/github/map/teams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["backend", "frontend"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let teams = client.auth().github().list_teams().await.unwrap();
    assert_eq!(teams, vec!["backend", "frontend"]);
}

// ---------------------------------------------------------------------------
// OIDC/JWT auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_login_jwt() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/oidc/login"))
        .and(body_json(
            serde_json::json!({"role": "my-role", "jwt": "eyJhbGciOiJSUzI1NiJ9.fake"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .oidc()
        .login_jwt("my-role", &SecretString::from("eyJhbGciOiJSUzI1NiJ9.fake"))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn oidc_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/oidc/config"))
        .and(body_json(serde_json::json!({
            "oidc_discovery_url": "https://accounts.google.com",
            "oidc_client_id": "client-id-123",
            "oidc_client_secret": "client-secret-456",
            "default_role": "default"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = OidcConfigRequest {
        oidc_discovery_url: Some("https://accounts.google.com".into()),
        oidc_client_id: Some("client-id-123".into()),
        oidc_client_secret: Some(SecretString::from("client-secret-456")),
        default_role: Some("default".into()),
        jwt_validation_pubkeys: None,
        bound_issuer: None,
        jwt_supported_algs: None,
    };
    client.auth().oidc().configure(&config).await.unwrap();
}

#[tokio::test]
async fn oidc_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/oidc/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "oidc_discovery_url": "https://accounts.google.com",
                "oidc_client_id": "client-id-123",
                "bound_issuer": "https://accounts.google.com",
                "default_role": "default",
                "jwt_supported_algs": ["RS256"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().oidc().read_config().await.unwrap();
    assert_eq!(
        config.oidc_discovery_url.as_deref(),
        Some("https://accounts.google.com")
    );
    assert_eq!(config.default_role.as_deref(), Some("default"));
    assert_eq!(config.jwt_supported_algs, vec!["RS256"]);
}

#[tokio::test]
async fn oidc_create_role() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/oidc/role/my-role"))
        .and(body_json(serde_json::json!({
            "role_type": "jwt",
            "bound_audiences": ["https://vault.example.com"],
            "user_claim": "sub",
            "token_policies": ["default"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = OidcRoleRequest {
        role_type: Some("jwt".into()),
        bound_audiences: Some(vec!["https://vault.example.com".into()]),
        user_claim: Some("sub".into()),
        token_policies: Some(vec!["default".into()]),
        ..Default::default()
    };
    client
        .auth()
        .oidc()
        .create_role("my-role", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn oidc_read_role() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/oidc/role/my-role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "role_type": "jwt",
                "bound_audiences": ["https://vault.example.com"],
                "user_claim": "sub",
                "bound_claims": {},
                "token_policies": ["default"],
                "token_ttl": 3600,
                "token_max_ttl": 7200,
                "allowed_redirect_uris": []
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let role = client.auth().oidc().read_role("my-role").await.unwrap();
    assert_eq!(role.role_type, "jwt");
    assert_eq!(role.user_claim, "sub");
    assert_eq!(role.token_policies, vec!["default"]);
    assert_eq!(role.token_ttl, 3600);
}

#[tokio::test]
async fn oidc_delete_role() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/oidc/role/my-role"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().oidc().delete_role("my-role").await.unwrap();
}

#[tokio::test]
async fn oidc_list_roles() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/oidc/role"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-role", "other-role"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let roles = client.auth().oidc().list_roles().await.unwrap();
    assert_eq!(roles, vec!["my-role", "other-role"]);
}

// ---------------------------------------------------------------------------
// GitHub auth - read_team_mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn github_read_team_mapping() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/github/map/teams/backend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "value": "dev-policy"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .auth()
        .github()
        .read_team_mapping("backend")
        .await
        .unwrap();
    assert_eq!(info.value, "dev-policy");
}
