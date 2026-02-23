use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::auth::*;
use vault_client_rs::{KerberosAuthOperations, RadiusAuthOperations};

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
// RADIUS auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn radius_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/radius/login/alice"))
        .and(body_json(serde_json::json!({"password": "s3cret"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .radius()
        .login("alice", &SecretString::from("s3cret"))
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn radius_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/radius/config"))
        .and(body_json(serde_json::json!({
            "host": "radius.example.com",
            "secret": "radius-shared-secret",
            "port": 1812
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = RadiusConfigRequest {
        host: "radius.example.com".into(),
        secret: SecretString::from("radius-shared-secret"),
        port: Some(1812),
        unregistered_user_policies: None,
        dial_timeout: None,
        read_timeout: None,
        nas_port: None,
        token_policies: None,
        token_ttl: None,
        token_max_ttl: None,
    };
    client.auth().radius().configure(&config).await.unwrap();
}

#[tokio::test]
async fn radius_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/radius/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "host": "radius.example.com",
                "port": 1812,
                "unregistered_user_policies": "default",
                "dial_timeout": 10,
                "read_timeout": 10,
                "nas_port": 10
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().radius().read_config().await.unwrap();
    assert_eq!(config.host, "radius.example.com");
    assert_eq!(config.port, 1812);
    assert_eq!(config.unregistered_user_policies, "default");
    assert_eq!(config.dial_timeout, 10);
    assert_eq!(config.read_timeout, 10);
    assert_eq!(config.nas_port, 10);
}

#[tokio::test]
async fn radius_write_user() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/radius/users/alice"))
        .and(body_json(
            serde_json::json!({"policies": ["dev", "staging"]}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RadiusUserRequest {
        policies: Some(vec!["dev".into(), "staging".into()]),
    };
    client
        .auth()
        .radius()
        .write_user("alice", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn radius_read_user() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/radius/users/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "policies": ["dev", "staging"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let user = client.auth().radius().read_user("alice").await.unwrap();
    assert_eq!(user.policies, vec!["dev", "staging"]);
}

#[tokio::test]
async fn radius_delete_user() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/radius/users/alice"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().radius().delete_user("alice").await.unwrap();
}

#[tokio::test]
async fn radius_list_users() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/radius/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["alice", "bob"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let users = client.auth().radius().list_users().await.unwrap();
    assert_eq!(users, vec!["alice", "bob"]);
}

// ---------------------------------------------------------------------------
// Kerberos auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kerberos_login() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kerberos/login"))
        .and(body_json(
            serde_json::json!({"authorization": "Negotiate YIIG..."}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response_json()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .kerberos()
        .login("Negotiate YIIG...")
        .await
        .unwrap();
    assert_eq!(auth.client_token.expose_secret(), "s.newtoken");
    assert_eq!(auth.accessor, "acc-new");
}

#[tokio::test]
async fn kerberos_configure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kerberos/config"))
        .and(body_json(serde_json::json!({
            "keytab": "BQIAAABF...",
            "service_account": "vault_svc@EXAMPLE.COM"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = KerberosConfigRequest {
        keytab: Some(SecretString::from("BQIAAABF...")),
        service_account: Some("vault_svc@EXAMPLE.COM".into()),
    };
    client.auth().kerberos().configure(&config).await.unwrap();
}

#[tokio::test]
async fn kerberos_read_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/kerberos/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "service_account": "vault_svc@EXAMPLE.COM"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.auth().kerberos().read_config().await.unwrap();
    assert_eq!(config.service_account, "vault_svc@EXAMPLE.COM");
}

#[tokio::test]
async fn kerberos_configure_ldap() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kerberos/config/ldap"))
        .and(body_json(serde_json::json!({
            "url": "ldap://ldap.example.com",
            "userdn": "ou=Users,dc=example,dc=com"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = KerberosLdapConfigRequest {
        url: "ldap://ldap.example.com".into(),
        userdn: Some("ou=Users,dc=example,dc=com".into()),
        userattr: None,
        groupdn: None,
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
    client
        .auth()
        .kerberos()
        .configure_ldap(&config)
        .await
        .unwrap();
}

#[tokio::test]
async fn kerberos_read_ldap_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/kerberos/config/ldap"))
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
    let config = client.auth().kerberos().read_ldap_config().await.unwrap();
    assert_eq!(config.url, "ldap://ldap.example.com");
    assert_eq!(config.userdn, "ou=Users,dc=example,dc=com");
    assert_eq!(config.userattr, "cn");
    assert_eq!(config.groupdn, "ou=Groups,dc=example,dc=com");
    assert_eq!(config.groupattr, "cn");
    assert_eq!(config.groupfilter, "(|(memberUid={{.Username}}))");
    assert!(!config.starttls);
    assert!(!config.insecure_tls);
}

#[tokio::test]
async fn kerberos_write_group() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/kerberos/groups/admins"))
        .and(body_json(
            serde_json::json!({"policies": ["admin", "default"]}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = KerberosGroupRequest {
        policies: Some(vec!["admin".into(), "default".into()]),
    };
    client
        .auth()
        .kerberos()
        .write_group("admins", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn kerberos_read_group() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/kerberos/groups/admins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "policies": ["admin", "default"]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let group = client.auth().kerberos().read_group("admins").await.unwrap();
    assert_eq!(group.policies, vec!["admin", "default"]);
}

#[tokio::test]
async fn kerberos_delete_group() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/auth/kerberos/groups/admins"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .auth()
        .kerberos()
        .delete_group("admins")
        .await
        .unwrap();
}

#[tokio::test]
async fn kerberos_list_groups() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/auth/kerberos/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["admins", "developers"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let groups = client.auth().kerberos().list_groups().await.unwrap();
    assert_eq!(groups, vec!["admins", "developers"]);
}
