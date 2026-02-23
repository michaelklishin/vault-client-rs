use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::IdentityOperations;
use vault_client_rs::types::identity::*;

#[tokio::test]
async fn create_entity() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/entity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "entity-id-1",
                "name": "my-entity",
                "metadata": null,
                "policies": ["default"],
                "disabled": false,
                "aliases": [],
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = EntityCreateRequest {
        name: Some("my-entity".to_string()),
        ..Default::default()
    };
    let entity = client.identity().create_entity(&params).await.unwrap();
    assert_eq!(entity.id, "entity-id-1");
    assert_eq!(entity.name, "my-entity");
}

#[tokio::test]
async fn read_entity() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/entity/id/entity-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "entity-id-1",
                "name": "my-entity",
                "metadata": null,
                "policies": ["default"],
                "disabled": false,
                "aliases": [
                    {
                        "id": "alias-id-1",
                        "canonical_id": "entity-id-1",
                        "mount_accessor": "auth_token_abc",
                        "mount_type": "token",
                        "name": "my-alias",
                        "metadata": null
                    }
                ],
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let entity = client.identity().read_entity("entity-id-1").await.unwrap();
    assert_eq!(entity.id, "entity-id-1");
    assert_eq!(entity.name, "my-entity");
    assert_eq!(entity.aliases.len(), 1);
    assert_eq!(entity.aliases[0].id, "alias-id-1");
    assert_eq!(entity.aliases[0].canonical_id, "entity-id-1");
}

#[tokio::test]
async fn read_entity_by_name() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/entity/name/my-entity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "entity-id-1",
                "name": "my-entity",
                "metadata": null,
                "policies": [],
                "disabled": false,
                "aliases": [],
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let entity = client
        .identity()
        .read_entity_by_name("my-entity")
        .await
        .unwrap();
    assert_eq!(entity.id, "entity-id-1");
    assert_eq!(entity.name, "my-entity");
}

#[tokio::test]
async fn update_entity() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/entity/id/entity-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = EntityCreateRequest {
        name: Some("updated-entity".to_string()),
        policies: Some(vec!["admin".to_string()]),
        ..Default::default()
    };
    client
        .identity()
        .update_entity("entity-id-1", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_entity() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/identity/entity/id/entity-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .identity()
        .delete_entity("entity-id-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_entities() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/identity/entity/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["entity-id-1", "entity-id-2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let entities = client.identity().list_entities().await.unwrap();
    assert_eq!(entities, vec!["entity-id-1", "entity-id-2"]);
}

#[tokio::test]
async fn create_entity_alias() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/entity-alias"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "alias-id-1",
                "canonical_id": "entity-id-1",
                "mount_accessor": "auth_userpass_abc",
                "name": "my-user"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = EntityAliasCreateRequest {
        name: "my-user".to_string(),
        canonical_id: "entity-id-1".to_string(),
        mount_accessor: "auth_userpass_abc".to_string(),
        ..Default::default()
    };
    let alias = client
        .identity()
        .create_entity_alias(&params)
        .await
        .unwrap();
    assert_eq!(alias.id, "alias-id-1");
    assert_eq!(alias.canonical_id, "entity-id-1");
}

#[tokio::test]
async fn create_group() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/group"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "group-id-1",
                "name": "my-group",
                "policies": ["default"],
                "metadata": null,
                "member_entity_ids": ["entity-id-1"],
                "member_group_ids": [],
                "type": "internal",
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z",
                "alias": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GroupCreateRequest {
        name: "my-group".to_string(),
        member_entity_ids: Some(vec!["entity-id-1".to_string()]),
        ..Default::default()
    };
    let group = client.identity().create_group(&params).await.unwrap();
    assert_eq!(group.id, "group-id-1");
    assert_eq!(group.name, "my-group");
}

#[tokio::test]
async fn read_group() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/group/id/group-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "group-id-1",
                "name": "my-group",
                "policies": ["admin"],
                "metadata": null,
                "member_entity_ids": [],
                "member_group_ids": [],
                "type": "internal",
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z",
                "alias": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let group = client.identity().read_group("group-id-1").await.unwrap();
    assert_eq!(group.id, "group-id-1");
    assert_eq!(group.name, "my-group");
    assert_eq!(group.policies, vec!["admin"]);
    assert_eq!(group.group_type, "internal");
}

#[tokio::test]
async fn list_groups() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/identity/group/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["group-id-1", "group-id-2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let groups = client.identity().list_groups().await.unwrap();
    assert_eq!(groups, vec!["group-id-1", "group-id-2"]);
}

#[tokio::test]
async fn read_entity_alias() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/entity-alias/id/alias-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "alias-id-1",
                "canonical_id": "entity-id-1",
                "mount_accessor": "auth_userpass_abc",
                "name": "my-alias"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let alias = client
        .identity()
        .read_entity_alias("alias-id-1")
        .await
        .unwrap();
    assert_eq!(alias.id, "alias-id-1");
    assert_eq!(alias.canonical_id, "entity-id-1");
    assert_eq!(alias.mount_accessor, "auth_userpass_abc");
}

#[tokio::test]
async fn delete_entity_alias() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/identity/entity-alias/id/alias-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .identity()
        .delete_entity_alias("alias-id-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_entity_aliases() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/identity/entity-alias/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["alias-id-1", "alias-id-2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let aliases = client.identity().list_entity_aliases().await.unwrap();
    assert_eq!(aliases, vec!["alias-id-1", "alias-id-2"]);
}

#[tokio::test]
async fn update_group() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/group/id/group-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GroupCreateRequest {
        name: "updated-group".to_string(),
        policies: Some(vec!["admin".to_string()]),
        ..Default::default()
    };
    client
        .identity()
        .update_group("group-id-1", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_group() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/identity/group/id/group-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.identity().delete_group("group-id-1").await.unwrap();
}

#[tokio::test]
async fn create_group_alias() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/identity/group-alias"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "group-alias-id-1",
                "canonical_id": "group-id-1",
                "mount_accessor": "auth_ldap_abc",
                "name": "engineering"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GroupAliasCreateRequest {
        name: "engineering".to_string(),
        mount_accessor: "auth_ldap_abc".to_string(),
        canonical_id: "group-id-1".to_string(),
    };
    let alias = client.identity().create_group_alias(&params).await.unwrap();
    assert_eq!(alias.id, "group-alias-id-1");
    assert_eq!(alias.canonical_id, "group-id-1");
    assert_eq!(alias.mount_accessor, "auth_ldap_abc");
    assert_eq!(alias.name, "engineering");
}

#[tokio::test]
async fn read_group_alias() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/group-alias/id/group-alias-id-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "group-alias-id-1",
                "canonical_id": "group-id-1",
                "mount_accessor": "auth_ldap_abc",
                "name": "engineering"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let alias = client
        .identity()
        .read_group_alias("group-alias-id-1")
        .await
        .unwrap();
    assert_eq!(alias.id, "group-alias-id-1");
    assert_eq!(alias.canonical_id, "group-id-1");
    assert_eq!(alias.name, "engineering");
}

#[tokio::test]
async fn delete_group_alias() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/identity/group-alias/id/group-alias-id-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .identity()
        .delete_group_alias("group-alias-id-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_group_aliases() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/identity/group-alias/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["group-alias-id-1", "group-alias-id-2"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let aliases = client.identity().list_group_aliases().await.unwrap();
    assert_eq!(aliases, vec!["group-alias-id-1", "group-alias-id-2"]);
}

#[tokio::test]
async fn read_group_by_name() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/identity/group/name/my-group"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "group-id-1",
                "name": "my-group",
                "policies": ["default", "admin"],
                "metadata": null,
                "member_entity_ids": ["entity-id-1"],
                "member_group_ids": [],
                "type": "internal",
                "creation_time": "2024-01-01T00:00:00Z",
                "last_update_time": "2024-01-01T00:00:00Z",
                "alias": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let group = client
        .identity()
        .read_group_by_name("my-group")
        .await
        .unwrap();
    assert_eq!(group.id, "group-id-1");
    assert_eq!(group.name, "my-group");
    assert_eq!(group.policies, vec!["default", "admin"]);
    assert_eq!(group.group_type, "internal");
    assert_eq!(group.member_entity_ids, vec!["entity-id-1"]);
}
