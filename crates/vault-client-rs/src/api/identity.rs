use reqwest::Method;

use crate::VaultClient;
use crate::api::traits::IdentityOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::identity::*;

#[derive(Debug)]
pub struct IdentityHandler<'a> {
    pub(crate) client: &'a VaultClient,
}

impl IdentityOperations for IdentityHandler<'_> {
    async fn create_entity(&self, params: &EntityCreateRequest) -> Result<Entity, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(Method::POST, "identity/entity", Some(&body))
            .await
    }

    async fn read_entity(&self, id: &str) -> Result<Entity, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/entity/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn read_entity_by_name(&self, name: &str) -> Result<Entity, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/entity/name/{}", encode_path(name)),
                None,
            )
            .await
    }

    async fn update_entity(
        &self,
        id: &str,
        params: &EntityCreateRequest,
    ) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("identity/entity/id/{}", encode_path(id)),
                Some(&body),
            )
            .await
    }

    async fn delete_entity(&self, id: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("identity/entity/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn list_entities(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("identity/entity/id").await
    }

    async fn create_entity_alias(
        &self,
        params: &EntityAliasCreateRequest,
    ) -> Result<EntityAliasResponse, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(Method::POST, "identity/entity-alias", Some(&body))
            .await
    }

    async fn read_entity_alias(&self, id: &str) -> Result<EntityAliasResponse, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/entity-alias/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn delete_entity_alias(&self, id: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("identity/entity-alias/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn list_entity_aliases(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("identity/entity-alias/id").await
    }

    async fn create_group(&self, params: &GroupCreateRequest) -> Result<Group, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(Method::POST, "identity/group", Some(&body))
            .await
    }

    async fn read_group(&self, id: &str) -> Result<Group, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/group/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn read_group_by_name(&self, name: &str) -> Result<Group, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/group/name/{}", encode_path(name)),
                None,
            )
            .await
    }

    async fn update_group(&self, id: &str, params: &GroupCreateRequest) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("identity/group/id/{}", encode_path(id)),
                Some(&body),
            )
            .await
    }

    async fn delete_group(&self, id: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("identity/group/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn list_groups(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("identity/group/id").await
    }

    async fn create_group_alias(
        &self,
        params: &GroupAliasCreateRequest,
    ) -> Result<GroupAliasResponse, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(Method::POST, "identity/group-alias", Some(&body))
            .await
    }

    async fn read_group_alias(&self, id: &str) -> Result<GroupAliasResponse, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("identity/group-alias/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn delete_group_alias(&self, id: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("identity/group-alias/id/{}", encode_path(id)),
                None,
            )
            .await
    }

    async fn list_group_aliases(&self) -> Result<Vec<String>, VaultError> {
        self.client.exec_list("identity/group-alias/id").await
    }
}
