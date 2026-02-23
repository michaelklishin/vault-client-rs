use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Default, Clone)]
pub struct EntityCreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct Entity {
    pub id: String,
    pub name: String,
    pub metadata: Option<HashMap<String, String>>,
    #[serde(default)]
    pub policies: Vec<String>,
    pub disabled: bool,
    #[serde(default)]
    pub aliases: Vec<EntityAlias>,
    pub creation_time: String,
    pub last_update_time: String,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct EntityAlias {
    pub id: String,
    pub canonical_id: String,
    pub mount_accessor: String,
    pub mount_type: String,
    pub name: String,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct EntityAliasCreateRequest {
    pub name: String,
    pub canonical_id: String,
    pub mount_accessor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct EntityAliasResponse {
    pub id: String,
    pub canonical_id: String,
    pub mount_accessor: String,
    pub name: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct GroupCreateRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_entity_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_group_ids: Option<Vec<String>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub group_type: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub policies: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
    #[serde(default)]
    pub member_entity_ids: Vec<String>,
    #[serde(default)]
    pub member_group_ids: Vec<String>,
    #[serde(rename = "type")]
    pub group_type: String,
    pub creation_time: String,
    pub last_update_time: String,
    pub alias: Option<GroupAlias>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GroupAlias {
    pub id: String,
    pub canonical_id: String,
    pub mount_accessor: String,
    pub mount_type: String,
    pub name: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct GroupAliasCreateRequest {
    pub name: String,
    pub mount_accessor: String,
    pub canonical_id: String,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct GroupAliasResponse {
    pub id: String,
    pub canonical_id: String,
    pub mount_accessor: String,
    pub name: String,
}
