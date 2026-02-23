use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::redact;

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct AwsConfigRootRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<i32>,
}

impl Clone for AwsConfigRootRequest {
    fn clone(&self) -> Self {
        Self {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            region: self.region.clone(),
            iam_endpoint: self.iam_endpoint.clone(),
            sts_endpoint: self.sts_endpoint.clone(),
            max_retries: self.max_retries,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AwsConfigRoot {
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub iam_endpoint: String,
    #[serde(default)]
    pub sts_endpoint: String,
    #[serde(default)]
    pub max_retries: i32,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct AwsRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_arns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_document: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_tags: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_sts_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sts_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_boundary_arn: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AwsRole {
    #[serde(default)]
    pub credential_type: String,
    #[serde(default)]
    pub role_arns: Vec<String>,
    #[serde(default)]
    pub policy_arns: Vec<String>,
    #[serde(default)]
    pub policy_document: String,
    #[serde(default)]
    pub iam_groups: Vec<String>,
    #[serde(default)]
    pub default_sts_ttl: u64,
    #[serde(default)]
    pub max_sts_ttl: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: SecretString,
    #[serde(default)]
    pub security_token: Option<SecretString>,
    #[serde(default)]
    pub arn: Option<String>,
}

impl Clone for AwsCredentials {
    fn clone(&self) -> Self {
        Self {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            security_token: self.security_token.clone(),
            arn: self.arn.clone(),
        }
    }
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key", &self.access_key)
            .field("secret_key", &redact(self.secret_key.expose_secret()))
            .field(
                "security_token",
                &self
                    .security_token
                    .as_ref()
                    .map(|s| redact(s.expose_secret())),
            )
            .field("arn", &self.arn)
            .finish()
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct AwsStsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

// AWS Auth types

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct AwsAuthConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<i32>,
}

impl Clone for AwsAuthConfigRequest {
    fn clone(&self) -> Self {
        Self {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            endpoint: self.endpoint.clone(),
            iam_endpoint: self.iam_endpoint.clone(),
            sts_endpoint: self.sts_endpoint.clone(),
            sts_region: self.sts_region.clone(),
            max_retries: self.max_retries,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AwsAuthConfig {
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub iam_endpoint: String,
    #[serde(default)]
    pub sts_endpoint: String,
    #[serde(default)]
    pub sts_region: String,
    #[serde(default)]
    pub max_retries: i32,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct AwsAuthRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_ami_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_account_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_region: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_vpc_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subnet_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_iam_role_arn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_iam_instance_profile_arn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_iam_principal_arn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_ec2_instance_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct AwsAuthRoleInfo {
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub bound_ami_id: Vec<String>,
    #[serde(default)]
    pub bound_account_id: Vec<String>,
    #[serde(default)]
    pub bound_region: Vec<String>,
    #[serde(default)]
    pub bound_iam_role_arn: Vec<String>,
    #[serde(default)]
    pub bound_iam_principal_arn: Vec<String>,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub token_max_ttl: u64,
    #[serde(default)]
    pub token_policies: Vec<String>,
}

#[derive(Debug, Serialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct AwsAuthLoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity: Option<SecretString>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature: Option<SecretString>,
    #[serde(
        serialize_with = "super::serde_secret::serialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub pkcs7: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_http_request_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_request_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_request_headers: Option<String>,
}

impl Clone for AwsAuthLoginRequest {
    fn clone(&self) -> Self {
        Self {
            role: self.role.clone(),
            identity: self.identity.clone(),
            signature: self.signature.clone(),
            pkcs7: self.pkcs7.clone(),
            nonce: self.nonce.clone(),
            iam_http_request_method: self.iam_http_request_method.clone(),
            iam_request_url: self.iam_request_url.clone(),
            iam_request_body: self.iam_request_body.clone(),
            iam_request_headers: self.iam_request_headers.clone(),
        }
    }
}
