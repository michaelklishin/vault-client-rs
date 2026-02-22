pub mod approle;
pub mod kubernetes;
pub mod token;

use crate::VaultClient;
use crate::api::traits::{AppRoleAuthOperations, K8sAuthOperations};
use crate::client::encode_path;
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;
use crate::types::secret::SecretString;

#[derive(Debug)]
pub struct AuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
}

impl<'a> AuthHandler<'a> {
    pub fn token(&self) -> token::TokenAuthHandler<'a> {
        token::TokenAuthHandler {
            client: self.client,
        }
    }

    pub fn approle(&self) -> approle::AppRoleAuthHandler<'a> {
        self.approle_at("approle")
    }

    pub fn approle_at(&self, mount: &str) -> approle::AppRoleAuthHandler<'a> {
        approle::AppRoleAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn kubernetes(&self) -> kubernetes::K8sAuthHandler<'a> {
        self.kubernetes_at("kubernetes")
    }

    pub fn kubernetes_at(&self, mount: &str) -> kubernetes::K8sAuthHandler<'a> {
        kubernetes::K8sAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthMethod trait
// ---------------------------------------------------------------------------

/// Pluggable authentication method. Implementors store their own
/// credentials and produce an `AuthInfo` on login.
pub trait AuthMethod: Send + Sync {
    fn login<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send + 'a;
}

use std::future::Future;

/// Self-contained AppRole login credentials.
pub struct AppRoleLogin {
    pub role_id: String,
    pub secret_id: SecretString,
    pub mount: String,
}

impl AuthMethod for AppRoleLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .approle_at(&self.mount)
            .login(&self.role_id, &self.secret_id)
            .await
    }
}

/// Self-contained Kubernetes login credentials.
pub struct K8sLogin {
    pub role: String,
    pub jwt: SecretString,
    pub mount: String,
}

impl AuthMethod for K8sLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .kubernetes_at(&self.mount)
            .login(&self.role, &self.jwt)
            .await
    }
}
