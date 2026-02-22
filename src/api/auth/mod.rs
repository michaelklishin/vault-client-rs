pub mod approle;
pub mod cert;
pub mod github;
pub mod kubernetes;
pub mod ldap;
pub mod oidc;
pub mod token;
pub mod userpass;

use std::future::Future;

use crate::VaultClient;
use crate::api::traits::{
    AppRoleAuthOperations, GithubAuthOperations, K8sAuthOperations, LdapAuthOperations,
    OidcAuthOperations, UserpassAuthOperations,
};
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

    pub fn userpass(&self) -> userpass::UserpassAuthHandler<'a> {
        self.userpass_at("userpass")
    }

    pub fn userpass_at(&self, mount: &str) -> userpass::UserpassAuthHandler<'a> {
        userpass::UserpassAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn ldap(&self) -> ldap::LdapAuthHandler<'a> {
        self.ldap_at("ldap")
    }

    pub fn ldap_at(&self, mount: &str) -> ldap::LdapAuthHandler<'a> {
        ldap::LdapAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn cert(&self) -> cert::CertAuthHandler<'a> {
        self.cert_at("cert")
    }

    pub fn cert_at(&self, mount: &str) -> cert::CertAuthHandler<'a> {
        cert::CertAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn github(&self) -> github::GithubAuthHandler<'a> {
        self.github_at("github")
    }

    pub fn github_at(&self, mount: &str) -> github::GithubAuthHandler<'a> {
        github::GithubAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn oidc(&self) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at("oidc")
    }

    pub fn oidc_at(&self, mount: &str) -> oidc::OidcAuthHandler<'a> {
        oidc::OidcAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    pub fn jwt(&self) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at("jwt")
    }

    pub fn jwt_at(&self, mount: &str) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at(mount)
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

/// Object-safe version of `AuthMethod` for dynamic dispatch inside the client.
pub(crate) trait AuthMethodDyn: Send + Sync {
    fn login_dyn<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<AuthInfo, VaultError>> + Send + 'a>>;
}

impl<T: AuthMethod> AuthMethodDyn for T {
    fn login_dyn<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<AuthInfo, VaultError>> + Send + 'a>> {
        Box::pin(self.login(client))
    }
}

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

/// Self-contained userpass login credentials.
pub struct UserpassLogin {
    pub username: String,
    pub password: SecretString,
    pub mount: String,
}

impl AuthMethod for UserpassLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .userpass_at(&self.mount)
            .login(&self.username, &self.password)
            .await
    }
}

/// Self-contained LDAP login credentials.
pub struct LdapLogin {
    pub username: String,
    pub password: SecretString,
    pub mount: String,
}

impl AuthMethod for LdapLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .ldap_at(&self.mount)
            .login(&self.username, &self.password)
            .await
    }
}

/// Self-contained GitHub login credentials.
pub struct GithubLogin {
    pub token: SecretString,
    pub mount: String,
}

impl AuthMethod for GithubLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .github_at(&self.mount)
            .login(&self.token)
            .await
    }
}

/// Self-contained JWT login credentials (for the jwt/oidc backend).
pub struct JwtLogin {
    pub role: String,
    pub jwt: SecretString,
    pub mount: String,
}

impl AuthMethod for JwtLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .oidc_at(&self.mount)
            .login_jwt(&self.role, &self.jwt)
            .await
    }
}
