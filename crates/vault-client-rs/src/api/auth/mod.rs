pub mod approle;
pub mod aws;
pub mod azure;
pub mod cert;
pub mod gcp;
pub mod github;
pub mod kerberos;
pub mod kubernetes;
pub mod ldap;
pub mod oidc;
pub mod radius;
pub mod token;
pub mod userpass;

use std::future::Future;
use std::pin::Pin;

use crate::VaultClient;
use crate::api::traits::{
    AppRoleAuthOperations, AwsAuthOperations, AzureAuthOperations, GcpAuthOperations,
    GithubAuthOperations, K8sAuthOperations, LdapAuthOperations, OidcAuthOperations,
    UserpassAuthOperations,
};
use crate::client::encode_path;
use crate::types::aws::AwsAuthLoginRequest;
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;
use crate::types::secret::SecretString;

#[derive(Debug)]
pub struct AuthHandler<'a> {
    pub(crate) client: &'a VaultClient,
}

impl<'a> AuthHandler<'a> {
    #[must_use]
    pub fn token(&self) -> token::TokenAuthHandler<'a> {
        token::TokenAuthHandler {
            client: self.client,
        }
    }

    #[must_use]
    pub fn approle(&self) -> approle::AppRoleAuthHandler<'a> {
        self.approle_at("approle")
    }

    #[must_use]
    pub fn approle_at(&self, mount: &str) -> approle::AppRoleAuthHandler<'a> {
        approle::AppRoleAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn kubernetes(&self) -> kubernetes::K8sAuthHandler<'a> {
        self.kubernetes_at("kubernetes")
    }

    #[must_use]
    pub fn kubernetes_at(&self, mount: &str) -> kubernetes::K8sAuthHandler<'a> {
        kubernetes::K8sAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn userpass(&self) -> userpass::UserpassAuthHandler<'a> {
        self.userpass_at("userpass")
    }

    #[must_use]
    pub fn userpass_at(&self, mount: &str) -> userpass::UserpassAuthHandler<'a> {
        userpass::UserpassAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn ldap(&self) -> ldap::LdapAuthHandler<'a> {
        self.ldap_at("ldap")
    }

    #[must_use]
    pub fn ldap_at(&self, mount: &str) -> ldap::LdapAuthHandler<'a> {
        ldap::LdapAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn cert(&self) -> cert::CertAuthHandler<'a> {
        self.cert_at("cert")
    }

    #[must_use]
    pub fn cert_at(&self, mount: &str) -> cert::CertAuthHandler<'a> {
        cert::CertAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn github(&self) -> github::GithubAuthHandler<'a> {
        self.github_at("github")
    }

    #[must_use]
    pub fn github_at(&self, mount: &str) -> github::GithubAuthHandler<'a> {
        github::GithubAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn oidc(&self) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at("oidc")
    }

    #[must_use]
    pub fn oidc_at(&self, mount: &str) -> oidc::OidcAuthHandler<'a> {
        oidc::OidcAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn jwt(&self) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at("jwt")
    }

    #[must_use]
    pub fn jwt_at(&self, mount: &str) -> oidc::OidcAuthHandler<'a> {
        self.oidc_at(mount)
    }

    #[must_use]
    pub fn aws(&self) -> aws::AwsAuthHandler<'a> {
        self.aws_at("aws")
    }

    #[must_use]
    pub fn aws_at(&self, mount: &str) -> aws::AwsAuthHandler<'a> {
        aws::AwsAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn azure(&self) -> azure::AzureAuthHandler<'a> {
        self.azure_at("azure")
    }

    #[must_use]
    pub fn azure_at(&self, mount: &str) -> azure::AzureAuthHandler<'a> {
        azure::AzureAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn gcp(&self) -> gcp::GcpAuthHandler<'a> {
        self.gcp_at("gcp")
    }

    #[must_use]
    pub fn gcp_at(&self, mount: &str) -> gcp::GcpAuthHandler<'a> {
        gcp::GcpAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn radius(&self) -> radius::RadiusAuthHandler<'a> {
        self.radius_at("radius")
    }

    #[must_use]
    pub fn radius_at(&self, mount: &str) -> radius::RadiusAuthHandler<'a> {
        radius::RadiusAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn kerberos(&self) -> kerberos::KerberosAuthHandler<'a> {
        self.kerberos_at("kerberos")
    }

    #[must_use]
    pub fn kerberos_at(&self, mount: &str) -> kerberos::KerberosAuthHandler<'a> {
        kerberos::KerberosAuthHandler {
            client: self.client,
            mount: encode_path(mount),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthMethod trait
// ---------------------------------------------------------------------------

/// Pluggable authentication method
///
/// Implementors store their own credentials and produce an `AuthInfo` on login
pub trait AuthMethod: Send + Sync {
    fn login<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> impl Future<Output = Result<AuthInfo, VaultError>> + Send + 'a;
}

/// Object-safe version of `AuthMethod` for dynamic dispatch inside the client
pub(crate) trait AuthMethodDyn: Send + Sync {
    fn login_dyn<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, VaultError>> + Send + 'a>>;
}

impl<T: AuthMethod> AuthMethodDyn for T {
    fn login_dyn<'a>(
        &'a self,
        client: &'a VaultClient,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, VaultError>> + Send + 'a>> {
        Box::pin(self.login(client))
    }
}

/// Self-contained AppRole login credentials
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

/// Self-contained Kubernetes login credentials
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

/// Self-contained userpass login credentials
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

/// Self-contained LDAP login credentials
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

/// Self-contained GitHub login credentials
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

/// Self-contained JWT login credentials (for the jwt/oidc backend)
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

/// Self-contained AWS login credentials
pub struct AwsLogin {
    pub params: AwsAuthLoginRequest,
    pub mount: String,
}

impl AuthMethod for AwsLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client.auth().aws_at(&self.mount).login(&self.params).await
    }
}

/// Self-contained Azure login credentials
pub struct AzureLogin {
    pub role: String,
    pub jwt: SecretString,
    pub subscription_id: Option<String>,
    pub resource_group_name: Option<String>,
    pub vm_name: Option<String>,
    pub vmss_name: Option<String>,
    pub mount: String,
}

impl AuthMethod for AzureLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .azure_at(&self.mount)
            .login(
                &self.role,
                &self.jwt,
                self.subscription_id.as_deref(),
                self.resource_group_name.as_deref(),
                self.vm_name.as_deref(),
                self.vmss_name.as_deref(),
            )
            .await
    }
}

/// Self-contained GCP login credentials
pub struct GcpLogin {
    pub role: String,
    pub jwt: SecretString,
    pub mount: String,
}

impl AuthMethod for GcpLogin {
    async fn login(&self, client: &VaultClient) -> Result<AuthInfo, VaultError> {
        client
            .auth()
            .gcp_at(&self.mount)
            .login(&self.role, &self.jwt)
            .await
    }
}
