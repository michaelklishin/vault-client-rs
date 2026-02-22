use reqwest::Method;
use secrecy::SecretString;

use crate::VaultClient;
use crate::api::traits::PkiOperations;
use crate::client::{encode_path, to_body};
use crate::types::error::VaultError;
use crate::types::pki::*;

#[derive(Debug)]
pub struct PkiHandler<'a> {
    pub(crate) client: &'a VaultClient,
    pub(crate) mount: String,
}

impl PkiOperations for PkiHandler<'_> {
    // --- CA management ---

    async fn generate_root(&self, params: &PkiRootParams) -> Result<PkiCertificate, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!(
                    "{}/root/generate/{}",
                    self.mount,
                    encode_path(&params.generate_type)
                ),
                Some(&body),
            )
            .await
    }

    async fn generate_intermediate_csr(
        &self,
        params: &PkiIntermediateParams,
    ) -> Result<PkiCsr, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!(
                    "{}/intermediate/generate/{}",
                    self.mount,
                    encode_path(&params.generate_type)
                ),
                Some(&body),
            )
            .await
    }

    async fn set_signed_intermediate(
        &self,
        certificate: &str,
    ) -> Result<PkiImportResult, VaultError> {
        let body = serde_json::json!({ "certificate": certificate });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/intermediate/set-signed", self.mount),
                Some(&body),
            )
            .await
    }

    async fn delete_root(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::DELETE, &format!("{}/root", self.mount), None)
            .await
    }

    // --- Issuers ---

    async fn list_issuers(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/issuers", self.mount))
            .await
    }

    async fn read_issuer(&self, issuer_ref: &str) -> Result<PkiIssuerInfo, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/issuer/{}", self.mount, encode_path(issuer_ref)),
                None,
            )
            .await
    }

    async fn delete_issuer(&self, issuer_ref: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/issuer/{}", self.mount, encode_path(issuer_ref)),
                None,
            )
            .await
    }

    // --- Roles ---

    async fn create_role(&self, name: &str, params: &PkiRoleParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                Some(&body),
            )
            .await
    }

    async fn read_role(&self, name: &str) -> Result<PkiRole, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/roles", self.mount))
            .await
    }

    async fn delete_role(&self, name: &str) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::DELETE,
                &format!("{}/roles/{}", self.mount, encode_path(name)),
                None,
            )
            .await
    }

    // --- Certificate issuance ---

    async fn issue(
        &self,
        role: &str,
        params: &PkiIssueParams,
    ) -> Result<PkiIssuedCert, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/issue/{}", self.mount, encode_path(role)),
                Some(&body),
            )
            .await
    }

    async fn sign(&self, role: &str, params: &PkiSignParams) -> Result<PkiSignedCert, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/sign/{}", self.mount, encode_path(role)),
                Some(&body),
            )
            .await
    }

    async fn sign_verbatim(&self, role: &str, csr: &str) -> Result<PkiSignedCert, VaultError> {
        let body = serde_json::json!({ "csr": csr });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/sign-verbatim/{}", self.mount, encode_path(role)),
                Some(&body),
            )
            .await
    }

    // --- Certificates ---

    async fn list_certs(&self) -> Result<Vec<String>, VaultError> {
        self.client
            .exec_list(&format!("{}/certs", self.mount))
            .await
    }

    async fn read_cert(&self, serial: &str) -> Result<PkiCertificateEntry, VaultError> {
        self.client
            .exec_with_data(
                Method::GET,
                &format!("{}/cert/{}", self.mount, encode_path(serial)),
                None,
            )
            .await
    }

    // --- URLs config ---

    async fn set_urls(&self, config: &PkiUrlsConfig) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/urls", self.mount),
                Some(&body),
            )
            .await
    }

    async fn read_urls(&self) -> Result<PkiUrlsConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config/urls", self.mount), None)
            .await
    }

    // --- Revocation / CRL ---

    async fn revoke(&self, serial: &str) -> Result<PkiRevocationInfo, VaultError> {
        let body = serde_json::json!({ "serial_number": serial });
        self.client
            .exec_with_data(Method::POST, &format!("{}/revoke", self.mount), Some(&body))
            .await
    }

    async fn revoke_with_key(
        &self,
        serial: &str,
        private_key: &SecretString,
    ) -> Result<PkiRevocationInfo, VaultError> {
        use secrecy::ExposeSecret;
        let body = serde_json::json!({
            "serial_number": serial,
            "private_key": private_key.expose_secret(),
        });
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/revoke-with-key", self.mount),
                Some(&body),
            )
            .await
    }

    async fn rotate_crl(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(Method::POST, &format!("{}/crl/rotate", self.mount), None)
            .await
    }

    // --- Tidy ---

    async fn tidy(&self, params: &PkiTidyParams) -> Result<(), VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_empty(Method::POST, &format!("{}/tidy", self.mount), Some(&body))
            .await
    }

    async fn tidy_status(&self) -> Result<PkiTidyStatus, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/tidy-status", self.mount), None)
            .await
    }

    // --- Issuer update ---

    async fn update_issuer(
        &self,
        issuer_ref: &str,
        params: &PkiIssuerUpdateParams,
    ) -> Result<PkiIssuerInfo, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/issuer/{}", self.mount, encode_path(issuer_ref)),
                Some(&body),
            )
            .await
    }

    // --- Cross-signing ---

    async fn cross_sign_intermediate(
        &self,
        params: &PkiCrossSignRequest,
    ) -> Result<PkiCertificate, VaultError> {
        let body = to_body(params)?;
        self.client
            .exec_with_data(
                Method::POST,
                &format!("{}/intermediate/cross-sign", self.mount),
                Some(&body),
            )
            .await
    }

    // --- ACME (Vault 1.14+) ---

    async fn read_acme_config(&self) -> Result<PkiAcmeConfig, VaultError> {
        self.client
            .exec_with_data(Method::GET, &format!("{}/config/acme", self.mount), None)
            .await
    }

    async fn write_acme_config(&self, config: &PkiAcmeConfig) -> Result<(), VaultError> {
        let body = to_body(config)?;
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/config/acme", self.mount),
                Some(&body),
            )
            .await
    }

    // --- Delta CRL ---

    async fn rotate_delta_crl(&self) -> Result<(), VaultError> {
        self.client
            .exec_empty(
                Method::POST,
                &format!("{}/crl/rotate-delta", self.mount),
                None,
            )
            .await
    }
}
