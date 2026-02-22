use secrecy::SecretString;
use vault_client_rs::VaultClient;
use wiremock::MockServer;

pub async fn build_test_client(server: &MockServer) -> VaultClient {
    VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::new("test-token".into()))
        .max_retries(0)
        .build()
        .unwrap()
}
