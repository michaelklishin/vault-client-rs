use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{Kv1Operations, VaultClient};

/// A minimal tracing layer that captures span names
struct SpanCollector {
    spans: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCollector {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.spans
            .lock()
            .unwrap()
            .push(attrs.metadata().name().to_string());
    }
}

#[tokio::test]
async fn execute_raw_emits_vault_request_span() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "foo": "bar" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let spans = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCollector {
        spans: Arc::clone(&spans),
    };

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .build()
        .unwrap();

    let _: HashMap<String, String> =
        client.kv1("secret").read("my-key").await.unwrap();

    let captured = spans.lock().unwrap();
    assert!(
        captured.iter().any(|s| s == "vault.request"),
        "expected vault.request span, got: {captured:?}"
    );
}
