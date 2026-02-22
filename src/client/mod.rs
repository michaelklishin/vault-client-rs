mod async_client;

#[cfg(feature = "blocking")]
pub(crate) mod blocking_client;

pub(crate) use async_client::{encode_path, to_body};
pub use async_client::{ClientBuilder, VaultClient};
