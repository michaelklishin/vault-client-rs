mod async_client;

#[cfg(feature = "blocking")]
pub(crate) mod blocking_client;

pub use async_client::{ClientBuilder, VaultClient};
pub(crate) use async_client::{encode_path, to_body};
