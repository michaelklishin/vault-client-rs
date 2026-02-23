//! Serde helpers for serializing `SecretString` fields.
//!
//! `secrecy` does not provide a blanket `Serialize` for `Secret<T>`.
//! These helpers bridge the gap by exposing the secret during
//! serialization only.

use secrecy::{ExposeSecret, SecretString};
use serde::Serializer;

pub fn serialize<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(secret.expose_secret())
}

pub fn serialize_option<S: Serializer>(
    secret: &Option<SecretString>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(v) => s.serialize_str(v.expose_secret()),
        None => s.serialize_none(),
    }
}
