use serde::{Deserialize, Serialize};

use crate::VaultError;

pub use secrecy::SecretString;

fn validate_vault_path(s: &str, kind: &str) -> Result<(), VaultError> {
    if s.is_empty()
        || s.contains("..")
        || s.starts_with('/')
        || s.ends_with('/')
        || s.contains('\0')
        || s.contains("%2e")
        || s.contains("%2E")
        || s.contains("%2f")
        || s.contains("%2F")
        || s.chars().any(|c| c.is_control())
    {
        return Err(VaultError::Config(format!("invalid {kind}: {s:?}")));
    }
    Ok(())
}

macro_rules! vault_path_type {
    ($Name:ident, $label:literal) => {
        impl $Name {
            pub fn new(s: impl Into<String>) -> Result<Self, VaultError> {
                let s = s.into();
                validate_vault_path(&s, $label)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $Name {
            type Error = VaultError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl TryFrom<&str> for $Name {
            type Error = VaultError;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl<'de> Deserialize<'de> for $Name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }

        impl std::fmt::Display for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// A Vault mount path like "secret" or "transit".
/// Validated: non-empty, no leading/trailing slashes, no `..` traversal,
/// no null bytes, no percent-encoded special characters, no control chars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct MountPath(String);
vault_path_type!(MountPath, "mount path");

/// A secret path within a mount. Uses the same validation as MountPath.
/// Exists as a distinct type for semantic clarity at call sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SecretPath(String);
vault_path_type!(SecretPath, "secret path");
