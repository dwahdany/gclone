//! Vault descriptor `gclone-vault.json` — a plaintext, untrusted hint (SPEC §3.3, §9.4).
//! The authoritative vault identity is the `vault_id` inside every authenticated index object.

use serde::{Deserialize, Serialize};

use super::unhex_array;
use crate::error::FormatError;
use crate::util;

pub const DESCRIPTOR_NAME: &str = "gclone-vault.json";
pub const README_NAME: &str = "README.txt";
pub const README_TEXT: &str =
    "Encrypted gclone vault. Do not rename, edit or delete anything in here.\n";
pub const INDEX_FOLDER: &str = "index";
pub const DATA_FOLDER: &str = "data";
pub const SUPPORTED_FORMAT: u16 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDescriptor {
    pub gclone_vault: u32,
    pub min_reader: u32,
    pub vault_id: String,
    pub created_ms: u64,
}

impl VaultDescriptor {
    /// A descriptor of the format this build writes, created now.
    pub fn new(vault_id: [u8; 16]) -> Self {
        VaultDescriptor {
            gclone_vault: u32::from(SUPPORTED_FORMAT),
            min_reader: u32::from(SUPPORTED_FORMAT),
            vault_id: util::hex(&vault_id),
            created_ms: util::now_ms(),
        }
    }

    /// One line of JSON.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(self)
            .expect("a struct of three integers and a string serializes to JSON");
        bytes.push(b'\n');
        bytes
    }

    /// Unknown fields are ignored; `vault_id` must be 32 lowercase hex digits. Whether this build
    /// can read the vault (`min_reader`) is the caller's check (§3.3).
    pub fn parse(b: &[u8]) -> Result<Self, FormatError> {
        let d: VaultDescriptor = serde_json::from_slice(b)
            .map_err(|e| FormatError::Decode(format!("vault descriptor: {e}")))?;
        if unhex_array::<16>(&d.vault_id).is_none() {
            return Err(FormatError::Decode(
                "vault descriptor: vault_id is not 32 lowercase hex digits".into(),
            ));
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id: [u8; 16] = std::array::from_fn(|i| 0xa0 + i as u8);
        let d = VaultDescriptor::new(id);
        assert_eq!((d.gclone_vault, d.min_reader), (1, 1));
        assert_eq!(d.vault_id, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        assert!(d.created_ms > 1_700_000_000_000);
        let bytes = d.to_bytes();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let back = VaultDescriptor::parse(&bytes).unwrap();
        assert_eq!(
            (
                back.gclone_vault,
                back.min_reader,
                back.vault_id,
                back.created_ms
            ),
            (d.gclone_vault, d.min_reader, d.vault_id, d.created_ms)
        );
    }

    #[test]
    fn parses_the_spec_literal_and_ignores_unknown_fields() {
        let d = VaultDescriptor::parse(
            br#"{ "gclone_vault": 1, "min_reader": 1, "vault_id": "000102030405060708090a0b0c0d0e0f", "created_ms": 1794400000000 }"#,
        )
        .unwrap();
        assert_eq!(d.created_ms, 1_794_400_000_000);
        let d = VaultDescriptor::parse(
            br#"{"gclone_vault":2,"min_reader":2,"vault_id":"000102030405060708090a0b0c0d0e0f","created_ms":5,"later":[1]}"#,
        )
        .unwrap();
        assert_eq!((d.gclone_vault, d.min_reader), (2, 2));
    }

    #[test]
    fn rejects() {
        for bad in [
            &b""[..],
            b"not json",
            b"{}",
            br#"{"gclone_vault":1,"min_reader":1,"vault_id":"00","created_ms":5}"#,
            br#"{"gclone_vault":1,"min_reader":1,"vault_id":"000102030405060708090A0B0C0D0E0F","created_ms":5}"#,
            br#"{"gclone_vault":1,"min_reader":1,"vault_id":"000102030405060708090a0b0c0d0e0f"}"#,
            br#"{"gclone_vault":-1,"min_reader":1,"vault_id":"000102030405060708090a0b0c0d0e0f","created_ms":5}"#,
        ] {
            assert!(
                matches!(VaultDescriptor::parse(bad), Err(FormatError::Decode(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
