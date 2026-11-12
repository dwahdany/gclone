//! Data blobs (SPEC §4.5, §9.4). v1 blobs have no trailer.
//!
//! ```text
//! blob     = member_0 ‖ member_1 ‖ … ‖ member_{k-1}
//! member_j = Stream(type Data) of one file's content
//! ```

use crate::consts::CHUNK_LOG2;
use crate::crypto::ciphertext_len;
use crate::types::{BlobId, DeviceId};

/// Reserved for the future manifest trailer; unused in v1.
pub const RESERVED_FOOTER_MAGIC: [u8; 8] = *b"GCBLOB01";

/// A blob's object name is its id: 32 lowercase hex digits.
pub fn blob_name(id: &BlobId) -> String {
    id.hex()
}

pub fn parse_blob_name(name: &str) -> Option<BlobId> {
    BlobId::from_hex(name)
}

/// `<dev16>-<n:04>`: the device's n-th data folder, decimal, at least four digits.
pub fn data_folder_name(device: DeviceId, n: u32) -> String {
    format!("{}-{n:04}", device.hex())
}

/// `Σ ciphertext_len(size, CHUNK_LOG2)`: the exact blob length, known before streaming starts.
pub fn blob_len(member_plain_sizes: &[u64]) -> u64 {
    member_plain_sizes.iter().fold(0, |sum, &size| {
        sum.saturating_add(ciphertext_len(size, CHUNK_LOG2))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let id = BlobId(std::array::from_fn(|i| 0xa0 + i as u8));
        assert_eq!(blob_name(&id), "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        assert_eq!(parse_blob_name(&blob_name(&id)), Some(id));
        for bad in [
            "",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaea",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00",
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
            "g0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        ] {
            assert_eq!(parse_blob_name(bad), None, "{bad}");
        }
        let dev = DeviceId([1, 2, 3, 4, 5, 6, 7, 0xff]);
        assert_eq!(data_folder_name(dev, 0), "01020304050607ff-0000");
        assert_eq!(data_folder_name(dev, 12), "01020304050607ff-0012");
        assert_eq!(data_folder_name(dev, 123_456), "01020304050607ff-123456");
    }

    #[test]
    fn blob_len_sums_member_lengths() {
        assert_eq!(blob_len(&[]), 0);
        assert_eq!(blob_len(&[1]), 60 + 1 + 16);
        assert_eq!(
            blob_len(&[65536, 65537]),
            (60 + 65536 + 16) + (60 + 65537 + 32)
        );
    }
}
