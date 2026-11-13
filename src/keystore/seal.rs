//! Sealing a device's secrets to a key that cannot leave the machine (SPEC §8.2).
//!
//! [`Sealer`] is the one interface the key store uses. The real implementation is the Secure
//! Enclave of a Mac (`super::macos::EnclaveSealer`); [`FakeSealer`] stands in for it in tests
//! on every platform and is not part of a release build.

use zeroize::Zeroizing;

/// Why a sealer could not do what was asked. The text is the platform's own error, for the
/// user and for the trial's record; it never holds key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealError(pub String);

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SealError {}

/// The text of [`SealError`] when a reloaded key is not the one the data was sealed to.
#[cfg(any(test, debug_assertions, target_os = "macos"))]
pub(crate) const OTHER_KEY: &str =
    "the stored key blob gives another key than the one the secrets were sealed to";

pub(crate) trait Sealer: Send + Sync {
    /// What holds the keys, for messages: "Secure Enclave".
    fn name(&self) -> &'static str;
    /// A new key: (blob, public). Err = this session cannot make one.
    fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError>;
    /// Needs no key blob and no call into the hardware.
    fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError>;
    /// Reloads the blob, checks it against `public`, decrypts.
    fn open(
        &self,
        blob: &[u8],
        public: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError>;
}

/// Creates a key, seals a few bytes to it and opens them: can this process, in this session,
/// use `sealer` at all? What tells a dead key from a session without access (§8.2).
pub(crate) fn probe(sealer: &dyn Sealer) -> Result<(), SealError> {
    let (blob, public) = sealer.create()?;
    let plain: [u8; 16] = crate::util::random();
    let sealed = sealer.seal(&public, &plain)?;
    let back = sealer.open(&blob, &public, &sealed)?;
    if back.as_slice() == plain {
        Ok(())
    } else {
        Err(SealError(
            "a value sealed to a new key did not open to itself".into(),
        ))
    }
}

#[cfg(any(test, debug_assertions))]
pub(crate) use fake::{FakeFail, FakeSealer};

#[cfg(any(test, debug_assertions))]
mod fake {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use chacha20poly1305::aead::Aead as _;
    use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305};
    use zeroize::Zeroizing;

    use super::{OTHER_KEY, SealError, Sealer};
    use crate::util;

    /// What a [`FakeSealer`] refuses, as `GCLONE_TEST_KEYSTORE_FAIL` names it.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(crate) enum FakeFail {
        /// No key can be made: a machine without the hardware.
        Create,
        /// Nothing opens, a key made a moment ago included: a session without access.
        Open,
        /// Keys made by this process work, every other one does not: a dead blob.
        OpenStored,
        /// A transient failure: the first `n` opens of keys that this process did not make
        /// fail, every later one works (`open-first` = 1, `open-first-N`). A key that is
        /// intact and answers with an error once — the case in which nothing may be thrown
        /// away.
        OpenFirst(u32),
        /// Every call into the "hardware" (`create`, `open`) blocks for an hour: a framework
        /// call that does not return.
        Hang,
    }

    impl FakeFail {
        pub(crate) fn parse(text: &str) -> Option<FakeFail> {
            match text {
                "create" => Some(FakeFail::Create),
                "open" => Some(FakeFail::Open),
                "open-stored" => Some(FakeFail::OpenStored),
                "open-first" => Some(FakeFail::OpenFirst(1)),
                "hang" => Some(FakeFail::Hang),
                other => other
                    .strip_prefix("open-first-")
                    .and_then(|n| n.parse().ok())
                    .map(FakeFail::OpenFirst),
            }
        }
    }

    /// A stand-in for the Secure Enclave. A "machine" is a 32-byte secret (derived from a
    /// name): a blob is 32 random bytes with a tag under the machine's secret, so that a blob
    /// made on one machine is refused on another, as the real one is. The "public" half is a
    /// symmetric key derived from the blob: enough to seal without the blob, which is all the
    /// store relies on. Nothing here is secure, and nothing here is in a release build.
    pub(crate) struct FakeSealer {
        machine: [u8; 32],
        fail: Option<FakeFail>,
        /// The blobs this process made (`FakeFail::OpenStored` lets only these open).
        made: Mutex<HashSet<Vec<u8>>>,
        /// Opens of stored blobs so far (`FakeFail::OpenFirst`).
        stored_opens: std::sync::atomic::AtomicU32,
    }

    impl FakeSealer {
        pub(crate) fn new(machine: &str, fail: Option<FakeFail>) -> FakeSealer {
            FakeSealer {
                machine: blake3::derive_key("gclone test keystore: machine", machine.as_bytes()),
                fail,
                made: Mutex::new(HashSet::new()),
                stored_opens: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn public_of(seed: &[u8]) -> [u8; 32] {
            blake3::derive_key("gclone test keystore: public", seed)
        }

        /// `FakeFail::Hang`: the call does not return (for longer than any test waits).
        fn hang(&self) {
            if self.fail == Some(FakeFail::Hang) {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }

        fn cipher(public: &[u8]) -> Result<XChaCha20Poly1305, SealError> {
            let key: [u8; 32] = public
                .try_into()
                .map_err(|_| SealError("fake sealer: the public key is not 32 bytes".into()))?;
            Ok(XChaCha20Poly1305::new(&key.into()))
        }
    }

    impl Sealer for FakeSealer {
        fn name(&self) -> &'static str {
            "Secure Enclave (test stand-in)"
        }

        fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError> {
            self.hang();
            if self.fail == Some(FakeFail::Create) {
                return Err(SealError(
                    "fake sealer: no key can be made on this machine".into(),
                ));
            }
            let seed: [u8; 32] = util::random();
            let tag = blake3::keyed_hash(&self.machine, &seed);
            let mut blob = Zeroizing::new(seed.to_vec());
            blob.extend_from_slice(tag.as_bytes());
            self.made
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(blob.to_vec());
            Ok((blob, Self::public_of(&seed).to_vec()))
        }

        fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
            let nonce: [u8; 24] = util::random();
            let mut out = nonce.to_vec();
            let sealed = Self::cipher(public)?
                .encrypt(&nonce.into(), plain)
                .map_err(|_| SealError("fake sealer: cannot encrypt".into()))?;
            out.extend_from_slice(&sealed);
            Ok(out)
        }

        fn open(
            &self,
            blob: &[u8],
            public: &[u8],
            sealed: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SealError> {
            let made_here = self
                .made
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(blob);
            self.hang();
            match self.fail {
                Some(FakeFail::Open) => {
                    return Err(SealError(
                        "fake sealer: this session cannot use the key store".into(),
                    ));
                }
                Some(FakeFail::OpenStored) if !made_here => {
                    return Err(SealError("fake sealer: token error -3".into()));
                }
                Some(FakeFail::OpenFirst(n)) if !made_here => {
                    let before = self
                        .stored_opens
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if before < n {
                        return Err(SealError("fake sealer: transient token error".into()));
                    }
                }
                _ => {}
            }
            let (seed, tag) = match blob.len() {
                64 => blob.split_at(32),
                _ => return Err(SealError("fake sealer: the key blob is damaged".into())),
            };
            if !util::ct_eq(blake3::keyed_hash(&self.machine, seed).as_bytes(), tag) {
                // What the real one says for a blob of another Mac.
                return Err(SealError("fake sealer: token error -3".into()));
            }
            if Self::public_of(seed) != public {
                return Err(SealError(OTHER_KEY.into()));
            }
            if sealed.len() < 24 {
                return Err(SealError("fake sealer: the sealed data is cut off".into()));
            }
            let (nonce, body) = sealed.split_at(24);
            let nonce: [u8; 24] = nonce.try_into().expect("24 bytes");
            Self::cipher(public)?
                .decrypt(&nonce.into(), body)
                .map(Zeroizing::new)
                .map_err(|_| SealError("fake sealer: the sealed data does not open".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fake_sealer_seals_to_the_public_half_and_opens_with_the_blob() {
        let sealer = FakeSealer::new("mac-1", None);
        let (blob, public) = sealer.create().unwrap();
        let sealed = sealer.seal(&public, b"the secrets").unwrap();
        assert_ne!(&sealed[24..], b"the secrets");
        assert_eq!(
            sealer.open(&blob, &public, &sealed).unwrap().as_slice(),
            b"the secrets"
        );
        probe(&sealer).unwrap();

        // damaged inputs: an error, never another plaintext
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(sealer.open(&blob, &public, &bad).is_err());
        let mut bad_blob = blob.to_vec();
        bad_blob[3] ^= 1;
        assert!(sealer.open(&bad_blob, &public, &sealed).is_err());
        assert!(sealer.open(&blob[..40], &public, &sealed).is_err());
        assert!(sealer.open(&blob, &public, &sealed[..10]).is_err());
    }

    #[test]
    fn a_blob_of_another_machine_or_another_key_is_refused() {
        let here = FakeSealer::new("mac-1", None);
        let there = FakeSealer::new("mac-2", None);
        let (blob, public) = there.create().unwrap();
        let sealed = there.seal(&public, b"x").unwrap();
        assert!(here.open(&blob, &public, &sealed).is_err());
        // sealing needs no blob, so it works anywhere — opening does not
        let sealed_here = here.seal(&public, b"x").unwrap();
        assert!(here.open(&blob, &public, &sealed_here).is_err());
        assert_eq!(
            there.open(&blob, &public, &sealed_here).unwrap().as_slice(),
            b"x"
        );

        // a blob that reloads to another key than the one sealed to (the pitfall of §17.28)
        let (other_blob, _) = here.create().unwrap();
        let (_, public) = here.create().unwrap();
        let sealed = here.seal(&public, b"x").unwrap();
        assert_eq!(
            here.open(&other_blob, &public, &sealed).unwrap_err().0,
            OTHER_KEY
        );
    }

    #[test]
    fn the_failure_switches() {
        let (blob, public, sealed) = {
            let sealer = FakeSealer::new("mac-1", None);
            let (blob, public) = sealer.create().unwrap();
            let sealed = sealer.seal(&public, b"x").unwrap();
            (blob, public, sealed)
        };
        let no_create = FakeSealer::new("mac-1", Some(FakeFail::Create));
        assert!(no_create.create().is_err());
        assert!(probe(&no_create).is_err());
        assert!(no_create.open(&blob, &public, &sealed).is_ok());

        let no_open = FakeSealer::new("mac-1", Some(FakeFail::Open));
        assert!(no_open.open(&blob, &public, &sealed).is_err());
        assert!(probe(&no_open).is_err(), "a fresh key fails as well");

        let dead = FakeSealer::new("mac-1", Some(FakeFail::OpenStored));
        assert!(dead.open(&blob, &public, &sealed).is_err());
        probe(&dead).expect("a fresh key works");

        assert_eq!(FakeFail::parse("open-stored"), Some(FakeFail::OpenStored));
        assert_eq!(FakeFail::parse("create"), Some(FakeFail::Create));
        assert_eq!(FakeFail::parse("open"), Some(FakeFail::Open));
        assert_eq!(FakeFail::parse("nonsense"), None);
        assert_eq!(FakeFail::parse("open-first"), Some(FakeFail::OpenFirst(1)));
        assert_eq!(
            FakeFail::parse("open-first-2"),
            Some(FakeFail::OpenFirst(2))
        );
        assert_eq!(FakeFail::parse("open-first-x"), None);
        assert_eq!(FakeFail::parse("hang"), Some(FakeFail::Hang));

        // a transient failure: the stored key answers with an error twice, then works —
        // while a key made here works throughout
        let flaky = FakeSealer::new("mac-1", Some(FakeFail::OpenFirst(2)));
        probe(&flaky).expect("a fresh key works");
        assert!(flaky.open(&blob, &public, &sealed).is_err());
        assert!(flaky.open(&blob, &public, &sealed).is_err());
        assert_eq!(
            flaky.open(&blob, &public, &sealed).unwrap().as_slice(),
            b"x"
        );
    }
}
