//! macOS: the Secure Enclave through Security.framework, the identifiers of the boot and of
//! the login session, and the Time Machine exclusion attribute (SPEC §8.2, §17.28). The only
//! unsafe code of the key store.
//!
//! No Keychain is involved: the enclave key is not permanent. It exists only as the opaque
//! blob the framework hands out for it (the attribute `toid` — what CryptoKit calls a key's
//! `dataRepresentation`), which only the Secure Enclave of the Mac that made it can use. No
//! call here can show a dialog: the key carries no user-presence, biometry or password
//! condition.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::access_control::{
    SecAccessControlCreateWithFlags, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
};
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs,
};
use security_framework_sys::key::{
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation, SecKeyCopyPublicKey,
    SecKeyCreateDecryptedData, SecKeyCreateEncryptedData, SecKeyCreateRandomKey,
    SecKeyCreateWithData, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
};
use zeroize::Zeroizing;

use super::seal::{OTHER_KEY, SealError, Sealer};

// What Security.framework offers beyond the declarations of `security-framework-sys`. This
// block and the imports above are the whole foreign surface of the key store; a test reads
// this file and fails if a Keychain or code-signing call ever appears in it.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// `SessionGetInfo(callerSecuritySession, &id, &attributes)`.
    fn SessionGetInfo(session: u32, session_id: *mut u32, attributes: *mut u32) -> i32;
}

/// `kSecAccessControlPrivateKeyUsage`: the key may be used for private-key operations, with
/// no further condition.
const PRIVATE_KEY_USAGE: usize = 1 << 30;
/// `callerSecuritySession`.
const CALLER_SESSION: u32 = u32::MAX;
/// `kSecAttrTokenOID`: the attribute that holds — and, on reload, names — a token key's blob.
/// A private-header constant with this value in every macOS since the Secure Enclave exists;
/// if a later macOS stops exposing it, `create` fails with a clear text and nothing is sealed.
const TOKEN_OID: &str = "toid";

/// An owned `SecKeyRef`.
struct Key(SecKeyRef);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null key this value owns one reference of.
        unsafe { core_foundation::base::CFRelease(self.0 as CFTypeRef) }
    }
}

/// A `CFStringRef` constant of the framework as a `CFString` (not owned: retained here).
fn constant(s: CFStringRef) -> CFString {
    // SAFETY: the framework's string constants are valid for the life of the process.
    unsafe { CFString::wrap_under_get_rule(s) }
}

fn error_text(what: &str, e: CFErrorRef) -> SealError {
    if e.is_null() {
        return SealError(format!("{what} failed without an error"));
    }
    // SAFETY: a non-null error returned through an out-parameter is owned by the caller.
    let e = unsafe { CFError::wrap_under_create_rule(e) };
    SealError(format!(
        "{what}: {} error {} ({})",
        e.domain(),
        e.code(),
        e.description()
    ))
}

/// Takes ownership of a `CFDataRef` a "Create" or "Copy" function returned.
fn owned_data(what: &str, d: CFDataRef, e: CFErrorRef) -> Result<CFData, SealError> {
    if d.is_null() {
        return Err(error_text(what, e));
    }
    // SAFETY: non-null, and owned by the caller under the create rule.
    Ok(unsafe { CFData::wrap_under_create_rule(d) })
}

fn algorithm() -> CFStringRef {
    // SAFETY: a string constant of the framework.
    unsafe { kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM }
}

/// `{ key type: EC P-256, key class: <class> }`.
fn key_attributes(class: CFStringRef) -> CFMutableDictionary<CFString, CFType> {
    let mut attrs = CFMutableDictionary::new();
    // SAFETY (all `k…` reads below): string constants of the framework.
    attrs.set(
        constant(unsafe { kSecAttrKeyType }),
        constant(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).as_CFType(),
    );
    attrs.set(
        constant(unsafe { kSecAttrKeyClass }),
        constant(class).as_CFType(),
    );
    attrs
}

/// The X9.63 form of a key's public half (65 bytes for P-256: `04 || X || Y`).
fn public_of(key: &Key) -> Result<Vec<u8>, SealError> {
    // SAFETY: `key.0` is a valid key; the result is owned (copy rule) or null.
    let public = unsafe { SecKeyCopyPublicKey(key.0) };
    if public.is_null() {
        return Err(SealError("the key has no public half".into()));
    }
    let public = Key(public);
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: a valid key and a valid out-pointer.
    let raw = unsafe { SecKeyCopyExternalRepresentation(public.0, &mut e) };
    Ok(owned_data("SecKeyCopyExternalRepresentation", raw, e)?
        .bytes()
        .to_vec())
}

/// A key object from the X9.63 form of a public key.
fn public_key(public: &[u8]) -> Result<Key, SealError> {
    // SAFETY: a string constant of the framework.
    let attrs = key_attributes(unsafe { kSecAttrKeyClassPublic });
    let data = CFData::from_buffer(public);
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: valid data and dictionary for the length of the call; the result is owned.
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef() as _,
            &mut e,
        )
    };
    if key.is_null() {
        return Err(error_text("SecKeyCreateWithData (public key)", e));
    }
    Ok(Key(key))
}

fn encrypt(public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
    let key = public_key(public)?;
    let data = CFData::from_buffer(plain);
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: valid key, algorithm constant and data; the result is owned.
    let sealed = unsafe {
        SecKeyCreateEncryptedData(key.0, algorithm(), data.as_concrete_TypeRef(), &mut e)
    };
    Ok(owned_data("SecKeyCreateEncryptedData", sealed, e)?
        .bytes()
        .to_vec())
}

fn decrypt(key: &Key, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let data = CFData::from_buffer(sealed);
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: valid key, algorithm constant and data; the result is owned.
    let plain = unsafe {
        SecKeyCreateDecryptedData(key.0, algorithm(), data.as_concrete_TypeRef(), &mut e)
    };
    let plain = owned_data("SecKeyCreateDecryptedData", plain, e)?;
    Ok(Zeroizing::new(plain.bytes().to_vec()))
}

/// A new P-256 key that is not stored anywhere: in the Secure Enclave (`enclave`), protected
/// "after first unlock, this device only" with `privateKeyUsage` and nothing else, or in
/// software.
fn new_key(enclave: bool) -> Result<Key, SealError> {
    let mut private: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
    // SAFETY (all `k…` reads below): string constants of the framework.
    private.set(
        constant(unsafe { kSecAttrIsPermanent }),
        CFBoolean::false_value().as_CFType(),
    );
    let mut params: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
    params.set(
        constant(unsafe { kSecAttrKeyType }),
        constant(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).as_CFType(),
    );
    params.set(
        constant(unsafe { kSecAttrKeySizeInBits }),
        CFNumber::from(256i32).as_CFType(),
    );
    if enclave {
        params.set(
            constant(unsafe { kSecAttrTokenID }),
            constant(unsafe { kSecAttrTokenIDSecureEnclave }).as_CFType(),
        );
        let mut e: CFErrorRef = ptr::null_mut();
        // SAFETY: the default allocator, a constant, plain flags and a valid out-pointer.
        let access = unsafe {
            SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFTypeRef,
                PRIVATE_KEY_USAGE as _,
                &mut e,
            )
        };
        if access.is_null() {
            return Err(error_text("SecAccessControlCreateWithFlags", e));
        }
        // SAFETY: non-null, and owned by the caller under the create rule.
        let access = unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) };
        private.set(constant(unsafe { kSecAttrAccessControl }), access);
    }
    params.set(
        constant(unsafe { kSecPrivateKeyAttrs }),
        private.as_CFType(),
    );
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: a valid dictionary for the length of the call; the result is owned.
    let key = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef() as _, &mut e) };
    if key.is_null() {
        return Err(error_text("SecKeyCreateRandomKey", e));
    }
    Ok(Key(key))
}

/// The key's blob: the attribute `toid` of `SecKeyCopyAttributes`.
fn token_blob(key: &Key) -> Result<Zeroizing<Vec<u8>>, SealError> {
    // SAFETY: a valid key; the dictionary is owned (copy rule) or null.
    let attrs = unsafe { SecKeyCopyAttributes(key.0) };
    if attrs.is_null() {
        return Err(SealError("SecKeyCopyAttributes returned nothing".into()));
    }
    // SAFETY: non-null, owned; keys are strings and values are CF objects.
    let attrs: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(attrs) };
    let blob = attrs
        .find(CFString::from_static_string(TOKEN_OID))
        .and_then(|value| value.downcast::<CFData>())
        .ok_or_else(|| {
            SealError(
                "this macOS does not hand out the Secure Enclave key's blob (no `toid` \
                 attribute): the key cannot be kept"
                    .into(),
            )
        })?;
    Ok(Zeroizing::new(blob.bytes().to_vec()))
}

/// The enclave key of `blob`. The blob has to be in the ATTRIBUTES: handed over only as the
/// data argument, the framework makes a new, different key without an error — which is why
/// every caller compares the public half afterwards.
fn enclave_key(blob: &[u8]) -> Result<Key, SealError> {
    // SAFETY (the `k…` reads): string constants of the framework.
    let mut attrs = key_attributes(unsafe { kSecAttrKeyClassPrivate });
    attrs.set(
        constant(unsafe { kSecAttrTokenID }),
        constant(unsafe { kSecAttrTokenIDSecureEnclave }).as_CFType(),
    );
    let data = CFData::from_buffer(blob);
    attrs.set(CFString::from_static_string(TOKEN_OID), data.as_CFType());
    let mut e: CFErrorRef = ptr::null_mut();
    // SAFETY: valid data and dictionary for the length of the call; the result is owned.
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef() as _,
            &mut e,
        )
    };
    if key.is_null() {
        return Err(error_text("SecKeyCreateWithData (Secure Enclave key)", e));
    }
    Ok(Key(key))
}

fn check_public(key: &Key, public: &[u8]) -> Result<(), SealError> {
    if public_of(key)? == public {
        Ok(())
    } else {
        Err(SealError(OTHER_KEY.into()))
    }
}

/// The Secure Enclave of this Mac.
pub(crate) struct EnclaveSealer;

impl Sealer for EnclaveSealer {
    fn name(&self) -> &'static str {
        "Secure Enclave"
    }

    fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError> {
        let key = new_key(true)?;
        let blob = token_blob(&key)?;
        let public = public_of(&key)?;
        // What will be done at every later start: the blob must give this very key back.
        check_public(&enclave_key(&blob)?, &public)?;
        Ok((blob, public))
    }

    fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
        encrypt(public, plain)
    }

    fn open(
        &self,
        blob: &[u8],
        public: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let key = enclave_key(blob)?;
        check_public(&key, public)?;
        decrypt(&key, sealed)
    }
}

/// A software P-256 key through the same framework calls: what a machine without a Secure
/// Enclave (a hosted CI runner) can test of the code above. The "blob" is the private key
/// itself — test only, selected by `GCLONE_TEST_KEYSTORE_SEALER=soft` in debug builds.
#[cfg(any(test, debug_assertions))]
pub(crate) struct SoftKeySealer;

#[cfg(any(test, debug_assertions))]
impl SoftKeySealer {
    fn key(blob: &[u8]) -> Result<Key, SealError> {
        // SAFETY: a string constant of the framework.
        let attrs = key_attributes(unsafe { kSecAttrKeyClassPrivate });
        let data = CFData::from_buffer(blob);
        let mut e: CFErrorRef = ptr::null_mut();
        // SAFETY: valid data and dictionary for the length of the call; the result is owned.
        let key = unsafe {
            SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attrs.as_concrete_TypeRef() as _,
                &mut e,
            )
        };
        if key.is_null() {
            return Err(error_text("SecKeyCreateWithData (software key)", e));
        }
        Ok(Key(key))
    }
}

#[cfg(any(test, debug_assertions))]
impl Sealer for SoftKeySealer {
    fn name(&self) -> &'static str {
        "software key (test stand-in)"
    }

    fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError> {
        let key = new_key(false)?;
        let mut e: CFErrorRef = ptr::null_mut();
        // SAFETY: a valid key and a valid out-pointer; the result is owned.
        let raw = unsafe { SecKeyCopyExternalRepresentation(key.0, &mut e) };
        let raw = owned_data("SecKeyCopyExternalRepresentation", raw, e)?;
        let blob = Zeroizing::new(raw.bytes().to_vec());
        let public = public_of(&key)?;
        check_public(&Self::key(&blob)?, &public)?;
        Ok((blob, public))
    }

    fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
        encrypt(public, plain)
    }

    fn open(
        &self,
        blob: &[u8],
        public: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let key = Self::key(blob)?;
        check_public(&key, public)?;
        decrypt(&key, sealed)
    }
}

// ---------------------------------------------------------------------------------------------
// boot, session, system version
// ---------------------------------------------------------------------------------------------

fn sysctl_string(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let mut buf = [0u8; 128];
    let mut len = buf.len();
    // SAFETY: `name` is NUL-terminated, `buf` is writable for `len` bytes, no new value is set.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let text = &buf[..len.min(buf.len())];
    let text = text.split(|b| *b == 0).next().unwrap_or_default();
    let text = String::from_utf8_lossy(text).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// `kern.bootsessionuuid`: names this boot without depending on the clock.
pub(crate) fn boot_session() -> Option<String> {
    sysctl_string("kern.bootsessionuuid")
}

/// `kern.osproductversion`, e.g. `15.2`.
pub(crate) fn os_version() -> Option<String> {
    sysctl_string("kern.osproductversion")
}

/// The attribute word of the caller's security session (`SessionGetInfo`): `0x10` = the
/// session has graphic access, `0x20` = it has a terminal, `0x1000` = it is remote.
pub(crate) fn session_attributes() -> Option<u32> {
    let (mut id, mut attributes) = (0u32, 0u32);
    // SAFETY: two valid out-pointers; the call only reads the caller's session.
    let status = unsafe { SessionGetInfo(CALLER_SESSION, &mut id, &mut attributes) };
    (status == 0).then_some(attributes)
}

// ---------------------------------------------------------------------------------------------
// Time Machine
// ---------------------------------------------------------------------------------------------

const BACKUP_ATTR: &str = "com.apple.metadata:com_apple_backup_excludeItem";

/// What `tmutil addexclusion` writes into the attribute: a binary property list of the one
/// string `com.apple.backupd` (61 bytes).
pub(crate) fn backup_attr_value() -> Vec<u8> {
    const OWNER: &[u8] = b"com.apple.backupd";
    let mut v = b"bplist00".to_vec();
    // an ASCII string of 15 bytes or more: marker 0x5F, then the length as a one-byte integer
    v.extend_from_slice(&[0x5F, 0x10, OWNER.len() as u8]);
    v.extend_from_slice(OWNER);
    let offset_table = v.len() as u8;
    v.push(8); // the offset of object 0
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]); // offsets and references of one byte each
    v.extend_from_slice(&1u64.to_be_bytes()); // one object
    v.extend_from_slice(&0u64.to_be_bytes()); // the top object
    v.extend_from_slice(&u64::from(offset_table).to_be_bytes());
    v
}

fn c_path(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)
}

/// Whether `dir` carries the exclusion attribute (any value).
pub(crate) fn excluded_from_backups(dir: &Path) -> std::io::Result<bool> {
    let (path, name) = (c_path(dir)?, c_path(Path::new(BACKUP_ATTR))?);
    // SAFETY: two NUL-terminated strings; a null buffer of size 0 asks for the length only.
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len >= 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOATTR) => Ok(false),
        _ => Err(e),
    }
}

/// Sets the exclusion attribute on the directory `dir` — on the directory, because the files
/// in it are replaced by rename and an attribute on a file would be lost with the first one.
/// `Ok(true)`: it was set now; `Ok(false)`: it was there already.
pub(crate) fn exclude_from_backups(dir: &Path) -> std::io::Result<bool> {
    if excluded_from_backups(dir)? {
        return Ok(false);
    }
    let (path, name) = (c_path(dir)?, c_path(Path::new(BACKUP_ATTR))?);
    let value = backup_attr_value();
    // SAFETY: two NUL-terminated strings and a buffer that is valid for `value.len()` bytes.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(true)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::seal::probe;

    /// The whole FFI path with a software key: dictionary building, ECIES both ways, the
    /// public-key comparison, damaged inputs. Runs on any Mac, hosted CI runners included.
    #[test]
    fn a_software_key_goes_through_the_same_framework_calls() {
        let sealer = SoftKeySealer;
        let (blob, public) = sealer.create().expect("a software P-256 key");
        assert_eq!(public.len(), 65, "X9.63: 04 || X || Y");
        assert_eq!(public[0], 4);
        assert_eq!(blob.len(), 97, "X9.63 with the private scalar");
        let plain = b"{\"version\":1,\"keys\":[]}".to_vec();
        let sealed = sealer.seal(&public, &plain).unwrap();
        // ephemeral public key (65) + ciphertext + GCM tag (16)
        assert_eq!(sealed.len(), plain.len() + 81);
        assert_eq!(
            sealer.open(&blob, &public, &sealed).unwrap().as_slice(),
            plain
        );
        // sealing is randomised
        assert_ne!(sealer.seal(&public, &plain).unwrap(), sealed);
        probe(&sealer).unwrap();

        // one key, two sealings
        let other = sealer.seal(&public, b"second").unwrap();
        assert_eq!(
            sealer.open(&blob, &public, &other).unwrap().as_slice(),
            b"second"
        );

        // damaged ciphertext: an error, never another plaintext
        for at in [0, 70, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(sealer.open(&blob, &public, &bad).is_err(), "byte {at}");
        }
        assert!(sealer.open(&blob, &public, &sealed[..40]).is_err());
        assert!(sealer.open(&blob, &public, b"").is_err());
        // a damaged or cut-off key
        assert!(sealer.open(&blob[..50], &public, &sealed).is_err());
        assert!(sealer.open(b"", &public, &sealed).is_err());
        // garbage as a public key
        assert!(sealer.seal(b"not a key", &plain).is_err());
    }

    /// A key that reloads to another public half than the stored one must not be used.
    #[test]
    fn a_key_with_another_public_half_is_refused_before_anything_is_decrypted() {
        let sealer = SoftKeySealer;
        let (blob_a, public_a) = sealer.create().unwrap();
        let (blob_b, _) = sealer.create().unwrap();
        let sealed = sealer.seal(&public_a, b"x").unwrap();
        assert_eq!(
            sealer.open(&blob_b, &public_a, &sealed).unwrap_err().0,
            OTHER_KEY
        );
        assert!(sealer.open(&blob_a, &public_a, &sealed).is_ok());
    }

    #[test]
    fn the_backup_attribute_is_set_on_a_directory_and_read_back() {
        let value = backup_attr_value();
        assert_eq!(value.len(), 61, "what tmutil addexclusion writes");
        assert!(value.starts_with(b"bplist00\x5f\x10\x11com.apple.backupd\x08"));
        assert_eq!(value[60], 28, "the offset table follows the string");

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        assert!(!excluded_from_backups(&dir).unwrap());
        assert!(exclude_from_backups(&dir).unwrap(), "set now");
        assert!(excluded_from_backups(&dir).unwrap());
        assert!(!exclude_from_backups(&dir).unwrap(), "already there");

        // read back with the system's own tool
        let out = std::process::Command::new("/usr/bin/xattr")
            .args(["-px", BACKUP_ATTR])
            .arg(&dir)
            .output()
            .expect("xattr");
        let hex: String = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .collect();
        assert_eq!(hex.to_lowercase(), crate::util::hex(&value));

        // it stays when a file inside is replaced by rename
        std::fs::write(dir.join("a"), b"1").unwrap();
        std::fs::write(dir.join("b"), b"2").unwrap();
        std::fs::rename(dir.join("b"), dir.join("a")).unwrap();
        assert!(excluded_from_backups(&dir).unwrap());
        assert!(excluded_from_backups(&tmp.path().join("absent")).is_err());
    }

    #[test]
    fn boot_and_session_identifiers_are_there_and_stable() {
        let boot = boot_session().expect("kern.bootsessionuuid");
        assert_eq!(boot.len(), 36, "a UUID: {boot}");
        assert_eq!(boot_session().as_deref(), Some(boot.as_str()));
        let os = os_version().expect("kern.osproductversion");
        assert!(
            os.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "{os}"
        );
        // Present in every session of a logged-in user; a daemon context may have none.
        if let Some(word) = session_attributes() {
            assert_eq!(session_attributes(), Some(word));
        }
    }

    /// The key store must stay free of the Keychain and of code-signing checks: no dialog, no
    /// dependence on a signature (§17.28). Looks at the source of this module's foreign
    /// surface — the imports and the `extern` block — not at prose.
    #[test]
    fn no_keychain_and_no_code_signing_call_is_declared_or_imported() {
        let source = include_str!("macos.rs");
        let code: String = source
            .lines()
            .take_while(|l| !l.starts_with("#[cfg(test)]"))
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in [
            "SecItem",
            "SecKeychain",
            "SecCode",
            "SecTrust",
            "SecAccessCreate",
        ] {
            assert!(
                !code.contains(banned),
                "{banned}* appears in keystore/macos.rs"
            );
        }
        // every foreign function this module may call
        let allowed = [
            "SecKeyCreateRandomKey",
            "SecKeyCopyAttributes",
            "SecKeyCreateWithData",
            "SecKeyCopyPublicKey",
            "SecKeyCopyExternalRepresentation",
            "SecKeyCreateEncryptedData",
            "SecKeyCreateDecryptedData",
            "SecAccessControlCreateWithFlags",
            "SessionGetInfo",
        ];
        let mut found = std::collections::BTreeSet::new();
        for word in code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            let framework_call = word.starts_with("Sec")
                && word.chars().nth(3).is_some_and(|c| c.is_ascii_uppercase())
                && !word.ends_with("Ref");
            if framework_call || word == "SessionGetInfo" {
                found.insert(word);
            }
        }
        for word in &found {
            assert!(
                allowed.contains(word),
                "{word} is not on the list of §17.28"
            );
        }
        for word in allowed {
            assert!(
                found.contains(word),
                "{word} is no longer used: update §17.28"
            );
        }
    }

    /// The real Secure Enclave. Runs where there is one; elsewhere it says so and passes —
    /// unless `GCLONE_REQUIRE_ENCLAVE=1` (the owner's Mac, the release checklist), where a
    /// skip is a failure. Creates non-permanent keys only: nothing is stored anywhere.
    #[test]
    fn hardware_the_secure_enclave_seals_and_opens() {
        let sealer = EnclaveSealer;
        let (blob, public) = match sealer.create() {
            Ok(key) => key,
            Err(e) => {
                assert!(
                    std::env::var_os("GCLONE_REQUIRE_ENCLAVE").is_none_or(|v| v != "1"),
                    "GCLONE_REQUIRE_ENCLAVE=1, but no Secure Enclave key can be made here: {e}"
                );
                eprintln!("SKIPPED: no Secure Enclave on this machine ({e})");
                return;
            }
        };
        assert_eq!(public.len(), 65);
        assert!(
            blob.len() > 100,
            "an opaque blob, not a private key: {}",
            blob.len()
        );
        let sealed = sealer.seal(&public, b"hello enclave").unwrap();
        assert_eq!(sealed.len(), 13 + 81);
        assert_eq!(
            sealer.open(&blob, &public, &sealed).unwrap().as_slice(),
            b"hello enclave"
        );
        // one key for two sealings (the trial's test value, later the secrets)
        let document = vec![b'{'; 1600];
        let second = sealer.seal(&public, &document).unwrap();
        assert_eq!(
            sealer.open(&blob, &public, &second).unwrap().as_slice(),
            document
        );
        assert_eq!(
            sealer.open(&blob, &public, &sealed).unwrap().as_slice(),
            b"hello enclave"
        );
        probe(&sealer).unwrap();

        // a damaged blob, a blob of another key, damaged ciphertext
        let mut bad = blob.to_vec();
        let middle = bad.len() / 2;
        bad[middle] ^= 1;
        assert!(sealer.open(&bad, &public, &sealed).is_err());
        assert!(sealer.open(&blob[..20], &public, &sealed).is_err());
        let (other_blob, _) = sealer.create().unwrap();
        assert_eq!(
            sealer.open(&other_blob, &public, &sealed).unwrap_err().0,
            OTHER_KEY
        );
        let mut bad = sealed.clone();
        bad[80] ^= 1;
        assert!(sealer.open(&blob, &public, &bad).is_err());

        // 16 opens at once
        let (blob, public, sealed) = (blob.to_vec(), public.clone(), sealed.clone());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (blob, public, sealed) = (blob.clone(), public.clone(), sealed.clone());
                std::thread::spawn(move || {
                    EnclaveSealer
                        .open(&blob, &public, &sealed)
                        .map(|p| p.to_vec())
                })
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap().unwrap(), b"hello enclave");
        }
        eprintln!(
            "hardware: Secure Enclave key of {} bytes sealed and opened",
            blob.len()
        );
    }
}
