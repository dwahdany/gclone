//! Opening and hashing local sources (SPEC §5.4, §6.2, §9.8) — owned by WP5.
//!
//! Every read of a source file follows one rule: `fstat` on the open descriptor, read exactly
//! the size that `fstat` reported, then check that the descriptor is at end of file and that a
//! second `fstat` equals the first. Anything else means the file changed while it was read.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::consts::MIB;
use crate::error::TransferError;
use crate::types::StatSig;
use crate::util;

/// Plaintext is read from disk in pieces of this size (§6.2).
pub(crate) const READ_SIZE: usize = MIB as usize;

/// The payload of the error for a path that opened but is no regular file.
#[derive(Debug)]
struct NotRegular;

impl std::fmt::Display for NotRegular {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a regular file")
    }
}

impl std::error::Error for NotRegular {}

/// `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`; regular files only. A symlink fails in `open`; a FIFO or
/// a device opens without blocking (that is what `O_NONBLOCK` is for) and is refused by its
/// file type.
pub fn open_source(path: &Path) -> io::Result<(File, StatSig)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, NotRegular));
    }
    Ok((file, StatSig::from_metadata(&md)))
}

/// Whether a failed [`open_source`] says that the path no longer holds a regular file: it is
/// gone (`ENOENT`; `ENOTDIR` when a directory above it became a file), a symlink took its place
/// (`ELOOP` from `O_NOFOLLOW`), or what opened is a directory, FIFO or device.
fn no_longer_a_file(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) || err.raw_os_error() == Some(libc::ELOOP)
        || err.get_ref().is_some_and(|inner| inner.is::<NotRegular>())
}

/// The error for an upload source that cannot be opened (§6.2). Sources are files a scan just
/// saw as regular files, so one that is gone or has become something else *changed* since —
/// `SourceChanged`, which the sync engine reports as a skip. A file that is still there and
/// cannot be opened (permissions, I/O error) is `SourceUnreadable`, a failure.
pub(crate) fn open_failed(path: &Path, err: io::Error) -> TransferError {
    if no_longer_a_file(&err) {
        changed(path)
    } else {
        unreadable(path, err)
    }
}

/// `(sig, observed_ns, BLAKE3)`; fstat before/after must match → else `SourceChanged`.
/// `observed_ns` is taken before the first `fstat`, so a later write can only make the
/// signature look younger than its observation, never older (§5.4 racy-timestamp rule).
pub fn hash_file(path: &Path) -> Result<(StatSig, i64, [u8; 32]), TransferError> {
    let name = path.display().to_string();
    let unreadable = |err| TransferError::SourceUnreadable {
        path: name.clone(),
        err,
    };
    let observed_ns = util::now_ns();
    let (mut file, sig) = open_source(path).map_err(unreadable)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; READ_SIZE.min(sig.size as usize)];
    let mut left = sig.size;
    while left > 0 {
        let want = buf.len().min(left as usize);
        let got = read_full(&mut file, &mut buf[..want]).map_err(unreadable)?;
        if got < want {
            return Err(TransferError::SourceChanged(name));
        }
        hasher.update(&buf[..got]);
        left -= got as u64;
    }
    if !unchanged_at_eof(&mut file, &sig).map_err(unreadable)? {
        return Err(TransferError::SourceChanged(name));
    }
    Ok((sig, observed_ns, *hasher.finalize().as_bytes()))
}

/// `None` if absent (also when a parent of `path` is not a directory).
pub fn lstat_sig(path: &Path) -> io::Result<Option<StatSig>> {
    match std::fs::symlink_metadata(path) {
        Ok(md) => Ok(Some(StatSig::from_metadata(&md))),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Reads until `buf` is full or the file ends; returns the number of bytes read.
pub(crate) fn read_full(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// The check after the last byte: nothing follows the bytes read, and the descriptor still has
/// the signature it had when it was opened.
pub(crate) fn unchanged_at_eof(file: &mut File, sig: &StatSig) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    Ok(read_full(file, &mut probe)? == 0 && unchanged(file, sig)?)
}

/// The periodic check of a long read (§6.2, `SOURCE_RECHECK_BYTES`).
pub(crate) fn unchanged(file: &File, sig: &StatSig) -> io::Result<bool> {
    Ok(StatSig::from_metadata(&file.metadata()?) == *sig)
}

/// The error for a source that cannot be read (or opened, see [`open_failed`]).
pub(crate) fn unreadable(path: &Path, err: io::Error) -> TransferError {
    TransferError::SourceUnreadable {
        path: path.display().to_string(),
        err,
    }
}

/// The error for a source that changed while it was read, or since it was scanned.
pub(crate) fn changed(path: &Path) -> TransferError {
    TransferError::SourceChanged(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_file_matches_blake3_and_reports_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        for len in [
            0usize,
            1,
            READ_SIZE - 1,
            READ_SIZE,
            READ_SIZE + 1,
            3 * READ_SIZE + 7,
        ] {
            let path = dir.path().join(format!("f{len}"));
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            let before = util::now_ns();
            let (sig, observed_ns, hash) = hash_file(&path).unwrap();
            assert_eq!(hash, *blake3::hash(&data).as_bytes(), "len {len}");
            assert_eq!(sig.size, len as u64);
            assert_eq!(Some(sig), lstat_sig(&path).unwrap());
            assert!(observed_ns >= before && observed_ns <= util::now_ns());
        }
    }

    #[test]
    fn lstat_sig_of_missing_paths_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(lstat_sig(&dir.path().join("nope")).unwrap(), None);
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        assert_eq!(lstat_sig(&dir.path().join("file/below")).unwrap(), None);
    }

    #[test]
    fn symlinks_directories_and_fifos_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"content").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_source(&link).is_err());
        assert!(matches!(
            hash_file(&link),
            Err(TransferError::SourceUnreadable { .. })
        ));
        // lstat does not follow the link either.
        assert_ne!(lstat_sig(&link).unwrap(), lstat_sig(&real).unwrap());

        let err = open_source(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Without O_NONBLOCK this open would wait for a writer forever.
        let err = open_source(&fifo).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_source_that_is_gone_or_replaced_has_changed_and_one_that_is_locked_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"content").unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("dangling"))
            .unwrap();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        // Gone; below something that is a file now; a symlink; a directory; a FIFO.
        for name in ["missing", "real/below", "link", "dangling", "dir", "fifo"] {
            let path = dir.path().join(name);
            let err = open_source(&path).unwrap_err();
            assert!(no_longer_a_file(&err), "{name}: {err}");
            match open_failed(&path, err) {
                TransferError::SourceChanged(p) => assert_eq!(p, path.display().to_string()),
                e => panic!("{name}: {e}"),
            }
        }
        // The message of the file-type refusal is unchanged.
        let err = open_source(&dir.path().join("dir")).unwrap_err();
        assert_eq!(err.to_string(), "not a regular file");

        // Still a file, but not to be opened: a failure, not a change.
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o000)).unwrap();
        match open_source(&real) {
            // Running as root: permissions do not bind.
            Ok(_) => {}
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                assert!(matches!(
                    open_failed(&real, err),
                    TransferError::SourceUnreadable { .. }
                ));
            }
        }
        // Any other error is unreadable, too.
        let other = io::Error::from_raw_os_error(libc::EIO);
        assert!(!no_longer_a_file(&other));
        let invalid = io::Error::new(io::ErrorKind::InvalidInput, "something else");
        assert!(!no_longer_a_file(&invalid));
    }

    #[test]
    fn a_file_that_grows_after_the_fstat_is_reported_as_changed() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"12345").unwrap();
        let (mut file, sig) = open_source(&path).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(read_full(&mut file, &mut buf).unwrap(), 5);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"6")
            .unwrap();
        assert!(!unchanged_at_eof(&mut file, &sig).unwrap());
        assert!(!unchanged(&file, &sig).unwrap());
    }
}
