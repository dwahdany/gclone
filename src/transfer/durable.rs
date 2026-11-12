//! The durability barriers of the download side (SPEC §5.7 steps 3a and 3b, §17.15, §17.16).
//!
//! Making one file durable costs a flush of the drive's write cache: about 4 ms on an Apple
//! SSD, whatever the size of the file. A restore of many small files therefore does not flush
//! per file. It collects a batch and makes the whole batch durable at once.
//!
//! There are two ways in, because there are two kinds of paths:
//!
//! - **Files this process wrote** go through [`hand_over`], which syncs each of them through
//!   the descriptor it was written with and closes it, and then through [`Drives::flush`],
//!   the content barrier. They are never opened a second time: `fsync(2)` reports a failed
//!   write-back to the descriptors that wrote the data or were open when it failed — and
//!   promises nothing to one that was opened afterwards.
//! - **Everything else** — the directories renames, `mkdir`s and removals happened in, and
//!   files that were already there (their content found equal, their mtime or mode set) —
//!   goes through [`make_durable`], which opens each path.
//!
//! What a flush covers differs by platform, and this module relies only on what is documented:
//!
//! - **macOS** (`fcntl(2)`, `F_FULLFSYNC`): "Does the same thing as fsync(2) then asks the drive
//!   to flush all buffered data to the permanent storage device. As this drains the entire
//!   queue of the device and acts as a barrier, data that had been fsync'd on the same device
//!   before is guaranteed to be persisted when this call returns." The promise is about data
//!   that **was `fsync`ed** — not about dirty pages of other files that are still in the page
//!   cache. So every path gets a plain `fsync(2)` (which hands its data to the drive and is
//!   cheap: microseconds), and then **one** `F_FULLFSYNC` per device ends the batch.
//! - **Linux**: `fsync(2)` is the durable operation, and every path gets one. Where several
//!   paths are synced together a `syncfs(2)` per file system goes first: it writes everything
//!   back under one journal commit, so the `fsync`s that follow find their work done. Its
//!   error is the barrier's error (since Linux 5.8 it reports an inode that could not be
//!   written back; before that it reports nothing, and the `fsync`s are all there is).
//! - **Other Unix systems**: one `fsync(2)` per path.
//!
//! An error is either the error of **one path** (it cannot be opened, its `fsync` or its
//! `close` failed) — the caller fails what depends on that path and nothing else — or the
//! error of the **barrier** (`syncfs`, the flush of a drive): then nothing that was named is
//! known to be durable.

use std::fs::File;
use std::io;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// A path that could not be made durable: its position in the call, and why.
pub(crate) type Failed = (usize, io::Error);

/// One open descriptor per device that holds handed-over files: what [`Drives::flush`] needs
/// to end their batch. Each is the writing descriptor of the first such file on its device.
#[derive(Default)]
pub(crate) struct Drives(Vec<(u64, File)>);

/// First half of the content barrier, for files that were written through the descriptors
/// given here: every file's content and attributes are handed to the drive **through that
/// descriptor**, and the descriptor is closed. On macOS the data may still sit in the drive's
/// write cache — [`Drives::flush`] ends that, and `drives` collects what it needs; everywhere
/// else the files that are not reported as failed are durable when this returns.
///
/// The paths only name the files (for the errors' sake, and for the tests): nothing is opened.
///
/// `Err`: the barrier as a whole failed, no file of the call may be taken for synced. Every
/// descriptor is closed either way.
pub(crate) fn hand_over(files: Vec<(&Path, File)>, drives: &mut Drives) -> io::Result<Vec<Failed>> {
    // One file needs no help: its own `fsync` is the whole work, as it was before batching.
    if files.len() > 1 {
        let mut seen: Vec<u64> = Vec::new();
        for (_, file) in &files {
            let dev = file.metadata()?.dev();
            if !seen.contains(&dev) {
                seen.push(dev);
                write_back_all(file)?;
            }
        }
    }
    let mut failed = Vec::new();
    for (at, (path, file)) in files.into_iter().enumerate() {
        if let Err(e) = hand_over_one(path, file, drives) {
            failed.push((at, e));
        }
    }
    Ok(failed)
}

fn hand_over_one(path: &Path, file: File, drives: &mut Drives) -> io::Result<()> {
    #[cfg(test)]
    hook::file(path, &file)?;
    #[cfg(not(test))]
    let _ = path;
    to_drive(&file)?;
    let dev = file.metadata()?.dev();
    if drives.0.iter().any(|(seen, _)| *seen == dev) {
        return close(file);
    }
    // The first file of its device stays open for the flush of that drive.
    drives.0.push((dev, file));
    Ok(())
}

impl Drives {
    /// Descriptors held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Second half of the content barrier: the drives of everything that was handed over are
    /// flushed (macOS: one `F_FULLFSYNC` per device; a no-op where `fsync` is durable by
    /// itself), and the descriptors that were kept for it are closed. `written` names the
    /// files this barrier is for; nothing is opened.
    ///
    /// `Err`: none of the files may be taken for durable.
    pub(crate) fn flush(self, written: &[&Path]) -> io::Result<()> {
        #[cfg(test)]
        hook::call(written)?;
        #[cfg(not(test))]
        let _ = written;
        let mut result = Ok(());
        for (_, file) in self.0 {
            let done = match flush_drive(&file) {
                Ok(()) => close(file),
                Err(e) => Err(e),
            };
            if result.is_ok() {
                result = done;
            }
        }
        result
    }
}

/// The barrier for paths that exist and are opened here: when it returns `Ok`, everything done
/// so far to every path that is not listed in the answer survives a power loss — for a regular
/// file its content and attributes, for a directory its entries (the renames, links, `mkdir`s
/// and removals made in it).
///
/// For a file somebody else wrote this is the best there is: a descriptor opened now is told
/// about a failed write-back only as far as the kernel still remembers one.
///
/// `Err`: the barrier as a whole failed. The paths are opened one after another — the number
/// of open descriptors is the number of devices involved, not the number of paths.
pub(crate) fn make_durable(paths: &[&Path]) -> io::Result<Vec<Failed>> {
    #[cfg(test)]
    hook::call(paths)?;

    let mut failed = Vec::new();
    // One open file per device (`st_dev`): the paths may span mount points.
    let mut devices: Vec<(u64, File)> = Vec::new();
    for (at, path) in paths.iter().enumerate() {
        let opened = open(path).and_then(|file| Ok((file.metadata()?.dev(), file)));
        let (dev, file) = match opened {
            Ok(opened) => opened,
            Err(e) => {
                failed.push((at, e));
                continue;
            }
        };
        let first = devices.iter().all(|(seen, _)| *seen != dev);
        if first && paths.len() > 1 {
            write_back_all(&file)?;
        }
        #[cfg(test)]
        if let Err(e) = hook::file(path, &file) {
            failed.push((at, e));
            continue;
        }
        if let Err(e) = to_drive(&file) {
            failed.push((at, e));
            continue;
        }
        if first {
            devices.push((dev, file));
        }
    }
    for (_, file) in &devices {
        flush_drive(file)?;
    }
    Ok(failed)
}

/// Read-only is enough for `fsync`, and the only way to open a directory. `O_NONBLOCK` keeps
/// the open from hanging should somebody have put a FIFO where the file was. Symlinks are
/// followed, as they always were for the directories (a sync root may be given through one).
fn open(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// `close(2)`, with its answer: a file system that sends data only when a file is closed (NFS)
/// or meets its quota then reports the failed write here — "failing to check the return value
/// when closing a file may lead to silent loss of data" (`close(2)`, Linux). Never retried:
/// after `EINTR` the descriptor is gone all the same, and what there was to say about the
/// data the `fsync` before it said.
fn close(file: File) -> io::Result<()> {
    let fd = file.into_raw_fd();
    // SAFETY: `fd` was given up by its owner in the line above; nobody else closes it.
    if unsafe { libc::close(fd) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.kind() {
        io::ErrorKind::Interrupted => Ok(()),
        _ => Err(err),
    }
}

/// Linux: starts and awaits the write-back of the whole file system the file is on, once for
/// the paths synced together. An accelerator for the `fsync`s behind it — and a witness: since
/// Linux 5.8 it fails when an inode could not be written back, also one whose error no later
/// `fsync` would see. `ENOSYS` (a kernel without the call) is the one answer that says nothing.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn write_back_all(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `syncfs` takes a file descriptor and nothing else; the descriptor is open for
    // the duration of the call.
    if unsafe { libc::syncfs(file.as_raw_fd()) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) => Ok(()),
        _ => Err(err),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn write_back_all(_: &File) -> io::Result<()> {
    Ok(())
}

/// Hands the file's data and attributes to the drive. On Apple systems that is all plain
/// `fsync(2)` does (the drive may still hold them in its write cache); everywhere else it is
/// the durable operation itself.
#[cfg(target_vendor = "apple")]
fn to_drive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: `fsync` takes a file descriptor and nothing else; the descriptor is open for
        // the duration of the call.
        if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
fn to_drive(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// Apple systems: `F_FULLFSYNC` (that is what `File::sync_all` issues there) — everything that
/// was `fsync`ed on this device before is on stable storage when it returns.
#[cfg(target_vendor = "apple")]
fn flush_drive(file: &File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(not(target_vendor = "apple"))]
fn flush_drive(_: &File) -> io::Result<()> {
    Ok(())
}

/// Tests watch the barriers, or make them fail. Unit tests of one process run side by side,
/// hence every observer has a directory: it sees what happens to paths under it.
///
/// - [`hook::observe`]: every barrier — a [`make_durable`] call, a [`Drives::flush`] — that
///   names a path under the directory, before anything is flushed. Its `Err` is the barrier's.
/// - [`hook::observe_files`]: every single path that is synced, with the descriptor that is
///   used for it. Its `Err` is that path's.
#[cfg(test)]
pub(crate) mod hook {
    use std::fs::File;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    type Barriers = Arc<dyn Fn(&[&Path]) -> io::Result<()> + Send + Sync>;
    type Files = Arc<dyn Fn(&Path, &File) -> io::Result<()> + Send + Sync>;

    #[derive(Clone)]
    enum Observer {
        Barriers(Barriers),
        Files(Files),
    }

    static OBSERVERS: Mutex<Vec<(u64, PathBuf, Observer)>> = Mutex::new(Vec::new());
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Unregisters its observer when dropped.
    pub(crate) struct Guard(u64);

    impl Drop for Guard {
        fn drop(&mut self) {
            OBSERVERS.lock().unwrap().retain(|(id, _, _)| *id != self.0);
        }
    }

    fn register(dir: &Path, observer: Observer) -> Guard {
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let entry = (id, dir.to_path_buf(), observer);
        OBSERVERS.lock().unwrap().push(entry);
        Guard(id)
    }

    /// `observer` is called for every barrier that names a path under `dir`; an `Err` from it
    /// is the barrier's failure.
    pub(crate) fn observe(
        dir: &Path,
        observer: impl Fn(&[&Path]) -> io::Result<()> + Send + Sync + 'static,
    ) -> Guard {
        register(dir, Observer::Barriers(Arc::new(observer)))
    }

    /// `observer` is called for every path under `dir` that is synced, with the descriptor
    /// the `fsync` goes through; an `Err` from it is the failure of that path alone.
    pub(crate) fn observe_files(
        dir: &Path,
        observer: impl Fn(&Path, &File) -> io::Result<()> + Send + Sync + 'static,
    ) -> Guard {
        register(dir, Observer::Files(Arc::new(observer)))
    }

    /// The observers of `paths`, taken out of the registry: they run without its lock.
    fn observers(paths: &[&Path]) -> Vec<Observer> {
        let all = OBSERVERS.lock().unwrap();
        all.iter()
            .filter(|(_, dir, _)| paths.iter().any(|p| p.starts_with(dir)))
            .map(|(_, _, observer)| observer.clone())
            .collect()
    }

    pub(super) fn call(paths: &[&Path]) -> io::Result<()> {
        observers(paths).iter().try_for_each(|o| match o {
            Observer::Barriers(observer) => observer(paths),
            Observer::Files(_) => Ok(()),
        })
    }

    pub(super) fn file(path: &Path, file: &File) -> io::Result<()> {
        observers(&[path]).iter().try_for_each(|o| match o {
            Observer::Files(observer) => observer(path, file),
            Observer::Barriers(_) => Ok(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A file as a download writes it: created here, still open for writing.
    fn written(path: &Path, data: &[u8]) -> File {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(data).unwrap();
        file
    }

    #[test]
    fn files_and_directories_are_synced_and_nothing_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let (a, b) = (dir.path().join("a"), sub.join("b"));
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"two").unwrap();
        assert!(make_durable(&[]).unwrap().is_empty());
        assert!(make_durable(&[&a, &b]).unwrap().is_empty());
        assert!(make_durable(&[&sub, dir.path()]).unwrap().is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"one");
        assert_eq!(std::fs::read(&b).unwrap(), b"two");
    }

    #[test]
    fn a_path_that_cannot_be_synced_fails_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let gone = dir.path().join("gone");
        // The barrier stands for the two paths around the missing one.
        let failed = make_durable(&[&file, &gone, dir.path()]).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, 1);
        assert_eq!(failed[0].1.kind(), io::ErrorKind::NotFound);
        // A root that is reached through a symlink is synced like any other directory.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(make_durable(&[&link]).unwrap().is_empty());
    }

    #[test]
    fn an_observer_sees_the_calls_under_its_directory_only() {
        let (mine, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (mine.path().join("a"), other.path().join("b"));
        std::fs::write(&a, b"").unwrap();
        std::fs::write(&b, b"").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let guard = hook::observe(mine.path(), move |paths| {
            seen.fetch_add(paths.len(), Ordering::SeqCst);
            Err(io::Error::other("refused"))
        });
        assert!(make_durable(&[&b]).unwrap().is_empty());
        assert_eq!(make_durable(&[&a]).unwrap_err().to_string(), "refused");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(guard);
        assert!(make_durable(&[&a]).unwrap().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A file observer refuses single paths: the barrier stands for the others.
        let guard = hook::observe_files(mine.path(), |path, _| {
            match path.file_name().unwrap() == "a" {
                true => Err(io::Error::other("not this one")),
                false => Ok(()),
            }
        });
        let failed = make_durable(&[mine.path(), &a, &b]).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(
            (failed[0].0, failed[0].1.to_string().as_str()),
            (1, "not this one")
        );
        drop(guard);
        assert!(make_durable(&[mine.path(), &a, &b]).unwrap().is_empty());
    }

    /// The access mode a descriptor was opened with.
    fn access_mode(file: &File) -> i32 {
        // SAFETY: `F_GETFL` reads the flags of an open descriptor.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) & libc::O_ACCMODE }
    }

    #[test]
    fn written_files_are_synced_through_their_own_descriptors_and_closed() {
        let dir = tempfile::tempdir().unwrap();
        let names = ["a", "b", "c"];
        let paths: Vec<_> = names.iter().map(|n| dir.path().join(n)).collect();
        let files: Vec<File> = paths.iter().map(|p| written(p, b"content")).collect();
        let fds: Vec<i32> = files.iter().map(|f| f.as_raw_fd()).collect();

        // Every `fsync` goes through the descriptor that was handed in — the one the file was
        // written with — and through no other.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let _files = hook::observe_files(dir.path(), move |path, file| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            log.lock()
                .unwrap()
                .push((name.clone(), file.as_raw_fd(), access_mode(file)));
            match name == "b" {
                true => Err(io::Error::other("write-back failed")),
                false => Ok(()),
            }
        });
        let barriers = Arc::new(AtomicUsize::new(0));
        let count = barriers.clone();
        let _barriers = hook::observe(dir.path(), move |paths| {
            count.fetch_add(paths.len(), Ordering::SeqCst);
            Ok(())
        });

        let mut drives = Drives::default();
        let handed: Vec<(&Path, File)> = paths.iter().map(PathBuf::as_path).zip(files).collect();
        let failed = hand_over(handed, &mut drives).unwrap();
        // The file whose sync failed fails alone.
        assert_eq!(failed.len(), 1);
        assert_eq!(
            (failed[0].0, failed[0].1.to_string().as_str()),
            (1, "write-back failed")
        );
        let expect: Vec<(String, i32, i32)> = names
            .iter()
            .zip(&fds)
            .map(|(name, fd)| (name.to_string(), *fd, libc::O_RDWR))
            .collect();
        assert_eq!(*seen.lock().unwrap(), expect);
        // One descriptor is kept, for the one device; handing over is no barrier yet.
        assert_eq!(drives.len(), 1);
        assert_eq!(barriers.load(Ordering::SeqCst), 0);

        let named: Vec<&Path> = vec![&paths[0], &paths[2]];
        drives.flush(&named).unwrap();
        assert_eq!(barriers.load(Ordering::SeqCst), 2);
        for path in &paths {
            assert_eq!(std::fs::read(path).unwrap(), b"content");
        }
    }

    #[test]
    fn a_refused_content_barrier_is_an_error_and_closes_what_was_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("only");
        let mut drives = Drives::default();
        let failed = hand_over(vec![(path.as_path(), written(&path, b"x"))], &mut drives);
        assert!(failed.unwrap().is_empty());
        assert_eq!(drives.len(), 1);
        let _guard = hook::observe(dir.path(), |_| Err(io::Error::other("the drive said no")));
        let err = drives.flush(&[&path]).unwrap_err();
        assert_eq!(err.to_string(), "the drive said no");
        // Nothing to hand over, nothing to flush.
        let mut drives = Drives::default();
        assert!(hand_over(Vec::new(), &mut drives).unwrap().is_empty());
        assert_eq!(drives.len(), 0);
        drives.flush(&[]).unwrap();
    }
}
