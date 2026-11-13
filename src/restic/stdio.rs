//! The transport of `gclone serve restic --stdio` (SPEC §7.6): restic starts gclone and speaks
//! HTTP/2 over the two pipes it gave it as stdin and stdout.

use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd as _, RawFd};

/// A new descriptor (≥ 3, close-on-exec) for the file behind `fd`.
fn duplicate(fd: RawFd) -> io::Result<File> {
    // SAFETY: F_DUPFD_CLOEXEC only creates a descriptor; it is owned by the `File` right away.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new` is a descriptor nothing else knows.
    Ok(unsafe { File::from_raw_fd(new) })
}

fn replace(fd: RawFd, with: RawFd) -> io::Result<()> {
    // SAFETY: dup2 only re-points `fd`.
    match unsafe { libc::dup2(with, fd) } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Takes the two pipes for the protocol and takes them away from everything else: the
/// returned files are the only way to them. Descriptor 1 becomes stderr — a stray `println!`
/// of any code in the process then cannot put a byte into the HTTP/2 stream — and descriptor 0
/// becomes `/dev/null`, so that nothing else can eat protocol bytes.
pub fn claim() -> io::Result<(File, File)> {
    use std::os::fd::AsRawFd as _;
    let input = duplicate(libc::STDIN_FILENO)?;
    let output = duplicate(libc::STDOUT_FILENO)?;
    replace(libc::STDOUT_FILENO, libc::STDERR_FILENO)?;
    let null = File::open("/dev/null")?;
    replace(libc::STDIN_FILENO, null.as_raw_fd())?;
    Ok((input, output))
}

/// The connection: reads from restic's pipe, writes to the other. `tokio::fs::File` works on
/// pipes, sockets and files alike (the reads and writes run on the blocking pool).
pub fn connection(
    input: File,
    output: File,
) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
    tokio::io::join(
        tokio::fs::File::from_std(input),
        tokio::fs::File::from_std(output),
    )
}
