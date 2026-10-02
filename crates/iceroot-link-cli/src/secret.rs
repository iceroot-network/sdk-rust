//! Reading the secret: from a file only its user can read, or from a pipe on standard input.
//!
//! The bytes are held in a buffer that is wiped when dropped, and read without the standard
//! library's input buffer, so no unwiped copy is left behind by the reading itself. The texts of
//! this module's errors never contain the secret or a path.

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use zeroize::Zeroizing;

/// The most bytes a secret may have. A recovery phrase of 24 words has at most 215.
pub const MAX_SECRET_BYTES: usize = 1024;

/// Why a secret cannot be read.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The file can be read or written by its group or by others, or is owned by another user.
    NotPrivate(String),
    /// Standard input is a terminal: the secret would be echoed, so it is read from a pipe only.
    Terminal,
    /// The source is empty or larger than [`MAX_SECRET_BYTES`].
    Size,
    /// Reading failed.
    Io(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::NotPrivate(reason) => f.write_str(reason),
            SecretError::Terminal => f.write_str(
                "--phrase-stdin reads a pipe, never a terminal, where the phrase would be echoed: \
                 pipe the phrase in, or use --phrase-file",
            ),
            SecretError::Size => write!(
                f,
                "the secret is empty or longer than {MAX_SECRET_BYTES} bytes"
            ),
            SecretError::Io(reason) => f.write_str(reason),
        }
    }
}

/// Refuse a terminal on standard input before anything is read from it.
pub fn check_stdin_is_not_a_terminal(stdin_is_terminal: bool) -> Result<(), SecretError> {
    if stdin_is_terminal {
        Err(SecretError::Terminal)
    } else {
        Ok(())
    }
}

/// The secret piped in on standard input. A terminal is refused, and a file redirected to
/// standard input must be private, as a `--phrase-file` file must.
pub fn read_stdin() -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let stdin = io::stdin();
    check_stdin_is_not_a_terminal(stdin.is_terminal())?;
    let source = unbuffered_stdin()?;
    let metadata = source
        .metadata()
        .map_err(|error| SecretError::Io(format!("standard input cannot be read: {error}")))?;
    if metadata.is_file() {
        check_private(&metadata, "--phrase-stdin")?;
    }
    read_limited(source)
}

/// Standard input as a file of its own, so that the standard library's input buffer never holds
/// the secret.
#[cfg(unix)]
fn unbuffered_stdin() -> Result<File, SecretError> {
    use std::os::fd::AsFd;
    let descriptor = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| SecretError::Io(format!("standard input cannot be read: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn unbuffered_stdin() -> Result<File, SecretError> {
    use std::os::windows::io::AsHandle;
    let handle = io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .map_err(|error| SecretError::Io(format!("standard input cannot be read: {error}")))?;
    Ok(File::from(handle))
}

#[cfg(not(any(unix, windows)))]
fn unbuffered_stdin() -> Result<File, SecretError> {
    Err(SecretError::Io(
        "standard input cannot be read on this system".to_owned(),
    ))
}

/// The secret in the file at `path`, which must be a regular file owned by this user that its
/// group and others can neither read nor write. `option` names the file in errors.
pub fn read_private_file(path: &Path, option: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let file = File::open(path)
        .map_err(|error| SecretError::Io(format!("the {option} file cannot be opened: {error}")))?;
    // The checks read the opened file itself, so the file cannot be swapped after them.
    let metadata = file
        .metadata()
        .map_err(|error| SecretError::Io(format!("the {option} file cannot be read: {error}")))?;
    if !metadata.is_file() {
        return Err(SecretError::Io(format!(
            "the {option} file is not a regular file"
        )));
    }
    check_private(&metadata, option)?;
    read_limited(file)
}

#[cfg(unix)]
fn check_private(metadata: &std::fs::Metadata, option: &str) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    check_owner_only(metadata.mode(), metadata.uid(), current_user()?, option)
}

/// Refuse a file that its group or others may read or write (`mode`), or that another user
/// than `user` holds (`holder`).
#[cfg(unix)]
fn check_owner_only(mode: u32, holder: u32, user: u32, option: &str) -> Result<(), SecretError> {
    if mode & 0o077 != 0 {
        return Err(SecretError::NotPrivate(format!(
            "the {option} file can be read or written by other users (mode {:03o}): make it \
             private with chmod 600",
            mode & 0o777
        )));
    }
    if holder != user {
        return Err(SecretError::NotPrivate(format!(
            "the {option} file is owned by another user: a secret file must be your own"
        )));
    }
    Ok(())
}

/// Without Unix permissions the file's privacy cannot be checked, so the file is refused.
#[cfg(not(unix))]
fn check_private(_metadata: &std::fs::Metadata, option: &str) -> Result<(), SecretError> {
    Err(SecretError::NotPrivate(format!(
        "the privacy of the {option} file cannot be checked on this system: pipe the phrase in \
         with --phrase-stdin"
    )))
}

/// The real user id of this process, without unsafe code: from `/proc/self/status` on Linux,
/// else the user a new empty file in the temporary directory belongs to.
#[cfg(unix)]
fn current_user() -> Result<u32, SecretError> {
    let unknown = || SecretError::Io("this process's user cannot be determined".to_owned());
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        return status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().next())
            .and_then(|id| id.parse::<u32>().ok())
            .ok_or_else(unknown);
    }
    use std::os::unix::fs::MetadataExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let probe = std::env::temp_dir().join(format!(".iceroot-link-{}-{nanos}", std::process::id()));
    let created = File::options()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|file| file.metadata());
    let _ = std::fs::remove_file(&probe);
    created
        .map(|metadata| metadata.uid())
        .map_err(|_| unknown())
}

/// Read all of `source` into a wiped buffer, refusing an empty or oversized secret. The buffer
/// never grows, so no copy of it is left in freed memory.
fn read_limited(source: impl Read) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 2));
    let limit = u64::try_from(MAX_SECRET_BYTES + 1).unwrap_or(u64::MAX);
    source
        .take(limit)
        .read_to_end(&mut buffer)
        .map_err(|error| SecretError::Io(format!("the secret cannot be read: {error}")))?;
    if buffer.is_empty() || buffer.len() > MAX_SECRET_BYTES {
        return Err(SecretError::Size);
    }
    Ok(buffer)
}

/// The legacy passphrase in a file's bytes: the text with one line ending at its end removed,
/// as a text editor or `echo` writes one. Nothing else is changed: the key is the SHA-256 of the
/// exact text.
pub fn passphrase_text(bytes: &[u8]) -> Result<&str, SecretError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SecretError::Io("the passphrase is not UTF-8 text".to_owned()))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.is_empty() {
        return Err(SecretError::Size);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_is_refused() {
        assert_eq!(
            check_stdin_is_not_a_terminal(true),
            Err(SecretError::Terminal)
        );
        assert_eq!(check_stdin_is_not_a_terminal(false), Ok(()));
    }

    #[test]
    fn sizes() {
        assert_eq!(read_limited(&b""[..]), Err(SecretError::Size));
        let long = vec![b'a'; MAX_SECRET_BYTES + 1];
        assert_eq!(read_limited(&long[..]), Err(SecretError::Size));
        let most = vec![b'a'; MAX_SECRET_BYTES];
        assert_eq!(read_limited(&most[..]).unwrap().len(), MAX_SECRET_BYTES);
    }

    #[test]
    fn one_line_ending_is_removed_from_a_passphrase() {
        assert_eq!(passphrase_text(b"a b\n").unwrap(), "a b");
        assert_eq!(passphrase_text(b"a b\r\n").unwrap(), "a b");
        assert_eq!(passphrase_text(b"a b\n\n").unwrap(), "a b\n");
        assert_eq!(passphrase_text(b" a b ").unwrap(), " a b ");
        assert_eq!(passphrase_text(b"\n"), Err(SecretError::Size));
        assert!(passphrase_text(&[0xff]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_may_read_or_write_the_file() {
        let option = "--phrase-file";
        assert_eq!(check_owner_only(0o100600, 1000, 1000, option), Ok(()));
        assert_eq!(check_owner_only(0o100400, 1000, 1000, option), Ok(()));
        for mode in [
            0o100640,
            0o100604,
            0o100620,
            0o100602,
            0o100610,
            0o100601,
            0o100700 | 0o004,
        ] {
            let error = check_owner_only(mode, 1000, 1000, option).unwrap_err();
            assert!(error.to_string().contains("chmod 600"), "{mode:o}");
        }
        let error = check_owner_only(0o100600, 0, 1000, option).unwrap_err();
        assert!(error.to_string().contains("owned by another user"));
    }

    #[cfg(unix)]
    #[test]
    fn the_user_is_the_one_a_new_file_belongs_to() {
        use std::os::unix::fs::MetadataExt;
        let probe = std::env::temp_dir().join(format!("iceroot-link-uid-{}", std::process::id()));
        std::fs::write(&probe, b"").unwrap();
        let holder = std::fs::metadata(&probe).unwrap().uid();
        std::fs::remove_file(&probe).unwrap();
        assert_eq!(current_user().unwrap(), holder);
    }
}
