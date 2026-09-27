//! The two primitives: Argon2id for the key, XChaCha20-Poly1305 for the payload. Both are
//! RustCrypto's pure-Rust implementations, so native and WebAssembly builds run the same code.

use argon2::{Algorithm, Argon2, Block, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, PasswordProblem};
use crate::format::{NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::params::Params;

/// Length of the derived key, in bytes.
const KEY_LEN: usize = 32;

/// The most UTF-8 bytes a password may have, before normalization.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The password as the KDF reads it: the UTF-8 bytes of its NFKD normalization, so that the same
/// text typed on different systems gives the same key. Empty and over-long passwords are refused
/// before any work is done.
pub(crate) fn password_bytes(password: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidPassword {
            problem: PasswordProblem::Empty,
        });
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::InvalidPassword {
            problem: PasswordProblem::TooLong {
                bytes: password.len(),
                maximum: MAX_PASSWORD_BYTES,
            },
        });
    }
    // Sized exactly first, so that the buffer never reallocates and leaves a copy behind.
    let length: usize = password.nfkd().map(char::len_utf8).sum();
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    let mut buffer = [0u8; 4];
    for c in password.nfkd() {
        bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
    }
    buffer.zeroize();
    Ok(bytes)
}

/// Argon2id of `password` and `salt` under `params`, which the caller has checked against its
/// bounds. The memory is allocated here, so that a failed allocation is an error rather than an
/// abort, and wiped before it is freed.
pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let out_of_memory = Error::OutOfMemory {
        memory_kib: params.memory_kib(),
    };
    let argon_params = argon2::Params::new(
        params.memory_kib(),
        params.iterations(),
        params.parallelism(),
        Some(KEY_LEN),
    )
    // Unreachable: the bounds admit only parameters Argon2 accepts.
    .map_err(|_| out_of_memory.clone())?;
    let blocks = argon_params.block_count();
    let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut memory: Vec<Block> = Vec::new();
    memory
        .try_reserve_exact(blocks)
        .map_err(|_| out_of_memory.clone())?;
    memory.resize(blocks, Block::new());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let result =
        context.hash_password_into_with_memory(password, salt, key.as_mut_slice(), &mut memory);
    // One pass over the blocks: `Vec::zeroize` would wipe the whole capacity a second time.
    for block in &mut memory {
        block.zeroize();
    }
    drop(memory);
    result.map_err(|_| out_of_memory)?;
    Ok(key)
}

/// Encrypt `buffer` in place under `key` and `nonce`, authenticating `aad`; returns the tag.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buffer.into())
        // Only a message longer than 256 GiB fails; a payload is at most 32 bytes.
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    Ok(tag.into())
}

/// Check the tag and decrypt `buffer` in place. Every failure is
/// [`Error::WrongPasswordOrCorrupt`].
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag = Tag::try_from(tag).map_err(|_| Error::WrongPasswordOrCorrupt)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_inout_detached(&XNonce::from(*nonce), aad, buffer.into(), &tag)
        .map_err(|_| Error::WrongPasswordOrCorrupt)
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn passwords_are_normalized() {
        // "é" precomposed and decomposed, and the "ﬁ" ligature, which NFKD splits.
        let composed = password_bytes("caf\u{e9} \u{fb01}").unwrap();
        let decomposed = password_bytes("cafe\u{301} fi").unwrap();
        assert_eq!(composed.as_slice(), decomposed.as_slice());
        assert_eq!(composed.as_slice(), "cafe\u{301} fi".as_bytes());
    }

    #[test]
    fn password_limits() {
        assert_eq!(
            password_bytes("").unwrap_err(),
            Error::InvalidPassword {
                problem: PasswordProblem::Empty
            }
        );
        assert!(password_bytes(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert_eq!(
            password_bytes(&"a".repeat(MAX_PASSWORD_BYTES + 1)).unwrap_err(),
            Error::InvalidPassword {
                problem: PasswordProblem::TooLong {
                    bytes: MAX_PASSWORD_BYTES + 1,
                    maximum: MAX_PASSWORD_BYTES
                }
            }
        );
    }

    #[test]
    fn derive_key_matches_the_argon2_crates_own_allocation() {
        // The keystore allocates and wipes Argon2's memory itself; the key must be the one the
        // crate computes with its own allocation.
        let params = Params::new(32, 3, 4);
        let key = derive_key(&[1; 32], &[2; SALT_LEN], &params).unwrap();
        let mut expected = [0u8; KEY_LEN];
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            argon2::Params::new(32, 3, 4, Some(KEY_LEN)).unwrap(),
        )
        .hash_password_into(&[1; 32], &[2; SALT_LEN], &mut expected)
        .unwrap();
        assert_eq!(*key, expected);
    }

    #[test]
    fn seal_and_open() {
        let key = [9u8; KEY_LEN];
        let nonce = [8u8; NONCE_LEN];
        let mut buffer = *b"entropy entropy entropy!";
        let tag = seal(&key, &nonce, b"header", &mut buffer).unwrap();
        assert_ne!(&buffer, b"entropy entropy entropy!");
        let mut opened = buffer;
        open(&key, &nonce, b"header", &mut opened, &tag).unwrap();
        assert_eq!(&opened, b"entropy entropy entropy!");
        let mut again = buffer;
        assert_eq!(
            open(&key, &nonce, b"headers", &mut again, &tag),
            Err(Error::WrongPasswordOrCorrupt)
        );
    }
}
