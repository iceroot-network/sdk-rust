//! The two primitives: Argon2id for the key, XChaCha20-Poly1305 for the payload. Both are
//! RustCrypto's pure-Rust implementations, so native and WebAssembly builds run the same code.

use argon2::{Algorithm, Argon2, Block, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use unicode_normalization::char::{canonical_combining_class, decompose_compatible};
use zeroize::{Zeroize, Zeroizing};

// The state that holds secrets inside the primitives is wiped when dropped only with the `zeroize`
// features the manifest turns on: the Blake2b state in which Argon2 absorbs the password, and
// XChaCha20's keystream buffer, which with the stored ciphertext gives the payload. Without them
// this does not build. (Poly1305's feature has no marker to check.)
const _: () = {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<blake2::Blake2bVarCore>();
};
use cipher::zeroize as _;

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
///
/// The normalization is done here, over buffers of exact size that are wiped, rather than with
/// `unicode-normalization`'s iterator, whose buffer moves to the heap for a character with a long
/// decomposition or a run of combining marks, and is then freed without being wiped.
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
    // Each buffer is sized exactly first, so that it never reallocates and leaves a copy behind.
    let mut count = 0usize;
    for c in password.chars() {
        decompose_compatible(c, |_| count += 1);
    }
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(count));
    for c in password.chars() {
        decompose_compatible(c, |d| chars.push(d));
    }
    canonical_order(&mut chars);
    let length: usize = chars.iter().map(|c| c.len_utf8()).sum();
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    let mut buffer = Zeroizing::new([0u8; 4]);
    for c in chars.iter() {
        bytes.extend_from_slice(c.encode_utf8(buffer.as_mut_slice()).as_bytes());
    }
    Ok(bytes)
}

/// The canonical ordering of the Unicode Standard (section 3.11), the last step of NFKD: each run
/// of characters with a non-zero canonical combining class is sorted by class, keeping the order
/// of equal classes. An insertion sort in place, so no scratch copy is made; a starter (class 0)
/// is never passed.
fn canonical_order(chars: &mut [char]) {
    for i in 1..chars.len() {
        let class = chars.get(i).map_or(0, |&c| canonical_combining_class(c));
        if class == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 {
            let before = chars
                .get(j - 1)
                .map_or(0, |&c| canonical_combining_class(c));
            if before <= class {
                break;
            }
            chars.swap(j - 1, j);
            j -= 1;
        }
    }
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

    /// The library's NFKD, which the normalization here must equal.
    fn library_nfkd(text: &str) -> Vec<u8> {
        use unicode_normalization::UnicodeNormalization;
        text.nfkd().collect::<String>().into_bytes()
    }

    #[test]
    fn nfkd_matches_the_library_for_every_character() {
        for code in 0..=0x10_ffff_u32 {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            let text = c.to_string();
            assert_eq!(
                password_bytes(&text).unwrap().as_slice(),
                library_nfkd(&text),
                "U+{code:04X}"
            );
        }
    }

    #[test]
    fn nfkd_matches_the_library_for_mixed_text() {
        // Starters, combining marks of several classes (including out of order and repeated
        // classes), Hangul, and characters with long compatibility decompositions.
        const POOL: &str = concat!(
            "aeZ1 \u{e9}\u{1e69}\u{1e0b}\u{301}\u{323}\u{302}\u{316}\u{31b}\u{345}",
            "\u{5b0}\u{5b1}\u{5bc}\u{591}\u{94d}\u{93c}\u{f71}\u{f72}\u{f74}\u{f73}",
            "\u{ac00}\u{d7a3}\u{1100}\u{1161}\u{11a8}\u{fb01}\u{fdfa}\u{3316}\u{2474}",
            "\u{2460}\u{ff21}\u{1d400}\u{1f511}\u{5bc6}\u{f900}\u{2126}\u{212b}\u{344}",
            "\u{1f82}\u{1dc0}\u{20d0}\u{302a}\u{3099}\u{ff9e}",
        );
        let pool: Vec<char> = POOL.chars().collect();
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        for _ in 0..20_000 {
            let length = 1 + next() % 24;
            let text: String = (0..length).map(|_| pool[next() % pool.len()]).collect();
            assert_eq!(
                password_bytes(&text).unwrap().as_slice(),
                library_nfkd(&text),
                "{text:?}"
            );
        }
        // A long run of combining marks in reverse class order.
        let text = format!("a{}", "\u{345}\u{302}\u{323}\u{316}\u{31b}".repeat(40));
        assert_eq!(
            password_bytes(&text).unwrap().as_slice(),
            library_nfkd(&text)
        );
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
