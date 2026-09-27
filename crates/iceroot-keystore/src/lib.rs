//! `iceroot-keystore`: the IceRoot keystore format, as pure functions.
//!
//! A keystore is a recovery seed encrypted under a password: the key comes from the password by
//! Argon2id, and the seed is sealed with XChaCha20-Poly1305. Its header (the format version, the
//! key derivation function and its parameters, the salt, the nonce and the payload's kind and
//! length) is readable without the password and authenticated with the seed, so changing any
//! byte of it makes decryption fail. The layout is in [`format`](mod@format) and in
//! `docs/keystore-format.md` of the repository.
//!
//! The crate stores nothing. An app keeps the keystore's bytes (or their text form, [`armor`])
//! where its platform keeps secrets best, and never stores the password.
//!
//! ```
//! use iceroot_keystore::{Params, Payload};
//!
//! # fn main() -> Result<(), iceroot_keystore::Error> {
//! // The 32 bytes of entropy of a 24-word recovery phrase.
//! let entropy = [0x5a; 32];
//! let payload = Payload::bip39_entropy(&entropy)?;
//! // An app passes its platform's preset, such as `Preset::Mobile`. This example uses the lowest
//! // parameters the format accepts, to run quickly.
//! let params = Params::new(19 * 1024, 2, 1);
//! let keystore = iceroot_keystore::encrypt(&payload, "correct horse", params)?;
//!
//! let header = iceroot_keystore::inspect(&keystore)?;
//! assert_eq!(header.payload_len(), 32);
//!
//! let opened = iceroot_keystore::decrypt(&keystore, "correct horse")?;
//! assert_eq!(opened.secret_bytes(), entropy);
//! assert!(iceroot_keystore::decrypt(&keystore, "wrong horse").is_err());
//! # Ok(())
//! # }
//! ```
//!
//! What goes in: the entropy of a BIP39 recovery phrase of 18, 21 or 24 words
//! ([`PayloadKind::Bip39Entropy`]); the ML-DSA-65 seed of IceRoot's post-quantum keys has its kind
//! reserved ([`PayloadKind::MlDsa65Seed`]) and arrives in a later release. Never the text of a
//! phrase, never a derived key.
//!
//! Rules for the whole crate: no unsafe code, no panics on untrusted input, no I/O, and no secret
//! in any `Debug` output or error. The password, the derived key, Argon2's memory and the payload
//! are wiped after use. Salts and nonces come from the operating system's generator only
//! (`crypto.getRandomValues` in WebAssembly); nothing in a normal build lets a caller choose them.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod armor;
mod crypto;
pub mod error;
pub mod format;
mod params;
mod payload;

use zeroize::Zeroizing;

pub use crate::armor::{ARMOR_PREFIX, armor, dearmor};
pub use crate::crypto::MAX_PASSWORD_BYTES;
pub use crate::error::{Error, Malformed, Param, PasswordProblem};
pub use crate::format::{HEADER_LEN, Header, Kdf, NONCE_LEN, SALT_LEN, TAG_LEN};
pub use crate::params::{Bounds, Params, Preset};
pub use crate::payload::{MAX_PAYLOAD_LEN, Payload, PayloadKind};

/// Encrypt `payload` under `password` with `params` (a [`Preset`] or explicit [`Params`]), a
/// fresh salt and a fresh nonce from the operating system's generator (`crypto.getRandomValues`
/// in WebAssembly).
///
/// The parameters must lie within [`Bounds::STANDARD`], else [`Error::ParamsOutOfRange`]. The
/// password is Unicode text, normalized to NFKD; it must not be empty and may have at most
/// [`MAX_PASSWORD_BYTES`] bytes of UTF-8 ([`Error::InvalidPassword`]). A failing generator gives
/// [`Error::RandomnessUnavailable`].
pub fn encrypt(
    payload: &Payload,
    password: &str,
    params: impl Into<Params>,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::RandomnessUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
    seal(
        payload,
        password,
        &params.into(),
        salt,
        nonce,
        &Bounds::STANDARD,
    )
}

/// Tests only (feature `testing`): encrypt with the caller's salt and nonce, checking the
/// parameters against `bounds`, for vectors. A salt or nonce must never be reused; [`encrypt`],
/// which draws both fresh, is the only way a normal build writes a keystore.
#[cfg(feature = "testing")]
pub fn encrypt_with_salt_and_nonce(
    payload: &Payload,
    password: &str,
    params: impl Into<Params>,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    bounds: &Bounds,
) -> Result<Vec<u8>, Error> {
    seal(payload, password, &params.into(), *salt, *nonce, bounds)
}

fn seal(
    payload: &Payload,
    password: &str,
    params: &Params,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    bounds: &Bounds,
) -> Result<Vec<u8>, Error> {
    let kind = payload.kind();
    if !kind.is_supported() {
        return Err(Error::UnsupportedPayload { kind: kind.code() });
    }
    let secret = payload.secret_bytes();
    let length = u8::try_from(secret.len()).map_err(|_| Error::InvalidPayload {
        kind,
        length: secret.len(),
    })?;
    bounds.check(params)?;
    let password = crypto::password_bytes(password)?;
    let header = Header::new(*params, salt, nonce, kind, length);
    let aad = header.to_bytes();
    let key = crypto::derive_key(&password, &salt, params)?;
    drop(password);

    // The plaintext is written into the output and encrypted where it lies, so no other copy of
    // it is made.
    let mut out = Zeroizing::new(Vec::with_capacity(header.keystore_len()));
    out.extend_from_slice(&aad);
    out.extend_from_slice(secret);
    let body = out.get_mut(HEADER_LEN..).ok_or(Error::InvalidPayload {
        kind,
        length: secret.len(),
    })?;
    let tag = crypto::seal(&key, &nonce, &aad, body)?;
    out.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *out))
}

/// Decrypt a keystore with `password`, under [`Bounds::STANDARD`].
///
/// The checks run in this order, and the first failure is reported: the layout
/// ([`Error::Malformed`], [`Error::UnsupportedVersion`], [`Error::UnsupportedKdf`],
/// [`Error::UnsupportedPayload`], as [`inspect`] makes them), whether this release decrypts the
/// payload kind ([`Error::UnsupportedPayload`]), the parameters ([`Error::ParamsOutOfRange`]),
/// the password's form ([`Error::InvalidPassword`]), and then the key derivation and the tag:
/// a wrong password and every change to the header, ciphertext or tag give the one error
/// [`Error::WrongPasswordOrCorrupt`].
pub fn decrypt(bytes: &[u8], password: &str) -> Result<Payload, Error> {
    decrypt_with_bounds(bytes, password, &Bounds::STANDARD)
}

/// [`decrypt`] under other bounds: [`Bounds::STANDARD`] with a lower memory ceiling
/// ([`Bounds::with_memory_ceiling_kib`]) on a platform that cannot spare more memory.
pub fn decrypt_with_bounds(
    bytes: &[u8],
    password: &str,
    bounds: &Bounds,
) -> Result<Payload, Error> {
    let parsed = format::parse(bytes)?;
    let header = parsed.header;
    let kind = header.payload_kind();
    if !kind.is_supported() {
        return Err(Error::UnsupportedPayload { kind: kind.code() });
    }
    let params = header.params();
    bounds.check(&params)?;
    let password = crypto::password_bytes(password)?;
    let key = crypto::derive_key(&password, header.salt(), &params)?;
    drop(password);

    // The ciphertext is decrypted where the payload keeps it, so no other copy of the plaintext
    // is made. The tag is checked before anything is decrypted; on a failure the payload, still
    // holding the ciphertext, is wiped as it is dropped.
    let mut payload = Payload::from_parts(kind, parsed.ciphertext)?;
    crypto::open(
        &key,
        header.nonce(),
        parsed.aad,
        payload.secret_bytes_mut(),
        parsed.tag,
    )?;
    Ok(payload)
}

/// The header of a keystore, read without the password. The layout is checked as [`decrypt`]
/// checks it; the parameters are reported as they are, in or out of bounds.
pub fn inspect(bytes: &[u8]) -> Result<Header, Error> {
    format::parse(bytes).map(|parsed| parsed.header)
}

/// Decrypt a keystore with `old_password` and encrypt its payload again under `new_password`,
/// with `params`, a fresh salt and a fresh nonce. The new password and parameters are checked
/// before the old password, so a refusal costs no key derivation.
pub fn change_password(
    bytes: &[u8],
    old_password: &str,
    new_password: &str,
    params: impl Into<Params>,
) -> Result<Vec<u8>, Error> {
    let params = params.into();
    Bounds::STANDARD.check(&params)?;
    crypto::password_bytes(new_password)?;
    let payload = decrypt(bytes, old_password)?;
    encrypt(&payload, new_password, params)
}

/// Encrypt a keystore's payload again under the same password with new `params`, a fresh salt
/// and a fresh nonce: for moving a keystore to a newer preset after an unlock (see
/// [`Params::is_weaker_than`]).
pub fn reencrypt(
    bytes: &[u8],
    password: &str,
    params: impl Into<Params>,
) -> Result<Vec<u8>, Error> {
    change_password(bytes, password, password, params)
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    /// All 60 bytes of the header are the associated data: with the right key and nonce, a
    /// change to any one of them, including the ones that do not feed the key derivation, fails
    /// the tag.
    #[test]
    fn every_header_byte_is_authenticated() {
        let params = Params::new(8, 1, 1);
        let salt = [3; SALT_LEN];
        let nonce = [4; NONCE_LEN];
        let payload = Payload::bip39_entropy(&[5; 24]).unwrap();
        let keystore =
            encrypt_with_salt_and_nonce(&payload, "pw", params, &salt, &nonce, &Bounds::TEST)
                .unwrap();
        let key = crypto::derive_key(b"pw", &salt, &params).unwrap();
        let (aad, rest) = keystore.split_at(HEADER_LEN);
        let (ciphertext, tag) = rest.split_at(24);
        let mut buffer = ciphertext.to_vec();
        crypto::open(&key, &nonce, aad, &mut buffer, tag).unwrap();
        assert_eq!(buffer, [5; 24]);
        for index in 0..HEADER_LEN {
            let mut changed = aad.to_vec();
            changed[index] ^= 0x01;
            let mut buffer = ciphertext.to_vec();
            assert_eq!(
                crypto::open(&key, &nonce, &changed, &mut buffer, tag),
                Err(Error::WrongPasswordOrCorrupt),
                "header byte {index}"
            );
            assert_eq!(buffer, ciphertext, "nothing is decrypted without the tag");
        }
    }
}
