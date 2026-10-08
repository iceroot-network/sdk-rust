//! The secret a keystore holds: seed material only, with a typed kind. Never the text of a
//! recovery phrase, never a derived key.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

/// The most bytes any payload kind holds.
pub const MAX_PAYLOAD_LEN: usize = 32;

/// What a keystore's payload is. The kind is stored in the header and authenticated with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PayloadKind {
    /// The entropy of a BIP39 recovery phrase: 24, 28 or 32 bytes, for phrases of 18, 21 or 24
    /// words. Shorter phrases (12 and 15 words) are refused, as they are for keys. The phrase is
    /// the entropy's encoding and its checksum, so the entropy alone restores it.
    Bip39Entropy,
    /// Reserved: the 32-byte ML-DSA-65 key generation seed (ξ) of IceRoot's post-quantum key
    /// scheme. The kind is assigned now so that the format does not change when it arrives; this
    /// release reads its header but neither writes nor decrypts it
    /// ([`Error::UnsupportedPayload`]).
    MlDsa65Seed,
}

impl PayloadKind {
    /// The kind's byte in the header: 1 for BIP39 entropy, 2 for the ML-DSA-65 seed.
    pub const fn code(self) -> u8 {
        match self {
            PayloadKind::Bip39Entropy => 1,
            PayloadKind::MlDsa65Seed => 2,
        }
    }

    /// The kind of a header byte, if it is one this release knows.
    pub const fn from_code(code: u8) -> Option<PayloadKind> {
        match code {
            1 => Some(PayloadKind::Bip39Entropy),
            2 => Some(PayloadKind::MlDsa65Seed),
            _ => None,
        }
    }

    /// The stable string form: `bip39-entropy` or `ml-dsa-65-seed`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PayloadKind::Bip39Entropy => "bip39-entropy",
            PayloadKind::MlDsa65Seed => "ml-dsa-65-seed",
        }
    }

    /// Whether this release writes and decrypts the kind.
    pub const fn is_supported(self) -> bool {
        match self {
            PayloadKind::Bip39Entropy => true,
            PayloadKind::MlDsa65Seed => false,
        }
    }

    /// Whether `length` bytes is a valid payload of this kind.
    pub const fn allows_length(self, length: usize) -> bool {
        match self {
            PayloadKind::Bip39Entropy => matches!(length, 24 | 28 | 32),
            PayloadKind::MlDsa65Seed => length == 32,
        }
    }
}

/// Secret seed material with its kind. The bytes are wiped when the payload is dropped, and
/// `Debug` never shows them. They live on the heap, so moving a payload moves a pointer and
/// leaves no copy of the secret behind.
pub struct Payload {
    kind: PayloadKind,
    len: usize,
    bytes: Box<[u8; MAX_PAYLOAD_LEN]>,
}

impl Payload {
    /// A payload of `kind` holding `bytes`.
    ///
    /// Refused with [`Error::InvalidPayload`] when the length does not fit the kind (for BIP39
    /// entropy, anything but 24, 28 or 32 bytes), and with [`Error::UnsupportedPayload`] for a
    /// kind this release does not write.
    pub fn new(kind: PayloadKind, bytes: &[u8]) -> Result<Payload, Error> {
        if !kind.is_supported() {
            return Err(Error::UnsupportedPayload { kind: kind.code() });
        }
        Payload::from_parts(kind, bytes)
    }

    /// A payload holding the entropy of a BIP39 recovery phrase of 18, 21 or 24 words.
    pub fn bip39_entropy(entropy: &[u8]) -> Result<Payload, Error> {
        Payload::new(PayloadKind::Bip39Entropy, entropy)
    }

    /// Any kind, supported or not, for the decoder, which copies the ciphertext in with this and
    /// decrypts it where it lies ([`Payload::secret_bytes_mut`]).
    pub(crate) fn from_parts(kind: PayloadKind, bytes: &[u8]) -> Result<Payload, Error> {
        let length = bytes.len();
        if !kind.allows_length(length) {
            return Err(Error::InvalidPayload { kind, length });
        }
        let mut payload = Payload {
            kind,
            len: length,
            bytes: Box::new([0; MAX_PAYLOAD_LEN]),
        };
        payload
            .bytes
            .get_mut(..length)
            .ok_or(Error::InvalidPayload { kind, length })?
            .copy_from_slice(bytes);
        Ok(payload)
    }

    /// The payload's kind.
    pub const fn kind(&self) -> PayloadKind {
        self.kind
    }

    /// The length of the secret, in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always false: every payload holds at least 24 bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// For BIP39 entropy, the number of words of its phrase (18, 21 or 24).
    pub const fn word_count(&self) -> Option<usize> {
        match self.kind {
            PayloadKind::Bip39Entropy => Some(self.len * 3 / 4),
            PayloadKind::MlDsa65Seed => None,
        }
    }

    /// The secret bytes. Copy them only into memory that is wiped after use.
    pub fn secret_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// The secret bytes, for decrypting in place.
    pub(crate) fn secret_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes.get_mut(..self.len).unwrap_or_default()
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

impl ZeroizeOnDrop for Payload {}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("kind", &self.kind)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Payload {
    /// Compares kinds and bytes. Not constant time: for tests, not for checking secrets.
    fn eq(&self, other: &Payload) -> bool {
        self.kind == other.kind && self.secret_bytes() == other.secret_bytes()
    }
}

impl Eq for Payload {}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn bip39_entropy_lengths() {
        for (length, words) in [(24, 18), (28, 21), (32, 24)] {
            let payload = Payload::bip39_entropy(&vec![7; length]).unwrap();
            assert_eq!(payload.len(), length);
            assert_eq!(payload.word_count(), Some(words));
            assert_eq!(payload.secret_bytes(), vec![7; length].as_slice());
        }
        for length in [0, 16, 20, 23, 25, 33, 64] {
            assert_eq!(
                Payload::bip39_entropy(&vec![7; length]).unwrap_err(),
                Error::InvalidPayload {
                    kind: PayloadKind::Bip39Entropy,
                    length
                }
            );
        }
    }

    #[test]
    fn the_reserved_kind_is_not_written() {
        assert_eq!(
            Payload::new(PayloadKind::MlDsa65Seed, &[1; 32]).unwrap_err(),
            Error::UnsupportedPayload { kind: 2 }
        );
    }

    #[test]
    fn debug_shows_no_secret() {
        let payload = Payload::bip39_entropy(&[0xab; 32]).unwrap();
        let text = format!("{payload:?}");
        assert!(!text.contains("171") && !text.to_lowercase().contains("ab"));
        assert!(text.contains("Bip39Entropy"));
    }
}
