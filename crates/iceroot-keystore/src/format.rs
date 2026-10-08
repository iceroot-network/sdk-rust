//! The binary layout of a keystore, version 1, and its strict decoder.
//!
//! ```text
//! offset  size  field
//!      0     4  magic "IRKS" (49 52 4b 53)
//!      4     1  format version: 1
//!      5     1  key derivation function: 1 = Argon2id, version 0x13, 32-byte output
//!      6     4  memory in KiB, u32 big-endian
//!     10     4  iterations, u32 big-endian
//!     14     4  parallelism, u32 big-endian
//!     18    16  salt
//!     34    24  nonce (XChaCha20-Poly1305)
//!     58     1  payload kind: 1 = BIP39 entropy, 2 = ML-DSA-65 seed (reserved)
//!     59     1  payload length in bytes
//!     60     n  ciphertext of the payload, n = payload length
//!   60+n    16  Poly1305 tag
//! ```
//!
//! The 60 header bytes are the AEAD's associated data, so changing any of them makes decryption
//! fail. Every field has a fixed size and every value one encoding, so a keystore has exactly one
//! byte form; trailing bytes are refused.

use crate::error::{Error, Malformed};
use crate::params::Params;
use crate::payload::PayloadKind;

/// The first four bytes of every keystore: `IRKS`.
pub const MAGIC: [u8; 4] = *b"IRKS";
/// The format version this release writes and reads.
pub const FORMAT_VERSION: u8 = 1;
/// Length of the salt, in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the XChaCha20-Poly1305 nonce, in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag, in bytes.
pub const TAG_LEN: usize = 16;
/// Length of the header, in bytes.
pub const HEADER_LEN: usize = 60;

/// A key derivation function a keystore can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kdf {
    /// Argon2id, version 0x13 (RFC 9106), with a 32-byte output and no secret or associated data.
    Argon2id,
}

impl Kdf {
    /// The KDF's byte in the header: 1 for Argon2id.
    pub const fn code(self) -> u8 {
        match self {
            Kdf::Argon2id => 1,
        }
    }

    /// The KDF of a header byte, if it is one this release knows.
    pub const fn from_code(code: u8) -> Option<Kdf> {
        match code {
            1 => Some(Kdf::Argon2id),
            _ => None,
        }
    }

    /// The stable string form: `argon2id`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kdf::Argon2id => "argon2id",
        }
    }
}

/// A keystore's header: everything but the secret, readable without the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    kdf: Kdf,
    params: Params,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    payload_kind: PayloadKind,
    payload_len: u8,
}

impl Header {
    pub(crate) const fn new(
        params: Params,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
        payload_kind: PayloadKind,
        payload_len: u8,
    ) -> Header {
        Header {
            kdf: Kdf::Argon2id,
            params,
            salt,
            nonce,
            payload_kind,
            payload_len,
        }
    }

    /// The format version: always [`FORMAT_VERSION`] for a header this release decodes.
    pub const fn version(&self) -> u8 {
        FORMAT_VERSION
    }

    /// The key derivation function.
    pub const fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// The key derivation parameters.
    pub const fn params(&self) -> Params {
        self.params
    }

    /// The salt.
    pub const fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The nonce.
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The payload's kind.
    pub const fn payload_kind(&self) -> PayloadKind {
        self.payload_kind
    }

    /// The payload's length, in bytes.
    pub const fn payload_len(&self) -> usize {
        self.payload_len as usize
    }

    /// The length of the whole keystore: header, ciphertext and tag.
    pub const fn keystore_len(&self) -> usize {
        HEADER_LEN + self.payload_len as usize + TAG_LEN
    }

    /// The header's bytes, which are also the AEAD's associated data.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let mut writer = Writer {
            out: &mut out,
            at: 0,
        };
        writer.put(&MAGIC);
        writer.put(&[FORMAT_VERSION, self.kdf.code()]);
        writer.put(&self.params.memory_kib().to_be_bytes());
        writer.put(&self.params.iterations().to_be_bytes());
        writer.put(&self.params.parallelism().to_be_bytes());
        writer.put(&self.salt);
        writer.put(&self.nonce);
        writer.put(&[self.payload_kind.code(), self.payload_len]);
        out
    }
}

struct Writer<'a> {
    out: &'a mut [u8; HEADER_LEN],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let end = self.at + bytes.len();
        if let Some(slot) = self.out.get_mut(self.at..end) {
            slot.copy_from_slice(bytes);
        }
        self.at = end;
    }
}

/// A keystore split into its parts, borrowed from its bytes.
pub(crate) struct Parsed<'a> {
    pub header: Header,
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

/// Decode `bytes` strictly. The checks run in this order, and the first failure is reported:
/// the magic, the version, the length of the header and tag, the KDF, the payload kind, the
/// payload length for its kind, and the total length.
pub(crate) fn parse(bytes: &[u8]) -> Result<Parsed<'_>, Error> {
    let malformed = |problem| Error::Malformed { problem };
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(malformed(Malformed::Magic));
    }
    let mut reader = Reader {
        bytes,
        at: MAGIC.len(),
    };
    let version = reader.byte().ok_or(malformed(Malformed::Truncated))?;
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion { version });
    }
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(malformed(Malformed::Truncated));
    }
    let truncated = || malformed(Malformed::Truncated);
    let kdf_code = reader.byte().ok_or_else(truncated)?;
    let kdf = Kdf::from_code(kdf_code).ok_or(Error::UnsupportedKdf { kdf: kdf_code })?;
    let memory_kib = reader.u32().ok_or_else(truncated)?;
    let iterations = reader.u32().ok_or_else(truncated)?;
    let parallelism = reader.u32().ok_or_else(truncated)?;
    let salt = reader.array::<SALT_LEN>().ok_or_else(truncated)?;
    let nonce = reader.array::<NONCE_LEN>().ok_or_else(truncated)?;
    let kind_code = reader.byte().ok_or_else(truncated)?;
    let payload_kind =
        PayloadKind::from_code(kind_code).ok_or(Error::UnsupportedPayload { kind: kind_code })?;
    let payload_len = reader.byte().ok_or_else(truncated)?;
    if !payload_kind.allows_length(usize::from(payload_len)) {
        return Err(malformed(Malformed::PayloadLength));
    }
    let header = Header {
        kdf,
        params: Params::new(memory_kib, iterations, parallelism),
        salt,
        nonce,
        payload_kind,
        payload_len,
    };
    if bytes.len() != header.keystore_len() {
        return Err(malformed(Malformed::Length));
    }
    let (aad, rest) = bytes.split_at_checked(HEADER_LEN).ok_or_else(truncated)?;
    let (ciphertext, tag) = rest
        .split_at_checked(usize::from(payload_len))
        .ok_or_else(truncated)?;
    Ok(Parsed {
        header,
        aad,
        ciphertext,
        tag,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let slice = self.bytes.get(self.at..self.at.checked_add(N)?)?;
        self.at += N;
        slice.try_into().ok()
    }

    fn byte(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array::<4>().map(u32::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn header() -> Header {
        Header::new(
            Params::new(0x0102_0304, 0x0506_0708, 0x090a_0b0c),
            [0x11; SALT_LEN],
            [0x22; NONCE_LEN],
            PayloadKind::Bip39Entropy,
            32,
        )
    }

    #[test]
    fn layout() {
        let bytes = header().to_bytes();
        assert_eq!(&bytes[..4], b"IRKS");
        assert_eq!(bytes[4..6], [1, 1]);
        assert_eq!(bytes[6..18], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(bytes[18..34], [0x11; 16]);
        assert_eq!(bytes[34..58], [0x22; 24]);
        assert_eq!(bytes[58..60], [1, 32]);
    }

    #[test]
    fn round_trip() {
        let mut bytes = header().to_bytes().to_vec();
        bytes.extend_from_slice(&[0x33; 32 + TAG_LEN]);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.header, header());
        assert_eq!(parsed.aad, &bytes[..HEADER_LEN]);
        assert_eq!(parsed.ciphertext, &[0x33; 32]);
        assert_eq!(parsed.tag, &[0x33; TAG_LEN]);
    }

    #[test]
    fn every_prefix_is_refused() {
        let mut bytes = header().to_bytes().to_vec();
        bytes.extend_from_slice(&[0x33; 32 + TAG_LEN]);
        for end in 0..bytes.len() {
            let error = parse(&bytes[..end]).err().unwrap();
            let expected = if end < 4 {
                Malformed::Magic
            } else if end < HEADER_LEN + TAG_LEN {
                Malformed::Truncated
            } else {
                Malformed::Length
            };
            assert_eq!(error, Error::Malformed { problem: expected }, "{end} bytes");
        }
    }
}
