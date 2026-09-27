//! The text form of a keystore, for stores that hold strings only: the prefix `irks:` and the
//! keystore's bytes in unpadded base64url (RFC 4648, section 5).
//!
//! Decoding is strict: the prefix is lowercase and exact, no padding, whitespace or line breaks
//! are allowed, the alphabet is base64url's only, and the unused bits of the last character must
//! be zero, so every keystore has exactly one text form. The checks run in a fixed order, so that
//! every implementation gives the same answer for the same text: the prefix, the alphabet, the
//! length, and then the canonical decoding.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{Error, Malformed};

/// The prefix of a keystore's text form.
pub const ARMOR_PREFIX: &str = "irks:";

/// The most bytes a keystore of any version this release knows may have once decoded.
const MAX_DECODED_LEN: usize = 1024;

/// The most characters of base64url after the prefix: the unpadded length of
/// [`MAX_DECODED_LEN`] bytes, 1,366. Longer text is refused before it is decoded.
const MAX_ENCODED_LEN: usize = (MAX_DECODED_LEN * 4).div_ceil(3);

/// The text form of keystore bytes. The bytes are not checked here: [`crate::inspect`] and
/// [`crate::decrypt`] check them when they are read back.
pub fn armor(bytes: &[u8]) -> String {
    let mut text =
        String::with_capacity(ARMOR_PREFIX.len() + Base64UrlUnpadded::encoded_len(bytes));
    text.push_str(ARMOR_PREFIX);
    text.push_str(&Base64UrlUnpadded::encode_string(bytes));
    text
}

/// The keystore bytes of a text form, decoded strictly. The result still has to pass
/// [`crate::inspect`] or [`crate::decrypt`].
///
/// The checks, in this order: the exact prefix ([`Malformed::ArmorPrefix`]); only characters of
/// the base64url alphabet after it ([`Malformed::ArmorEncoding`]); at most 1,366 of them
/// ([`Malformed::ArmorLength`]); and a canonical encoding, whose length is not one more than a
/// multiple of four and whose last character has its unused bits zero
/// ([`Malformed::ArmorEncoding`]).
pub fn dearmor(text: &str) -> Result<Vec<u8>, Error> {
    let malformed = |problem| Error::Malformed { problem };
    let encoded = text
        .strip_prefix(ARMOR_PREFIX)
        .ok_or(malformed(Malformed::ArmorPrefix))?;
    if !encoded
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(malformed(Malformed::ArmorEncoding));
    }
    if encoded.len() > MAX_ENCODED_LEN {
        return Err(malformed(Malformed::ArmorLength));
    }
    let mut buffer = [0u8; MAX_DECODED_LEN];
    let decoded = Base64UrlUnpadded::decode(encoded, &mut buffer)
        .map_err(|_| malformed(Malformed::ArmorEncoding))?;
    Ok(decoded.to_vec())
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn round_trip() {
        for length in 0..40 {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let text = armor(&bytes);
            assert!(text.starts_with(ARMOR_PREFIX));
            assert_eq!(dearmor(&text).unwrap(), bytes);
        }
    }

    #[test]
    fn strict() {
        let text = armor(b"IRKS\x01\x01");
        assert_eq!(text, "irks:SVJLUwEB");
        let encoding = Error::Malformed {
            problem: Malformed::ArmorEncoding,
        };
        let prefix = Error::Malformed {
            problem: Malformed::ArmorPrefix,
        };
        for bad in [
            "irks:SVJLUwEB=",
            "irks:SVJLUwEB\n",
            "irks: SVJLUwEB",
            "irks:SVJL+wEB",
            "irks:SVJL/wEB",
            "irks:SVJLUwEBA",
        ] {
            assert_eq!(dearmor(bad), Err(encoding.clone()), "{bad:?}");
        }
        // A last character whose unused bits are set is not canonical.
        let bytes = b"IRKS\x01";
        let canonical = armor(bytes);
        assert_eq!(canonical, "irks:SVJLUwE");
        assert_eq!(dearmor(&canonical).unwrap(), bytes);
        assert_eq!(dearmor("irks:SVJLUwF"), Err(encoding.clone()));
        for bad in ["IRKS:SVJLUwEB", "irks SVJLUwEB", "SVJLUwEB", ""] {
            assert_eq!(dearmor(bad), Err(prefix.clone()), "{bad:?}");
        }
        assert_eq!(
            dearmor(&format!("irks:{}", "A".repeat(2000))),
            Err(Error::Malformed {
                problem: Malformed::ArmorLength
            })
        );
    }

    #[test]
    fn the_length_limit_is_exact_and_checked_after_the_alphabet() {
        let length = Error::Malformed {
            problem: Malformed::ArmorLength,
        };
        let encoding = Error::Malformed {
            problem: Malformed::ArmorEncoding,
        };
        assert_eq!(MAX_ENCODED_LEN, 1366);
        let longest = armor(&[0xa5; MAX_DECODED_LEN]);
        assert_eq!(longest.len(), ARMOR_PREFIX.len() + MAX_ENCODED_LEN);
        assert_eq!(dearmor(&longest).unwrap(), [0xa5; MAX_DECODED_LEN]);
        // One character more would decode to 1,025 bytes; two more to 1,026.
        for extra in ["A", "AA", "AAA"] {
            assert_eq!(dearmor(&format!("{longest}{extra}")), Err(length.clone()));
        }
        // Text outside the alphabet is refused as such, however long; the length is counted only
        // once every character is known to be one byte.
        for bad in [
            format!("irks:{}", "\u{e9}".repeat(700)),
            format!("irks:{}\u{e9}", "A".repeat(1400)),
            format!("{longest} "),
        ] {
            assert_eq!(dearmor(&bad), Err(encoding.clone()));
        }
        assert_eq!(
            dearmor("Irks:SVJLUwEB"),
            Err(Error::Malformed {
                problem: Malformed::ArmorPrefix
            })
        );
    }
}
