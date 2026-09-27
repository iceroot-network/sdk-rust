//! The text form of a keystore, for stores that hold strings only: the prefix `irks:` and the
//! keystore's bytes in unpadded base64url (RFC 4648, section 5).
//!
//! Decoding is strict: the prefix is lowercase and exact, no padding, whitespace or line breaks
//! are allowed, the alphabet is base64url's only, and the unused bits of the last character must
//! be zero, so every keystore has exactly one text form.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{Error, Malformed};

/// The prefix of a keystore's text form.
pub const ARMOR_PREFIX: &str = "irks:";

/// The most bytes a keystore of any version this release knows may have once decoded. Longer
/// text is refused before it is decoded.
const MAX_DECODED_LEN: usize = 1024;

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
pub fn dearmor(text: &str) -> Result<Vec<u8>, Error> {
    let malformed = |problem| Error::Malformed { problem };
    let encoded = text
        .strip_prefix(ARMOR_PREFIX)
        .ok_or(malformed(Malformed::ArmorPrefix))?;
    if encoded.len() > MAX_DECODED_LEN.div_ceil(3) * 4 {
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
}
