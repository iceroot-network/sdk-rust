//! The forms values take across the IPC: bytes as lowercase hex, secrets as UTF-8 bytes.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Lowercase hex of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        for digit in [byte >> 4, byte & 15] {
            text.extend(char::from_digit(u32::from(digit), 16));
        }
    }
    text
}

/// The bytes of hex `text` (either case). `what` names the value in the refusal.
pub(crate) fn from_hex(text: &str, what: &str) -> Result<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::argument(format!("{what} is not hex of whole bytes")));
    }
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    pairs
        .iter()
        .map(|&[high, low]| Some((digit(high)? << 4) | digit(low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| Error::argument(format!("{what} is not hex")))
}

/// A phrase, passphrase or password, as the UTF-8 bytes the guest code sends. The plugin's copy
/// is overwritten with zeros when the command ends, whatever the outcome.
///
/// The IPC message that carried it is the webview's and Tauri's, and neither wipes it: a secret
/// that never needs to enter the webview should not (open keys from a keystore with
/// `key_from_keystore` instead of decrypting the phrase into the page).
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// The bytes, for a function that overwrites them with zeros.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// The text, which must be UTF-8.
    pub(crate) fn text(&self, what: &str) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|_| Error::argument(format!("{what} is not UTF-8")))
    }

    /// The text as an owned string, which the core wipes when it is done with it.
    pub(crate) fn into_string(self, what: &str) -> Result<String> {
        Ok(self.text(what)?.to_owned())
    }
}

/// The refusal of anything but an array of bytes where a secret is expected. It is fixed, so no
/// part of what the page sent (a phrase sent as a string, a word of it in an array) is written
/// into the refusal the page and its logs receive.
const NOT_A_SECRET: &str = "a secret is an array of UTF-8 bytes";

/// Reads a secret without ever writing what was sent into an error.
struct SecretVisitor;

/// Visitor methods that refuse their form with [`NOT_A_SECRET`], never with what was sent.
macro_rules! refuse {
    ($value:ty; $($method:ident($($ty:ty)?)),* $(,)?) => {
        $(
            fn $method<E: serde::de::Error>(self $(, _: $ty)?) -> std::result::Result<$value, E> {
                Err(E::custom(NOT_A_SECRET))
            }
        )*
    };
}

/// Visitor methods of the nested forms (an option's value, a map, an enum), refused the same way.
macro_rules! refuse_nested {
    ($value:ty, $de:lifetime) => {
        fn visit_some<D: Deserializer<$de>>(self, _: D) -> std::result::Result<$value, D::Error> {
            Err(serde::de::Error::custom(NOT_A_SECRET))
        }

        fn visit_newtype_struct<D: Deserializer<$de>>(
            self,
            _: D,
        ) -> std::result::Result<$value, D::Error> {
            Err(serde::de::Error::custom(NOT_A_SECRET))
        }

        fn visit_map<A: serde::de::MapAccess<$de>>(
            self,
            _: A,
        ) -> std::result::Result<$value, A::Error> {
            Err(serde::de::Error::custom(NOT_A_SECRET))
        }

        fn visit_enum<A: serde::de::EnumAccess<$de>>(
            self,
            _: A,
        ) -> std::result::Result<$value, A::Error> {
            Err(serde::de::Error::custom(NOT_A_SECRET))
        }
    };
}

impl<'de> serde::de::Visitor<'de> for SecretVisitor {
    type Value = Secret;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NOT_A_SECRET)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Secret, A::Error> {
        // Wiped on every path, including a refusal half way.
        let mut bytes = Zeroizing::new(Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096)));
        while let Some(SecretByte(byte)) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(Secret(bytes))
    }

    refuse!(
        Secret;
        visit_bool(bool),
        visit_i64(i64),
        visit_i128(i128),
        visit_u64(u64),
        visit_u128(u128),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_bytes(&[u8]),
        visit_none(),
        visit_unit(),
    );
    refuse_nested!(Secret, 'de);
}

/// One byte of a secret: a whole number from 0 to 255, refused without saying what it was.
struct SecretByte(u8);

/// Reads one byte of a secret without ever writing what was sent into an error.
struct SecretByteVisitor;

impl<'de> serde::de::Visitor<'de> for SecretByteVisitor {
    type Value = SecretByte;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NOT_A_SECRET)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<SecretByte, E> {
        u8::try_from(value)
            .map(SecretByte)
            .map_err(|_| E::custom(NOT_A_SECRET))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<SecretByte, E> {
        u8::try_from(value)
            .map(SecretByte)
            .map_err(|_| E::custom(NOT_A_SECRET))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        _: A,
    ) -> std::result::Result<SecretByte, A::Error> {
        Err(serde::de::Error::custom(NOT_A_SECRET))
    }

    refuse!(
        SecretByte;
        visit_bool(bool),
        visit_i128(i128),
        visit_u128(u128),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_bytes(&[u8]),
        visit_none(),
        visit_unit(),
    );
    refuse_nested!(SecretByte, 'de);
}

impl<'de> Deserialize<'de> for SecretByte {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<SecretByte, D::Error> {
        deserializer.deserialize_any(SecretByteVisitor)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Secret, D::Error> {
        // `deserialize_any`, not `deserialize_seq`: a JSON value that is not an array is handed
        // to the visitor, which refuses it without the value, instead of being described in the
        // deserializer's own error.
        deserializer.deserialize_any(SecretVisitor)
    }
}

/// A secret the plugin answers with (a decrypted recovery phrase), as the array of UTF-8 bytes the
/// guest code reads. The plugin's copy is overwritten with zeros once it is written into the answer;
/// the answer itself, like every IPC message, is the webview's and Tauri's.
pub(crate) struct SecretBytes(pub(crate) Zeroizing<Vec<u8>>);

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter())
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never shows the secret.
        f.write_str("SecretBytes(..)")
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never shows the secret.
        f.write_str("Secret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(to_hex(&[0, 0x7f, 0xff]), "007fff");
        assert_eq!(from_hex("007FfF", "x").unwrap(), [0, 0x7f, 0xff]);
        assert!(from_hex("abc", "x").is_err());
        assert!(from_hex("zz", "x").is_err());
        assert!(from_hex("", "x").unwrap().is_empty());
    }

    #[test]
    fn secrets_are_bytes_and_never_shown() {
        let mut secret: Secret = serde_json::from_str("[104, 105]").unwrap();
        assert_eq!(secret.text("s").unwrap(), "hi");
        assert_eq!(format!("{secret:?}"), "Secret(..)");
        secret.bytes_mut().fill(0);
        assert_eq!(secret.text("s").unwrap(), "\0\0");
        let invalid: Secret = serde_json::from_str("[255]").unwrap();
        assert_eq!(invalid.text("s").unwrap_err().code(), "InvalidArgument");
        // A secret sent in another form is refused without a trace of it, whatever the form,
        // through a JSON text or a JSON value (Tauri's command arguments).
        for sent in [
            r#""correct horse battery staple""#,
            r#"["correct", "horse"]"#,
            r#"[104, 1234567]"#,
            r#"[104, -7777777]"#,
            r#"[104, 1.5]"#,
            r#"[[104, 105]]"#,
            r#"{"phrase": "correct horse"}"#,
            "123456789",
            "true",
            "null",
        ] {
            let error = serde_json::from_str::<Secret>(sent)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(NOT_A_SECRET), "{sent}: {error}");
            for trace in ["correct", "horse", "1234567", "7777777", "1.5", "123456789"] {
                assert!(!error.contains(trace), "{sent}: {error}");
            }
            let value: serde_json::Value = serde_json::from_str(sent).unwrap();
            let error = serde_json::from_value::<Secret>(value)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(NOT_A_SECRET), "{sent}: {error}");
            assert!(
                !error.contains("correct") && !error.contains("7777"),
                "{error}"
            );
        }
        let value = serde_json::json!([104, 105]);
        let mut secret = serde_json::from_value::<Secret>(value).unwrap();
        assert_eq!(secret.bytes_mut(), b"hi");
        let answer = SecretBytes(Zeroizing::new(b"hi".to_vec()));
        assert_eq!(serde_json::to_string(&answer).unwrap(), "[104,105]");
        assert_eq!(format!("{answer:?}"), "SecretBytes(..)");
    }
}
