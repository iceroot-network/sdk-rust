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

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Secret, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(|bytes| Secret(Zeroizing::new(bytes)))
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
        let answer = SecretBytes(Zeroizing::new(b"hi".to_vec()));
        assert_eq!(serde_json::to_string(&answer).unwrap(), "[104,105]");
        assert_eq!(format!("{answer:?}"), "SecretBytes(..)");
    }
}
