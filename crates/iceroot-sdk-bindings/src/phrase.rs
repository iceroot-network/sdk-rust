//! Recovery phrases.
//!
//! A phrase is secret, so no copy of it is left behind in the binding's memory: the phrases these
//! functions take are owned strings that are wiped when the call ends. A new phrase comes from
//! the core's [`Mnemonic::generate`], whose buffer is wiped when dropped; a binding hands its text
//! to its host straight from that buffer.

use iceroot_sdk::Error;
use iceroot_sdk::phrase::Mnemonic;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::Result;

/// A new 24-word recovery phrase from 256 bits of the platform's random generator
/// (`crypto.getRandomValues` in WebAssembly), in a buffer that is wiped when dropped.
pub fn generate_phrase() -> Result<Mnemonic> {
    Ok(Mnemonic::generate()?)
}

/// What is wrong with `text` as a recovery phrase for keys, for feedback while it is typed. JSON:
/// `{ ok, words, reason?, position? }`, where the reason is `empty`, `not-text`, `unknown-word`
/// (with the 1-based position of the word), `word-count`, `too-short` or `checksum`. No word of
/// the phrase is ever repeated. The owned copy of `text` is wiped.
pub fn check_phrase(text: String) -> String {
    let text = Zeroizing::new(text);
    phrase_check(&text)
}

/// The JSON result of [`check_phrase`].
fn phrase_check(text: &str) -> String {
    let check = Mnemonic::check(text);
    let mut result = json!({ "ok": check.is_ok(), "words": check.words });
    if let Some(problem) = check.problem
        && let (Value::Object(result), Value::Object(details)) =
            (&mut result, Error::InvalidPhrase { problem }.details())
    {
        for key in ["reason", "position"] {
            if let Some(value) = details.get(key) {
                result.insert(key.to_owned(), value.clone());
            }
        }
    }
    result.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_check() {
        let phrase = generate_phrase().unwrap();
        assert_eq!(phrase.phrase().split(' ').count(), 24);
        let check: Value = serde_json::from_str(&check_phrase(phrase.phrase().to_owned())).unwrap();
        assert_eq!(check, json!({ "ok": true, "words": 24 }));
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let check: Value = serde_json::from_str(&check_phrase(twelve.to_owned())).unwrap();
        assert_eq!(
            check,
            json!({ "ok": false, "words": 12, "reason": "too-short" })
        );
        let check: Value = serde_json::from_str(&check_phrase("abandon zzz".to_owned())).unwrap();
        assert_eq!(check["reason"], "unknown-word");
        assert_eq!(check["position"], 2);
    }
}
