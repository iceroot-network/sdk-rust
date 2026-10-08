//! Ownership proofs of Solar addresses, version 1: the SDK core's `ownership` module.
//!
//! A holder proves control of a Solar mainnet address by signing a fixed nine-line message that
//! names the address and an IceRoot account, as the IceRoot Legacy Signer does. These functions
//! need no network profile.
//!
//! A Solar key is held by the binding like an account's key: the host receives its address and
//! public key, [`ProofKey::release`] wipes it, and a passphrase given as bytes is overwritten with
//! zeros whatever the outcome. The message functions share one entry, [`ownership_call`], which
//! keeps the WebAssembly module small. Refusals are the core's `InvalidProof` with its `reason`;
//! an argument of the wrong shape is `InvalidArgument`.

use iceroot_sdk::error::ProofProblem;
use iceroot_sdk::ownership::{
    self, IceRootAccount, OwnershipProof, ProofExpected, ProofFields, ProofRequest, SolarKey,
};
use iceroot_sdk::{Address, Aux, Error, PublicKey};
use zeroize::Zeroize;

use crate::error::{BindingError, Result};
use crate::json::{parse_object, string};
use crate::write::Json;

/// The largest time in milliseconds the functions accept either side of 1970: that of a
/// JavaScript `Date`.
const MAX_TIME_MS: f64 = 8.64e15;

/// A Solar key from its passphrase, held by the binding. It signs ownership proofs and nothing
/// else.
pub struct ProofKey {
    key: Option<SolarKey>,
}

impl ProofKey {
    /// The Solar key of the passphrase in `passphrase` (UTF-8 bytes): the SHA-256 of the exact
    /// text, as the reference implementation derives it. The bytes are overwritten with zeros,
    /// in the binding's memory and in the caller's buffer, whatever the outcome.
    pub fn from_passphrase(passphrase: &mut [u8]) -> Result<ProofKey> {
        let result = match core::str::from_utf8(passphrase) {
            Ok(text) => SolarKey::from_passphrase(text).map_err(BindingError::from),
            Err(_) => Err(BindingError::argument("the passphrase is not UTF-8")),
        };
        passphrase.zeroize();
        Ok(ProofKey { key: Some(result?) })
    }

    /// The key's Solar mainnet address.
    pub fn address(&self) -> Result<String> {
        Ok(self.key()?.address().to_string())
    }

    /// The key's public key, 33 bytes compressed, as lowercase hex.
    pub fn public_key(&self) -> Result<String> {
        Ok(self.key()?.public_key().to_hex())
    }

    /// Wipes the key. Later calls throw `KeyReleased`.
    pub fn release(&mut self) {
        // Dropped where it is, which overwrites the secret key's bytes. Taking it out first would
        // move a copy to the stack and wipe only that, leaving the bytes in the handle's memory.
        self.key = None;
    }

    /// The proof of `message` signed with this key and fresh randomness at the signer's time
    /// `now_ms`, as the proof's JSON text. The message must pass the format's checks and name
    /// this key's address.
    pub fn sign_proof(&self, message: &str, now_ms: f64) -> Result<String> {
        self.sign_proof_with(message, now_ms, Aux::random())
    }
}

impl ProofKey {
    fn key(&self) -> Result<&SolarKey> {
        self.key
            .as_ref()
            .ok_or_else(|| BindingError::from(Error::KeyReleased))
    }

    /// As [`ProofKey::sign_proof`], with the auxiliary randomness `aux` (the test seam of the
    /// feature `fixed-aux` passes fixed bytes).
    pub fn sign_proof_with(&self, message: &str, now_ms: f64, aux: Aux) -> Result<String> {
        let proof = ownership::sign_with(self.key()?, message, time(now_ms)?, aux)?;
        Ok(proof.to_json())
    }
}

/// The ownership proof functions, by `operation`:
///
/// - `source-address`: the Solar mainnet address of the public key `first` (lowercase hex);
/// - `account` and `account-canonical`: the IceRoot account in `first`, as typed or exactly as a
///   message writes it, in JSON `{ account, network }`;
/// - `nonce`: a new nonce, 64 lowercase hex digits;
/// - `build`: the proof message of `first`, JSON `{ address, account, nonce, issuedAtMs }`;
/// - `parse`: the fields of the message `first`, expected to name the address `second` unless it
///   is empty, at the reader's time `now_ms`, in JSON `{ address, account, accountNetwork, nonce,
///   issuedAt, issuedAtMs }`;
/// - `from-signature`: the proof of the message `first` with the signature made elsewhere in
///   `second`, JSON `{ publicKey, signature }`, checked at `now_ms`, as the proof's JSON text;
/// - `verify`: the fields of the signed proof in the JSON text `first`, verified at `now_ms`;
/// - `from-json`: the signed proof in the JSON text `first`, unverified, as the format writes it.
pub fn ownership_call(operation: &str, first: &str, second: &str, now_ms: f64) -> Result<String> {
    match operation {
        "source-address" => {
            let key = public_key(first).ok_or_else(|| problem(ProofProblem::Key))?;
            Ok(ownership::source_address(&key).to_string())
        }
        "account" => Ok(account_json(&IceRootAccount::parse(first)?)),
        "account-canonical" => Ok(account_json(&IceRootAccount::parse_canonical(first)?)),
        "nonce" => Ok(ownership::random_nonce()?),
        "build" => {
            let request = parse_object(first, "the proof request")?;
            let address = Address::parse_any_network(string(&request, "address")?)
                .map_err(|_| problem(ProofProblem::Address))?;
            let account = IceRootAccount::parse_canonical(string(&request, "account")?)?;
            let issued_at_ms = request
                .get("issuedAtMs")
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| BindingError::argument("issuedAtMs is not a number"))?;
            Ok(ownership::build(&ProofRequest {
                address: &address,
                account: &account,
                nonce: string(&request, "nonce")?,
                issued_at_ms: time(issued_at_ms)?,
            })?)
        }
        "parse" => {
            let expected = ProofExpected {
                address: (!second.is_empty()).then_some(second),
            };
            Ok(fields_json(&ownership::parse(
                first,
                &expected,
                time(now_ms)?,
            )?))
        }
        "from-signature" => {
            let signature = parse_object(second, "the signature")?;
            let proof = OwnershipProof::from_signature(
                first,
                string(&signature, "publicKey")?,
                string(&signature, "signature")?,
                time(now_ms)?,
            )?;
            Ok(proof.to_json())
        }
        "verify" => {
            let proof = OwnershipProof::from_json(first)?;
            Ok(fields_json(&ownership::verify(&proof, time(now_ms)?)?))
        }
        "from-json" => Ok(OwnershipProof::from_json(first)?.to_json()),
        other => Err(BindingError::argument(format!(
            "no ownership operation {other}"
        ))),
    }
}

fn problem(problem: ProofProblem) -> BindingError {
    BindingError::from(Error::InvalidProof { problem })
}

/// The public key in `text` in the form a proof writes it: 33 bytes compressed, lowercase hex.
fn public_key(text: &str) -> Option<PublicKey> {
    let form = text.len() == 66
        && (text.starts_with("02") || text.starts_with("03"))
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if form {
        PublicKey::from_hex(text).ok()
    } else {
        None
    }
}

/// A time in whole milliseconds since 1970, as JavaScript passes it.
fn time(ms: f64) -> Result<i64> {
    if ms.is_finite() && ms.fract() == 0.0 && ms.abs() <= MAX_TIME_MS {
        // Exact: the value is a whole number of at most 8.64e15.
        #[allow(clippy::cast_possible_truncation)]
        Ok(ms as i64)
    } else {
        Err(BindingError::argument(
            "a time is a whole number of milliseconds within a JavaScript Date's range",
        ))
    }
}

fn account_json(account: &IceRootAccount) -> String {
    let mut json = Json::new();
    json.open()
        .field_str("account", account.as_str())
        .field_str("network", account.network().as_str())
        .close();
    json.finish()
}

fn fields_json(fields: &ProofFields) -> String {
    let mut json = Json::new();
    json.open()
        .field_str("address", &fields.address)
        .field_str("account", fields.account.as_str())
        .field_str("accountNetwork", fields.account.network().as_str())
        .field_str("nonce", &fields.nonce)
        .field_str("issuedAt", &fields.issued_at)
        .key("issuedAtMs")
        .raw(&fields.issued_at_ms.to_string())
        .close();
    json.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "ownership proof binding test";

    fn key() -> ProofKey {
        let mut bytes = PASSPHRASE.as_bytes().to_vec();
        let key = ProofKey::from_passphrase(&mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
        key
    }

    fn account() -> String {
        // The IceRoot account of the format's own test vectors.
        "ice1xxy02tyls8d0p0jk8dwxnqjqts8ly4e87648j8zqdd7mnfndxsyqv4qs2h".to_owned()
    }

    #[test]
    fn a_proof_is_built_signed_verified_and_read_back() {
        let key = key();
        let now = 1_790_000_000_000_i64;
        let nonce = ownership_call("nonce", "", "", 0.0).unwrap();
        let request = format!(
            r#"{{"address":"{}","account":"{}","nonce":"{nonce}","issuedAtMs":{now}}}"#,
            key.address().unwrap(),
            account()
        );
        let message = ownership_call("build", &request, "", 0.0).unwrap();
        let fields =
            ownership_call("parse", &message, &key.address().unwrap(), now as f64).unwrap();
        assert!(fields.contains(r#""accountNetwork":"mainnet""#));
        assert!(fields.ends_with(&format!(r#""issuedAtMs":{now}}}"#)));

        let proof = key.sign_proof(&message, now as f64).unwrap();
        assert_eq!(
            ownership_call("verify", &proof, "", now as f64).unwrap(),
            fields
        );
        assert_eq!(ownership_call("from-json", &proof, "", 0.0).unwrap(), proof);
        let signed = OwnershipProof::from_json(&proof).unwrap();
        let signature = format!(
            r#"{{"publicKey":"{}","signature":"{}"}}"#,
            signed.public_key, signed.signature
        );
        assert_eq!(
            ownership_call("from-signature", &message, &signature, now as f64).unwrap(),
            proof
        );
        assert_eq!(
            ownership_call("source-address", &key.public_key().unwrap(), "", 0.0).unwrap(),
            key.address().unwrap()
        );
    }

    #[test]
    fn refusals_keep_the_core_code_and_reason() {
        let refused = ownership_call("account", "ice1qqqq", "", 0.0).unwrap_err();
        assert_eq!(refused.code(), "InvalidProof");
        assert_eq!(refused.details()["reason"], "account");
        let malformed = ownership_call("source-address", "04ab", "", 0.0).unwrap_err();
        assert_eq!(malformed.details()["reason"], "key");
        assert_eq!(
            ownership_call("parse", "x", "", 1.5).unwrap_err().code(),
            "InvalidArgument"
        );
        assert_eq!(
            ownership_call("unknown", "", "", 0.0).unwrap_err().code(),
            "InvalidArgument"
        );
        let mut handle = key();
        handle.release();
        assert_eq!(handle.address().unwrap_err().code(), "KeyReleased");
    }
}
