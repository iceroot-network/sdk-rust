//! The keystore: a recovery phrase's entropy encrypted under a password with Argon2id and
//! XChaCha20-Poly1305, in the versioned format of the SDK's `iceroot-keystore` crate. Nothing is
//! stored here; the app keeps the bytes (or their text form) where its platform keeps secrets.
//!
//! Secrets cross the boundary as UTF-8 bytes in the caller's own buffers: a phrase and every
//! password are overwritten with zeros whatever the outcome. A decrypted phrase is returned as the
//! core's [`Mnemonic`], whose buffer is wiped when it is dropped; the binding hands its bytes to
//! its host (the WebAssembly module as a new JavaScript array, which then wipes what the call left
//! on its stack) or keeps it (the Tauri plugin, which derives keys from it without handing the
//! phrase to the webview).
//!
//! The keystore's refusals keep their stable codes and details (`WrongPasswordOrCorrupt`,
//! `Malformed`, `UnsupportedVersion`, `UnsupportedKdf`, `UnsupportedPayload`, `ParamsOutOfRange`,
//! `InvalidPayload`, `InvalidPassword`, `OutOfMemory`, and the core's `RandomnessUnavailable`);
//! a phrase that is not one keys are made from keeps the core's `InvalidPhrase` or
//! `PhraseTooShort`, and a password that is not UTF-8 is `InvalidArgument`.

use iceroot_sdk::keystore::{self, Bounds, Header, Params, Payload, PayloadKind};
use iceroot_sdk::phrase::Mnemonic;
use zeroize::Zeroize;

use crate::error::{BindingError, Result};
use crate::json::{parse_object, unsigned};
use crate::write::Json;

impl From<keystore::Error> for BindingError {
    fn from(error: keystore::Error) -> BindingError {
        BindingError::with_details(error.code(), error.to_string(), error.details())
    }
}

/// A new keystore of the recovery phrase in `phrase` (UTF-8 bytes of 18, 21 or 24 BIP39 English
/// words) under `password` (UTF-8 bytes), with `params` in JSON: `{ memoryKib, iterations,
/// parallelism }`, a platform's preset or the app's own. The salt and nonce are fresh
/// from `crypto.getRandomValues`. Both arrays are overwritten with zeros.
pub fn keystore_encrypt(phrase: &mut [u8], password: &mut [u8], params: &str) -> Result<Vec<u8>> {
    let result = encrypt_phrase(phrase, password, params);
    phrase.zeroize();
    password.zeroize();
    result
}

/// Decrypts a keystore with `password` (UTF-8 bytes, overwritten with zeros) and gives back the
/// recovery phrase it holds (the payload kind `bip39-entropy`, the only one this release opens),
/// held in a buffer that is wiped when dropped; its canonical text has the words joined by single
/// spaces. `max_memory_kib` lowers the memory a keystore may ask for, on a platform that cannot
/// spare the format's ceiling.
pub fn keystore_decrypt(
    keystore: &[u8],
    password: &mut [u8],
    max_memory_kib: Option<u32>,
) -> Result<Mnemonic> {
    let result = open(keystore, password, &bounds(max_memory_kib));
    password.zeroize();
    result
}

/// The header of a keystore, read without the password, in JSON: `{ version, kdf, memoryKib,
/// iterations, parallelism, salt, nonce, payloadKind, payloadLength, keystoreLength }`.
pub fn keystore_inspect(keystore: &[u8]) -> Result<String> {
    let header = keystore::inspect(keystore)?;
    Ok(header_json(&header))
}

/// The keystore encrypted again under `new_password` with `params`, a fresh salt and a fresh
/// nonce, once `old_password` opens it. Both password arrays are overwritten with zeros.
pub fn keystore_change_password(
    keystore: &[u8],
    old_password: &mut [u8],
    new_password: &mut [u8],
    params: &str,
) -> Result<Vec<u8>> {
    let result = (|| {
        let params = params_from_json(params)?;
        let old = password_text(old_password)?;
        let new = password_text(new_password)?;
        Ok(keystore::change_password(keystore, old, new, params)?)
    })();
    old_password.zeroize();
    new_password.zeroize();
    result
}

/// The keystore encrypted again under the same password with new `params`, a fresh salt and a
/// fresh nonce: for moving it to a newer preset after an unlock. The password array is
/// overwritten with zeros.
pub fn keystore_reencrypt(keystore: &[u8], password: &mut [u8], params: &str) -> Result<Vec<u8>> {
    let result = (|| {
        let params = params_from_json(params)?;
        let password = password_text(password)?;
        Ok(keystore::reencrypt(keystore, password, params)?)
    })();
    password.zeroize();
    result
}

/// The text form of a keystore: `irks:` and the bytes in unpadded base64url.
pub fn keystore_armor(keystore: &[u8]) -> String {
    keystore::armor(keystore)
}

/// The bytes of a keystore's text form.
pub fn keystore_dearmor(text: &str) -> Result<Vec<u8>> {
    Ok(keystore::dearmor(text)?)
}

/// Checks `params` (as [`keystore_encrypt`] takes them) against the format's bounds, with the
/// memory ceiling lowered to `maxMemoryKib` when given: `ParamsOutOfRange` naming the first
/// parameter out of range, or nothing.
pub fn keystore_check_params(params: &str, max_memory_kib: Option<u32>) -> Result<()> {
    Ok(bounds(max_memory_kib).check(&params_from_json(params)?)?)
}

/// Whether a keystore written with `params` should be encrypted again with `than`, the parameters
/// an app writes now: less memory, or the same memory and fewer passes. A keystore never moves to
/// less memory.
pub fn keystore_is_weaker(params: &str, than: &str) -> Result<bool> {
    Ok(params_from_json(params)?.is_weaker_than(&params_from_json(than)?))
}

fn encrypt_phrase(phrase: &[u8], password: &[u8], params: &str) -> Result<Vec<u8>> {
    let params = params_from_json(params)?;
    let password = password_text(password)?;
    let mnemonic = Mnemonic::parse_utf8(phrase)?;
    let payload = Payload::bip39_entropy(mnemonic.entropy())?;
    Ok(keystore::encrypt(&payload, password, params)?)
}

/// The phrase of a keystore, held in wiped memory.
fn open(keystore: &[u8], password: &[u8], bounds: &Bounds) -> Result<Mnemonic> {
    let password = password_text(password)?;
    let payload = keystore::decrypt_with_bounds(keystore, password, bounds)?;
    match payload.kind() {
        PayloadKind::Bip39Entropy => Ok(Mnemonic::from_entropy(payload.secret_bytes())?),
        other => Err(keystore::Error::UnsupportedPayload { kind: other.code() }.into()),
    }
}

fn bounds(max_memory_kib: Option<u32>) -> Bounds {
    match max_memory_kib {
        Some(kib) => Bounds::STANDARD.with_memory_ceiling_kib(kib),
        None => Bounds::STANDARD,
    }
}

fn password_text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| BindingError::argument("the password is not UTF-8"))
}

fn params_from_json(text: &str) -> Result<Params> {
    let params = parse_object(text, "the parameters")?;
    let number = |key: &str| {
        u32::try_from(unsigned(&params, key, u64::from(u32::MAX))?)
            .map_err(|_| BindingError::argument(format!("{key} is out of range")))
    };
    Ok(Params::new(
        number("memoryKib")?,
        number("iterations")?,
        number("parallelism")?,
    ))
}

fn header_json(header: &Header) -> String {
    let params = header.params();
    let mut json = Json::new();
    json.open()
        .field_num("version", header.version())
        .field_str("kdf", header.kdf().as_str())
        .field_num("memoryKib", params.memory_kib())
        .field_num("iterations", params.iterations())
        .field_num("parallelism", params.parallelism())
        .field_str("salt", &hex(header.salt()))
        .field_str("nonce", &hex(header.nonce()))
        .field_str("payloadKind", header.payload_kind().as_str())
        .field_num("payloadLength", len(header.payload_len()))
        .field_num("keystoreLength", len(header.keystore_len()))
        .close();
    json.finish()
}

fn len(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Test seam of the bindings only (feature `keystore-testing`, which the test builds of the
/// WebAssembly module and the Tauri plugin turn on and the published builds never do): the
/// keystore vectors' own salt, nonce and lowered bounds, so that every record of the vectors runs
/// through a binding.
#[cfg(feature = "keystore-testing")]
pub mod testing {
    use super::*;
    use iceroot_sdk::keystore::{ARMOR_PREFIX, HEADER_LEN, MAX_PASSWORD_BYTES, Preset};

    /// The format's constants, in JSON: `{ presets: { desktop, mobile, web }, bounds: { floor,
    /// ceiling, maxWork }, maxPasswordBytes, armorPrefix, headerLength }`. The wrapper's
    /// constants are tested against them.
    pub fn keystore_constants() -> String {
        let bounds = Bounds::STANDARD;
        let mut json = Json::new();
        json.open().key("presets").open();
        for preset in Preset::ALL {
            json.key(preset.as_str());
            write_params(&mut json, &preset.params());
        }
        json.close().key("bounds").open().key("floor");
        write_params(&mut json, &bounds.floor());
        json.key("ceiling");
        write_params(&mut json, &bounds.ceiling());
        json.field_num("maxWork", bounds.max_work())
            .close()
            .field_num("maxPasswordBytes", len(MAX_PASSWORD_BYTES))
            .field_str("armorPrefix", ARMOR_PREFIX)
            .field_num("headerLength", len(HEADER_LEN))
            .close();
        json.finish()
    }

    fn write_params(json: &mut Json, params: &Params) {
        json.open()
            .field_num("memoryKib", params.memory_kib())
            .field_num("iterations", params.iterations())
            .field_num("parallelism", params.parallelism())
            .close();
    }

    fn test_bounds(name: &str) -> Result<Bounds> {
        match name {
            "standard" => Ok(Bounds::STANDARD),
            "test" => Ok(Bounds::TEST),
            other => Err(BindingError::argument(format!(
                "bounds {other:?} are not standard or test"
            ))),
        }
    }

    /// A keystore of `secret` of payload kind `kind` (`bip39-entropy` or `ml-dsa-65-seed`) with
    /// the given salt and nonce, under `bounds` (`standard` or `test`).
    pub fn keystore_encrypt_with_salt_and_nonce(
        kind: &str,
        secret: &[u8],
        password: &str,
        params: &str,
        salt: &[u8],
        nonce: &[u8],
        bounds: &str,
    ) -> Result<Vec<u8>> {
        let kind = match kind {
            "bip39-entropy" => PayloadKind::Bip39Entropy,
            "ml-dsa-65-seed" => PayloadKind::MlDsa65Seed,
            other => {
                return Err(BindingError::argument(format!(
                    "{other:?} is not a payload kind"
                )));
            }
        };
        let salt = salt
            .try_into()
            .map_err(|_| BindingError::argument("the salt is not 16 bytes"))?;
        let nonce = nonce
            .try_into()
            .map_err(|_| BindingError::argument("the nonce is not 24 bytes"))?;
        let payload = Payload::new(kind, secret)?;
        Ok(keystore::encrypt_with_salt_and_nonce(
            &payload,
            password,
            params_from_json(params)?,
            salt,
            nonce,
            &test_bounds(bounds)?,
        )?)
    }

    /// The payload of a keystore under `bounds`, in the vectors' JSON: `{ kind, secret,
    /// wordCount }`, the secret in hex.
    pub fn keystore_decrypt_with_bounds(
        keystore: &[u8],
        password: &str,
        bounds: &str,
    ) -> Result<String> {
        let payload = keystore::decrypt_with_bounds(keystore, password, &test_bounds(bounds)?)?;
        let mut json = Json::new();
        json.open()
            .field_str("kind", payload.kind().as_str())
            .field_str("secret", &hex(payload.secret_bytes()));
        if let Some(words) = payload.word_count() {
            json.field_num("wordCount", len(words));
        }
        json.close();
        Ok(json.finish())
    }

    /// Checks `params` against `bounds`.
    pub fn keystore_check_params_with_bounds(params: &str, bounds: &str) -> Result<()> {
        Ok(test_bounds(bounds)?.check(&params_from_json(params)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will";
    // The lowest parameters the format accepts, to run quickly.
    const LOW: &str = r#"{"memoryKib":19456,"iterations":2,"parallelism":1}"#;
    const WEB: &str = r#"{"memoryKib":65536,"iterations":4,"parallelism":4}"#;
    const DESKTOP: &str = r#"{"memoryKib":262144,"iterations":3,"parallelism":4}"#;

    #[test]
    fn a_phrase_round_trips_and_every_secret_is_wiped() {
        let mut phrase = PHRASE.as_bytes().to_vec();
        let mut password = b"correct horse".to_vec();
        let stored = keystore_encrypt(&mut phrase, &mut password, LOW).unwrap();
        assert!(phrase.iter().all(|&b| b == 0));
        assert!(password.iter().all(|&b| b == 0));
        let header: Value = serde_json::from_str(&keystore_inspect(&stored).unwrap()).unwrap();
        assert_eq!(header["payloadKind"], "bip39-entropy");
        assert_eq!(header["payloadLength"], 24);
        assert_eq!(header["keystoreLength"], stored.len());
        let mnemonic = open(&stored, b"correct horse", &Bounds::STANDARD).unwrap();
        assert_eq!(mnemonic.word_count(), 18);
        assert_eq!(mnemonic.phrase(), PHRASE);
        let wrong = open(&stored, b"wrong horse", &Bounds::STANDARD).unwrap_err();
        assert_eq!(wrong.code(), "WrongPasswordOrCorrupt");
        assert_eq!(keystore_dearmor(&keystore_armor(&stored)).unwrap(), stored);

        let mut old = b"correct horse".to_vec();
        let mut new = b"battery staple".to_vec();
        let changed = keystore_change_password(&stored, &mut old, &mut new, WEB).unwrap();
        assert!(old.iter().chain(&new).all(|&b| b == 0));
        let header: Value = serde_json::from_str(&keystore_inspect(&changed).unwrap()).unwrap();
        assert_eq!(header["memoryKib"], 65_536);
        let mnemonic = open(&changed, b"battery staple", &Bounds::STANDARD).unwrap();
        assert_eq!(mnemonic.phrase(), PHRASE);
    }

    #[test]
    fn refusals_keep_their_codes() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let error = keystore_encrypt(&mut twelve.as_bytes().to_vec(), &mut b"pw".to_vec(), LOW)
            .unwrap_err();
        assert_eq!(error.code(), "PhraseTooShort");
        let error =
            keystore_encrypt(&mut PHRASE.as_bytes().to_vec(), &mut Vec::new(), LOW).unwrap_err();
        assert_eq!(error.code(), "InvalidPassword");
        assert_eq!(error.details(), &json!({ "reason": "empty" }));
        let error =
            keystore_encrypt(&mut PHRASE.as_bytes().to_vec(), &mut [0xff], LOW).unwrap_err();
        assert_eq!(error.code(), "InvalidArgument");
        let error =
            keystore_check_params(r#"{"memoryKib":8,"iterations":1,"parallelism":1}"#, None)
                .unwrap_err();
        assert_eq!(error.code(), "ParamsOutOfRange");
        assert_eq!(error.details()["param"], "memory");
        assert_eq!(keystore_inspect(b"nope").unwrap_err().code(), "Malformed");
        assert!(params_from_json("\"web\"").is_err());
        assert!(keystore_check_params(DESKTOP, Some(64 * 1024)).is_err());
        assert!(keystore_check_params(WEB, Some(64 * 1024)).is_ok());
        assert!(keystore_is_weaker(WEB, DESKTOP).unwrap());
        assert!(!keystore_is_weaker(DESKTOP, WEB).unwrap());
    }

    #[cfg(feature = "keystore-testing")]
    #[test]
    fn constants() {
        let constants: Value = serde_json::from_str(&testing::keystore_constants()).unwrap();
        assert_eq!(
            constants["presets"]["desktop"],
            json!({ "memoryKib": 262_144, "iterations": 3, "parallelism": 4 })
        );
        assert_eq!(constants["armorPrefix"], "irks:");
        assert_eq!(constants["bounds"]["maxWork"], 2_097_152);
    }
}
