//! Accounts whose secret keys the binding holds.

use iceroot_sdk::keys::{Account, AccountOptions, KeyOrigin};
use iceroot_sdk::message::{self, MessageSignature};
use iceroot_sdk::phrase::Mnemonic;
use iceroot_sdk::{Aux, Profile};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{BindingError, Result};

/// An account of the core: a secret key, its public key and address, and the profile it belongs
/// to. The secret never leaves the binding's memory: a host receives public keys, addresses and
/// signatures only.
///
/// [`Key::release`] wipes the key; dropping the value wipes it too.
pub struct Key {
    account: Option<Account>,
    profile: Profile,
    legacy: bool,
    path: Option<String>,
}

impl Key {
    /// The account at `account` and `index` of the recovery phrase `phrase` (18, 21 or 24 BIP39
    /// English words), with the optional BIP39 `passphrase`, derived with the key scheme of
    /// `profile`. The owned copies of the phrase and passphrase are wiped.
    pub fn from_phrase(
        profile: &Profile,
        phrase: String,
        account: u32,
        index: u32,
        passphrase: String,
    ) -> Result<Key> {
        let phrase = Zeroizing::new(phrase);
        let passphrase = Zeroizing::new(passphrase);
        let mnemonic = Mnemonic::parse(&phrase)?;
        Key::from_mnemonic(profile, &mnemonic, account, index, &passphrase)
    }

    /// As [`Key::from_phrase`], from the phrase's UTF-8 bytes. The bytes are overwritten with
    /// zeros, whatever the outcome.
    pub fn from_phrase_bytes(
        profile: &Profile,
        phrase: &mut [u8],
        account: u32,
        index: u32,
        passphrase: String,
    ) -> Result<Key> {
        let passphrase = Zeroizing::new(passphrase);
        let result = Mnemonic::parse_utf8(phrase)
            .map_err(BindingError::from)
            .and_then(|mnemonic| {
                Key::from_mnemonic(profile, &mnemonic, account, index, &passphrase)
            });
        phrase.zeroize();
        result
    }

    /// The account at `account` and `index` of the recovery phrase the keystore `keystore` holds,
    /// opened with `password` (UTF-8 bytes, overwritten with zeros whatever the outcome), with the
    /// optional BIP39 `passphrase`, whose owned copy is wiped. The phrase is decrypted and the key
    /// derived here: the phrase never reaches the host. `max_memory_kib` lowers the memory the
    /// keystore may ask for, as [`crate::keystore::keystore_decrypt`] does.
    #[allow(clippy::too_many_arguments)]
    pub fn from_keystore(
        profile: &Profile,
        keystore: &[u8],
        password: &mut [u8],
        account: u32,
        index: u32,
        passphrase: String,
        max_memory_kib: Option<u32>,
    ) -> Result<Key> {
        let passphrase = Zeroizing::new(passphrase);
        let mnemonic = crate::keystore::keystore_decrypt(keystore, password, max_memory_kib)?;
        Key::from_mnemonic(profile, &mnemonic, account, index, &passphrase)
    }

    /// The account at `account` and `index` of a phrase the caller already holds as a
    /// [`Mnemonic`] (for example one a keystore opened), with the optional BIP39 `passphrase`.
    pub fn from_mnemonic(
        profile: &Profile,
        mnemonic: &Mnemonic,
        account: u32,
        index: u32,
        passphrase: &str,
    ) -> Result<Key> {
        let options = AccountOptions {
            account,
            index,
            passphrase,
        };
        let account = Account::from_phrase(profile, mnemonic, &options)?;
        let path = match account.origin() {
            KeyOrigin::Phrase(path) => Some(path.to_string()),
            KeyOrigin::LegacyPassphrase => None,
        };
        Ok(Key {
            account: Some(account),
            profile: profile.clone(),
            legacy: false,
            path,
        })
    }

    /// The reference implementation's passphrase key: the SHA-256 of the passphrase's UTF-8
    /// bytes. For importing existing devnet identities only, on profiles in today's formats; new
    /// accounts come from recovery phrases. The owned copy of the text is wiped.
    pub fn from_legacy_passphrase(profile: &Profile, passphrase: String) -> Result<Key> {
        let passphrase = Zeroizing::new(passphrase);
        Key::import_legacy(profile, &passphrase)
    }

    /// As [`Key::from_legacy_passphrase`], from the passphrase's UTF-8 bytes. The bytes are
    /// overwritten with zeros.
    pub fn from_legacy_passphrase_bytes(profile: &Profile, passphrase: &mut [u8]) -> Result<Key> {
        let result = match std::str::from_utf8(passphrase) {
            Ok(text) => Key::import_legacy(profile, text),
            Err(_) => Err(BindingError::new(
                "InvalidPhrase",
                "the passphrase bytes are not UTF-8",
            )),
        };
        passphrase.zeroize();
        result
    }

    /// The compressed public key (33 bytes).
    pub fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.account()?.public_key().as_bytes().to_vec())
    }

    /// The account's address on its profile's network.
    pub fn address(&self) -> Result<String> {
        Ok(self.account()?.address().to_string())
    }

    /// The signature algorithm, for example `secp256k1-bip340`.
    pub fn algorithm(&self) -> Result<String> {
        Ok(self.account()?.algorithm().as_str().to_owned())
    }

    /// The derivation path of a key from a recovery phrase, for example `m/44'/1'/0'/0'/0'`.
    pub fn path(&self) -> Option<String> {
        self.path.clone()
    }

    /// Whether the key was imported from a legacy passphrase.
    pub fn legacy(&self) -> bool {
        self.legacy
    }

    /// Whether the key was released.
    pub fn released(&self) -> bool {
        self.account.is_none()
    }

    /// The profile the key belongs to.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The message signature of `message`'s bytes on the account's network: BIP340 over their
    /// SHA-256, with fresh auxiliary randomness. JSON: `{ publicKey, signature, algorithm,
    /// network }`. The bytes must be UTF-8 text; any other bytes are refused with
    /// `InvalidArgument`, since they may be a transaction's, whose signature a message signature
    /// would be.
    pub fn sign_message(&self, message: &[u8]) -> Result<String> {
        self.sign_message_with(message, Aux::random())
    }

    /// As [`Key::sign_message`], with the auxiliary randomness `aux` (the test seam of the
    /// feature `fixed-aux` passes fixed bytes).
    pub fn sign_message_with(&self, message: &[u8], aux: Aux) -> Result<String> {
        let MessageSignature {
            public_key,
            signature,
            algorithm,
            network,
        } = message::sign_bytes_with(&self.profile, self.account()?, message, aux)?;
        Ok(json!({
            "publicKey": public_key,
            "signature": signature,
            "algorithm": algorithm,
            "network": network,
        })
        .to_string())
    }

    /// Wipes the secret key. Every later call that needs the key fails with `KeyReleased`.
    pub fn release(&mut self) {
        // Dropping the account where it is overwrites the secret key's bytes.
        self.account = None;
    }

    /// The account, unless it was released.
    pub fn account(&self) -> Result<&Account> {
        self.account
            .as_ref()
            .ok_or_else(|| BindingError::from(iceroot_sdk::Error::KeyReleased))
    }

    fn import_legacy(profile: &Profile, passphrase: &str) -> Result<Key> {
        let account = Account::from_legacy_passphrase(profile, passphrase)?;
        Ok(Key {
            account: Some(account),
            profile: profile.clone(),
            legacy: true,
            path: None,
        })
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never shows key material.
        f.debug_struct("Key")
            .field("legacy", &self.legacy)
            .field("released", &self.account.is_none())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "03f83f83227e28add5598d2c75c20f72b4bfb0328957ef27e2da2ff73779fa4bd2";
    const ADDRESS: &str = "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF";
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn devnet() -> Profile {
        crate::chain::tests::devnet_profile()
    }

    #[test]
    fn legacy_passphrase() {
        let key = Key::from_legacy_passphrase(&devnet(), "probe passphrase".to_owned()).unwrap();
        assert!(key.legacy());
        assert_eq!(key.path(), None);
        assert_eq!(hex::encode(key.public_key().unwrap()), PUBLIC_KEY);
        assert_eq!(key.address().unwrap(), ADDRESS);

        let mut bytes = b"probe passphrase".to_vec();
        let from_bytes = Key::from_legacy_passphrase_bytes(&devnet(), &mut bytes).unwrap();
        assert_eq!(from_bytes.address().unwrap(), ADDRESS);
        assert!(bytes.iter().all(|&byte| byte == 0));

        let mut invalid = vec![0xff, 0xfe];
        let error = Key::from_legacy_passphrase_bytes(&devnet(), &mut invalid).unwrap_err();
        assert_eq!(error.code(), "InvalidPhrase");
        assert_eq!(invalid, [0, 0]);
    }

    #[test]
    fn phrases() {
        let first = Key::from_phrase(&devnet(), PHRASE.to_owned(), 0, 0, String::new()).unwrap();
        assert!(!first.legacy());
        assert_eq!(first.path().as_deref(), Some("m/44'/1'/0'/0'/0'"));
        let mut bytes = PHRASE.as_bytes().to_vec();
        let again = Key::from_phrase_bytes(&devnet(), &mut bytes, 0, 0, String::new()).unwrap();
        assert_eq!(again.address().unwrap(), first.address().unwrap());
        assert!(bytes.iter().all(|&byte| byte == 0));
        let second = Key::from_phrase(&devnet(), PHRASE.to_owned(), 0, 1, String::new()).unwrap();
        assert_ne!(second.address().unwrap(), first.address().unwrap());
        let with_passphrase =
            Key::from_phrase(&devnet(), PHRASE.to_owned(), 0, 0, "x".to_owned()).unwrap();
        assert_ne!(with_passphrase.address().unwrap(), first.address().unwrap());

        let short = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let error = Key::from_phrase(&devnet(), short.to_owned(), 0, 0, String::new()).unwrap_err();
        assert_eq!(error.code(), "PhraseTooShort");
        let error =
            Key::from_phrase(&devnet(), PHRASE.to_owned(), 1 << 31, 0, String::new()).unwrap_err();
        assert_eq!(error.code(), "InvalidPath");
    }

    #[test]
    fn keystores_open_to_the_phrase_s_accounts() {
        // The format's floor, so the test stays quick.
        let params = r#"{"memoryKib":19456,"iterations":2,"parallelism":1}"#;
        let mut phrase = PHRASE.as_bytes().to_vec();
        let mut password = b"correct horse".to_vec();
        let stored = crate::keystore::keystore_encrypt(&mut phrase, &mut password, params).unwrap();
        let direct = Key::from_phrase(&devnet(), PHRASE.to_owned(), 0, 3, "x".to_owned()).unwrap();

        let mut password = b"correct horse".to_vec();
        let opened = Key::from_keystore(
            &devnet(),
            &stored,
            &mut password,
            0,
            3,
            "x".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(opened.address().unwrap(), direct.address().unwrap());
        assert_eq!(opened.path().as_deref(), Some("m/44'/1'/0'/0'/3'"));
        assert!(password.iter().all(|&byte| byte == 0));

        let mut wrong = b"wrong horse".to_vec();
        let error = Key::from_keystore(&devnet(), &stored, &mut wrong, 0, 0, String::new(), None)
            .unwrap_err();
        assert_eq!(error.code(), "WrongPasswordOrCorrupt");
        assert!(wrong.iter().all(|&byte| byte == 0));
        let mut password = b"correct horse".to_vec();
        let error = Key::from_keystore(
            &devnet(),
            &stored,
            &mut password,
            1 << 31,
            0,
            String::new(),
            None,
        )
        .unwrap_err();
        assert_eq!(error.code(), "InvalidPath");
    }

    #[test]
    fn sign_and_release() {
        let mut key =
            Key::from_legacy_passphrase(&devnet(), "probe passphrase".to_owned()).unwrap();
        let message = b"IceRoot sign-in test";
        let signed: serde_json::Value =
            serde_json::from_str(&key.sign_message(message).unwrap()).unwrap();
        assert_eq!(signed["network"], "heartwood-devnet-v90");
        assert_eq!(signed["publicKey"], PUBLIC_KEY);
        assert!(crate::messages::verify_message(
            message,
            PUBLIC_KEY,
            signed["signature"].as_str().unwrap(),
            "secp256k1-bip340-sha256"
        ));
        // Bytes that are not text, such as a transaction's (header byte 0xff), are refused.
        let refused = key.sign_message(&[0xff, 0x03, 0x5a, 0x01]).unwrap_err();
        assert_eq!(refused.code(), "InvalidArgument");
        assert_eq!(
            refused.details(),
            &serde_json::json!({ "reason": "a message is signed only as UTF-8 text" })
        );

        key.release();
        assert!(key.released());
        assert_eq!(key.sign_message(message).unwrap_err().code(), "KeyReleased");
        assert_eq!(key.address().unwrap_err().code(), "KeyReleased");
    }

    #[cfg(feature = "fixed-aux")]
    #[test]
    fn fixed_aux_matches_the_probe() {
        let key = Key::from_legacy_passphrase(&devnet(), "probe passphrase".to_owned()).unwrap();
        let aux = crate::draft::fixed_aux(&[7; 32]).unwrap();
        let signed: serde_json::Value =
            serde_json::from_str(&key.sign_message_with(b"IceRoot sign-in test", aux).unwrap())
                .unwrap();
        let hex = signed["signature"].as_str().unwrap();
        assert!(hex.starts_with("a2ca2893"), "{hex}");
        assert!(hex.ends_with("aeba5518f"), "{hex}");
        assert_eq!(
            crate::draft::fixed_aux(&[7; 31]).unwrap_err().code(),
            "InvalidArgument"
        );
    }
}
