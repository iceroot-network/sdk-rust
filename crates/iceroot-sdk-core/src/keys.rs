//! Accounts: keys from recovery phrases, and the legacy passphrase import.
//!
//! An [`Account`] holds a secret key in memory that is wiped when the account is dropped or
//! [released](Account::release). Nothing in the SDK hands the secret key out: an account signs
//! drafts and messages, and shows its public key and address.
//!
//! New accounts come from a recovery phrase ([`Account::from_phrase`]) with the profile's key
//! scheme. On networks in today's formats that is hardened BIP32 secp256k1 derivation at
//! `m/44'/coin'/account'/0'/index'` (see [`crate::derivation`]).
//!
//! The legacy passphrase import ([`Account::from_legacy_passphrase`]) gives the reference
//! implementation's passphrase key, the SHA-256 of the passphrase's UTF-8 text, for the devnet
//! tooling's genesis and test wallets and for existing devnet identities. It exists only on
//! profiles in today's formats, and is an import: it never creates a new account.

use std::fmt;

use heartwood_crypto::identities::{KeyPair, PublicKey, SecretKey};

use crate::address::Address;
use crate::derivation::{self, DerivationPath};
use crate::error::Error;
use crate::phrase::Mnemonic;
use crate::profile::{Capability, KeyScheme, Profile};

/// The signature algorithm of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// secp256k1 keys with BIP340 Schnorr signatures.
    Secp256k1Bip340,
}

impl Algorithm {
    /// The stable string form: `secp256k1-bip340`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Algorithm::Secp256k1Bip340 => "secp256k1-bip340",
        }
    }
}

/// Where an account's key comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOrigin {
    /// Derived from a recovery phrase at this path.
    Phrase(DerivationPath),
    /// The legacy passphrase import.
    LegacyPassphrase,
}

/// Options of [`Account::from_phrase`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountOptions<'a> {
    /// The account number (below 2^31).
    pub account: u32,
    /// The address index within the account (below 2^31).
    pub index: u32,
    /// The optional BIP39 passphrase; empty for none. A different passphrase gives different
    /// keys from the same phrase.
    pub passphrase: &'a str,
}

impl fmt::Debug for AccountOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountOptions")
            .field("account", &self.account)
            .field("index", &self.index)
            .field(
                "passphrase",
                &if self.passphrase.is_empty() { "" } else { ".." },
            )
            .finish()
    }
}

/// An account with its key.
pub struct Account {
    keys: KeyPair,
    address: Address,
    origin: KeyOrigin,
    profile: String,
}

impl Account {
    /// The account at `options.account` and `options.index` of `phrase`, with the key scheme of
    /// `profile`.
    pub fn from_phrase(
        profile: &Profile,
        phrase: &Mnemonic,
        options: &AccountOptions<'_>,
    ) -> Result<Account, Error> {
        profile.require(Capability::PhraseAccounts)?;
        match profile.key_scheme() {
            KeyScheme::Bip32Secp256k1 => {}
            KeyScheme::Slip10MlDsa65 => {
                return Err(Error::UnsupportedOnNetwork {
                    capability: Capability::PhraseAccounts,
                    profile: profile.id().to_owned(),
                });
            }
        }
        let path = DerivationPath::new(profile.coin_type(), options.account, options.index)?;
        let seed = phrase.seed(options.passphrase)?;
        let secret = derivation::derive(seed.as_bytes(), &path.steps())?;
        Account::new(profile, secret, KeyOrigin::Phrase(path))
    }

    /// The reference implementation's passphrase key for `passphrase`: the SHA-256 of its UTF-8
    /// text. Any text is accepted. Only on profiles in today's formats; an import, never a way to
    /// create an account.
    pub fn from_legacy_passphrase(profile: &Profile, passphrase: &str) -> Result<Account, Error> {
        profile.require(Capability::LegacyPassphraseImport)?;
        let secret = SecretKey::from_passphrase(passphrase).map_err(|_| Error::SigningFailed {
            reason: "the passphrase gives no valid key".to_owned(),
        })?;
        Account::new(profile, secret, KeyOrigin::LegacyPassphrase)
    }

    fn new(profile: &Profile, secret: SecretKey, origin: KeyOrigin) -> Result<Account, Error> {
        let keys = KeyPair::from_secret_key(secret);
        let address = Address::from_public_key(keys.public_key(), profile)?;
        Ok(Account {
            keys,
            address,
            origin,
            profile: profile.id().to_owned(),
        })
    }

    /// The account's address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The account's public key (33 bytes, compressed).
    pub fn public_key(&self) -> &PublicKey {
        self.keys.public_key()
    }

    /// The signature algorithm.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256k1Bip340
    }

    /// Where the key comes from.
    pub fn origin(&self) -> KeyOrigin {
        self.origin
    }

    /// Whether the key is a legacy passphrase import.
    pub fn is_legacy(&self) -> bool {
        self.origin == KeyOrigin::LegacyPassphrase
    }

    /// The id of the profile the account was made for.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Wipe the key. Dropping the account does the same; this names the moment.
    pub fn release(self) {
        drop(self);
    }

    /// The key pair, for signing inside the SDK.
    pub(crate) fn keys(&self) -> &KeyPair {
        &self.keys
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("address", &self.address.to_string())
            .field("origin", &self.origin)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{DevnetOptions, IdDevnetOptions};

    fn devnet() -> Profile {
        Profile::devnet(DevnetOptions::default())
    }

    #[test]
    fn legacy_passphrase() {
        let account =
            Account::from_legacy_passphrase(&devnet(), "this is a top secret passphrase").unwrap();
        assert_eq!(
            account.public_key().to_hex(),
            "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"
        );
        assert_eq!(
            account.address().to_string(),
            "dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt"
        );
        assert!(account.is_legacy());
        assert!(!format!("{account:?}").contains("secret"));
        let declared = Profile::devnet_pq(DevnetOptions::default());
        assert!(matches!(
            Account::from_legacy_passphrase(&declared, "x"),
            Err(Error::UnsupportedOnNetwork { .. })
        ));
    }

    #[test]
    fn phrase_accounts_differ_by_index_and_passphrase() {
        let phrase = Mnemonic::from_entropy(&[0x42; 32]).unwrap();
        let options = |index, passphrase| AccountOptions {
            account: 0,
            index,
            passphrase,
        };
        let first = Account::from_phrase(&devnet(), &phrase, &options(0, "")).unwrap();
        let second = Account::from_phrase(&devnet(), &phrase, &options(1, "")).unwrap();
        let other = Account::from_phrase(&devnet(), &phrase, &options(0, "x")).unwrap();
        assert_ne!(first.address(), second.address());
        assert_ne!(first.address(), other.address());
        assert_eq!(
            first.origin(),
            KeyOrigin::Phrase(DerivationPath::new(1, 0, 0).unwrap())
        );
        let again = Account::from_phrase(&devnet(), &phrase, &options(0, "")).unwrap();
        assert_eq!(again.public_key(), first.public_key());
        assert!(matches!(
            Account::from_phrase(&devnet(), &phrase, &options(1 << 31, "")),
            Err(Error::InvalidPath { .. })
        ));
        let id = Profile::id_devnet(IdDevnetOptions::default());
        assert!(matches!(
            Account::from_phrase(&id, &phrase, &options(0, "")),
            Err(Error::UnsupportedOnNetwork { .. })
        ));
    }
}
