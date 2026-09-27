//! Network profiles and their capabilities.
//!
//! A [`Profile`] binds the SDK to one chain: which backend talks to it, where its relays are, how
//! its keys are derived and how its chain is identified. The profile decides what the SDK may do
//! there, through its [`Capabilities`]: an operation a network lacks fails with
//! [`Error::UnsupportedOnNetwork`] naming the [`Capability`], and is never faked.
//!
//! Built-in profiles:
//!
//! - [`Profile::devnet`]: a devnet in today's formats, served by the backend of the reference
//!   implementation's formats and relay API.
//!   This is the profile the SDK fully supports now.
//! - [`Profile::devnet_pq`] and [`Profile::id_devnet`]: the IceRoot stages to come, declared so
//!   that applications can list and select them. Every capability is off until the SDK release
//!   that supports the stage, so any use fails with [`Error::UnsupportedOnNetwork`].
//!
//! The public testnet and mainnet have no profile yet: each gets its compiled-in chain identity in
//! the release made when its genesis is fixed, so no application can point at a guessed identity.

use std::fmt;

use crate::error::Error;
use crate::utils::is_lower_hex;

/// The backend that talks to a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// The backend compatible with the reference implementation: today's formats and its relay
    /// API.
    SolarCompatible,
    /// The IceRoot backend: the IceRoot formats, node API and indexer.
    IceRoot,
}

impl Backend {
    /// The stable string form: `solar-compat` or `iceroot`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Backend::SolarCompatible => "solar-compat",
            Backend::IceRoot => "iceroot",
        }
    }
}

/// The format stage of a chain, chosen by its milestones for the next block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// Today's formats: secp256k1 keys, BIP340 signatures and Base58Check addresses.
    S1,
    /// The post-quantum formats: ML-DSA-65 keys and signatures.
    Pq,
    /// The IceRoot formats from the fresh genesis: Bech32m addresses and 128-bit amounts.
    Id,
}

impl Stage {
    /// The stable string form: `s1`, `pq` or `id`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::S1 => "s1",
            Stage::Pq => "pq",
            Stage::Id => "id",
        }
    }
}

/// How new keys are derived from a recovery phrase. Both schemes are hardened-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyScheme {
    /// BIP39 seed, BIP32 master key and hardened secp256k1 steps at
    /// `m/44'/coin'/account'/0'/index'`.
    Bip32Secp256k1,
    /// BIP39 seed, a SLIP-0010-style master key for ML-DSA-65 and hardened steps at
    /// `m/44'/coin'/account'/0'/index'`.
    Slip10MlDsa65,
}

impl KeyScheme {
    /// The stable string form: `bip32-secp256k1` or `slip10-mldsa65`.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyScheme::Bip32Secp256k1 => "bip32-secp256k1",
            KeyScheme::Slip10MlDsa65 => "slip10-mldsa65",
        }
    }
}

/// The human-readable prefix of IceRoot Bech32m addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hrp {
    /// `ice`: mainnet only.
    Ice,
    /// `tice`: every other network, the public testnet and every devnet.
    Tice,
}

impl Hrp {
    /// The prefix text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Hrp::Ice => "ice",
            Hrp::Tice => "tice",
        }
    }
}

/// Something a network can do. Applications hide a feature when its capability is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    /// The SDK can load this network's configuration and build for it.
    Connect,
    /// Accounts from recovery phrases.
    PhraseAccounts,
    /// The legacy passphrase import (the reference's passphrase keys).
    LegacyPassphraseImport,
    /// Transfers to one or more recipients, with a memo.
    Transfer,
    /// Burns.
    Burn,
    /// Votes for validators.
    Vote,
    /// Validator registration.
    ValidatorRegistration,
    /// Validator resignation and its revoke.
    ValidatorResignation,
    /// A second key that co-signs every transaction.
    SecondKey,
    /// Key rotation.
    KeyRotation,
    /// Multisignature accounts.
    Multisig,
    /// Names for any account.
    Names,
    /// Validator names only.
    ValidatorNames,
    /// Declared reward sharing.
    ShareDeclare,
    /// Native assets.
    Assets,
    /// Swaps.
    Swaps,
    /// Hashed time-locked contracts.
    Htlc,
    /// Time-locked transfers.
    TimeLocks,
    /// Finality.
    Finality,
    /// History search.
    HistorySearch,
    /// Live updates.
    LiveEvents,
    /// A transaction id known before signing.
    TransactionIdBeforeSigning,
    /// Message signing.
    MessageSigning,
    /// Migration exits.
    MigrationExit,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Capability; 24] = [
        Capability::Connect,
        Capability::PhraseAccounts,
        Capability::LegacyPassphraseImport,
        Capability::Transfer,
        Capability::Burn,
        Capability::Vote,
        Capability::ValidatorRegistration,
        Capability::ValidatorResignation,
        Capability::SecondKey,
        Capability::KeyRotation,
        Capability::Multisig,
        Capability::Names,
        Capability::ValidatorNames,
        Capability::ShareDeclare,
        Capability::Assets,
        Capability::Swaps,
        Capability::Htlc,
        Capability::TimeLocks,
        Capability::Finality,
        Capability::HistorySearch,
        Capability::LiveEvents,
        Capability::TransactionIdBeforeSigning,
        Capability::MessageSigning,
        Capability::MigrationExit,
    ];

    /// The stable string form, for example `validator-registration`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Connect => "connect",
            Capability::PhraseAccounts => "phrase-accounts",
            Capability::LegacyPassphraseImport => "legacy-passphrase-import",
            Capability::Transfer => "transfer",
            Capability::Burn => "burn",
            Capability::Vote => "vote",
            Capability::ValidatorRegistration => "validator-registration",
            Capability::ValidatorResignation => "validator-resignation",
            Capability::SecondKey => "second-key",
            Capability::KeyRotation => "key-rotation",
            Capability::Multisig => "multisig",
            Capability::Names => "names",
            Capability::ValidatorNames => "validator-names",
            Capability::ShareDeclare => "share-declare",
            Capability::Assets => "assets",
            Capability::Swaps => "swaps",
            Capability::Htlc => "htlc",
            Capability::TimeLocks => "time-locks",
            Capability::Finality => "finality",
            Capability::HistorySearch => "history-search",
            Capability::LiveEvents => "live-events",
            Capability::TransactionIdBeforeSigning => "transaction-id-before-signing",
            Capability::MessageSigning => "message-signing",
            Capability::MigrationExit => "migration-exit",
        }
    }

    /// The capability with the string form `text`.
    pub fn parse(text: &str) -> Option<Capability> {
        Capability::ALL
            .into_iter()
            .find(|capability| capability.as_str() == text)
    }

    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities(u32);

impl Capabilities {
    /// No capability at all.
    pub const NONE: Capabilities = Capabilities(0);

    /// The set of `capabilities`.
    pub fn of(capabilities: &[Capability]) -> Capabilities {
        Capabilities(
            capabilities
                .iter()
                .fold(0, |bits, capability| bits | capability.bit()),
        )
    }

    /// Whether the set has `capability`.
    pub const fn has(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// The capabilities in the set, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |capability| self.has(*capability))
    }
}

/// What identifies a profile's chain. Unset fields are unknown until the first contact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ChainIdentity {
    /// The address network byte (today's and the post-quantum formats): 90 on devnets.
    pub network_byte: Option<u8>,
    /// The Bech32m prefix (IceRoot formats).
    pub hrp: Option<Hrp>,
    /// The network hash (today's and the post-quantum formats), pinned at the first contact on a
    /// devnet.
    pub nethash: Option<String>,
    /// The chain id (IceRoot formats).
    pub chain_id: Option<String>,
    /// The genesis hash (IceRoot formats).
    pub genesis_hash: Option<String>,
}

/// Where a profile's node API is served.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Endpoints {
    /// Relay base URLs, each including the API base path (for example `http://127.0.0.1:4003/api`).
    pub relays: Vec<String>,
    /// The indexer base URL (IceRoot formats).
    pub indexer: Option<String>,
}

/// Options of [`Profile::devnet`] and [`Profile::devnet_pq`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DevnetOptions {
    /// Relay base URLs, each including the API base path.
    pub relays: Vec<String>,
    /// The network hash pinned at an earlier contact, if any.
    pub nethash: Option<String>,
}

/// Options of [`Profile::id_devnet`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdDevnetOptions {
    /// Node API base URLs.
    pub relays: Vec<String>,
    /// The indexer base URL.
    pub indexer: Option<String>,
    /// The chain id pinned at an earlier contact, if any.
    pub chain_id: Option<String>,
    /// The genesis hash pinned at an earlier contact, if any.
    pub genesis_hash: Option<String>,
}

/// The network byte of every devnet in today's formats.
pub const DEVNET_NETWORK_BYTE: u8 = 90;

/// The SLIP-44 coin type of devnets and the public testnet: the shared test coin type.
pub const TEST_COIN_TYPE: u32 = 1;

/// A network profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Profile {
    id: String,
    backend: Backend,
    stage: Stage,
    endpoints: Endpoints,
    chain: ChainIdentity,
    key_scheme: KeyScheme,
    coin_type: u32,
    capabilities: Capabilities,
}

impl Profile {
    /// A devnet in today's formats (network byte 90), served by the backend compatible with the
    /// reference implementation.
    ///
    /// Devnets are generated again from time to time, so their network hash is not compiled in:
    /// the first contact pins it ([`crate::chain::Chain::load`]), and pass the pinned value back
    /// in `options.nethash` on later runs so that a different chain is refused.
    pub fn devnet(options: DevnetOptions) -> Profile {
        Profile {
            id: "devnet".to_owned(),
            backend: Backend::SolarCompatible,
            stage: Stage::S1,
            endpoints: Endpoints {
                relays: options.relays,
                indexer: None,
            },
            chain: ChainIdentity {
                network_byte: Some(DEVNET_NETWORK_BYTE),
                nethash: options.nethash.map(|hash| hash.to_ascii_lowercase()),
                ..ChainIdentity::default()
            },
            key_scheme: KeyScheme::Bip32Secp256k1,
            coin_type: TEST_COIN_TYPE,
            capabilities: Capabilities::of(&[
                Capability::Connect,
                Capability::PhraseAccounts,
                Capability::LegacyPassphraseImport,
                Capability::Transfer,
                Capability::Burn,
                Capability::Vote,
                Capability::ValidatorRegistration,
                Capability::ValidatorResignation,
                Capability::SecondKey,
                Capability::ValidatorNames,
                Capability::HistorySearch,
                Capability::LiveEvents,
                Capability::MessageSigning,
            ]),
        }
    }

    /// The same devnet chain after its post-quantum milestone. Declared only: every capability is
    /// off until the SDK release that supports the post-quantum formats.
    pub fn devnet_pq(options: DevnetOptions) -> Profile {
        Profile {
            id: "devnet-pq".to_owned(),
            backend: Backend::IceRoot,
            stage: Stage::Pq,
            key_scheme: KeyScheme::Slip10MlDsa65,
            capabilities: Capabilities::NONE,
            ..Profile::devnet(options)
        }
    }

    /// A fresh-genesis devnet in the IceRoot formats, with the `tice` prefix that every network but
    /// mainnet uses. Declared only: every capability is off until the SDK release that supports
    /// the IceRoot formats.
    pub fn id_devnet(options: IdDevnetOptions) -> Profile {
        Profile {
            id: "id-devnet".to_owned(),
            backend: Backend::IceRoot,
            stage: Stage::Id,
            endpoints: Endpoints {
                relays: options.relays,
                indexer: options.indexer,
            },
            chain: ChainIdentity {
                hrp: Some(Hrp::Tice),
                chain_id: options.chain_id,
                genesis_hash: options.genesis_hash,
                ..ChainIdentity::default()
            },
            key_scheme: KeyScheme::Slip10MlDsa65,
            coin_type: TEST_COIN_TYPE,
            capabilities: Capabilities::NONE,
        }
    }

    /// The same profile under another id, for custom development profiles. The id is carried in
    /// serialized drafts, so both sides must use the same one.
    pub fn with_id(mut self, id: &str) -> Profile {
        id.clone_into(&mut self.id);
        self
    }

    /// The same profile with the network hash `nethash` pinned (64 hex digits).
    pub fn with_nethash(mut self, nethash: &str) -> Result<Profile, Error> {
        if nethash.len() != 64 || !nethash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::BadResponse {
                reason: "a network hash is 64 hex digits".to_owned(),
            });
        }
        self.chain.nethash = Some(nethash.to_ascii_lowercase());
        Ok(self)
    }

    /// The profile id: `devnet`, `devnet-pq`, `id-devnet` or a custom id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The backend.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The format stage the profile starts at.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The node API endpoints.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// The chain identity, as far as it is known.
    pub fn chain(&self) -> &ChainIdentity {
        &self.chain
    }

    /// The key scheme of new accounts.
    pub fn key_scheme(&self) -> KeyScheme {
        self.key_scheme
    }

    /// The SLIP-44 coin type of new accounts (1 on devnets and the public testnet).
    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    /// The capabilities.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// `Ok` when the profile has `capability`, else [`Error::UnsupportedOnNetwork`].
    pub fn require(&self, capability: Capability) -> Result<(), Error> {
        if self.capabilities.has(capability) {
            Ok(())
        } else {
            Err(Error::UnsupportedOnNetwork {
                capability,
                profile: self.id.clone(),
            })
        }
    }

    /// The network byte of today's address format, for profiles that have one.
    pub(crate) fn network_byte(&self) -> Result<u8, Error> {
        match self.chain.network_byte {
            Some(byte) if self.capabilities.has(Capability::Connect) => Ok(byte),
            _ => Err(Error::UnsupportedOnNetwork {
                capability: Capability::Connect,
                profile: self.id.clone(),
            }),
        }
    }

    /// The network name that message signatures and sign-in messages carry, for example
    /// `heartwood-devnet-v90`.
    pub fn message_network(&self) -> Result<String, Error> {
        self.require(Capability::MessageSigning)?;
        Ok(format!("heartwood-devnet-v{}", self.network_byte()?))
    }

    /// Whether `nethash` is this profile's pinned network hash, or the profile has none pinned.
    pub(crate) fn accepts_nethash(&self, nethash: &str) -> bool {
        self.chain
            .nethash
            .as_deref()
            .is_none_or(|pinned| pinned.eq_ignore_ascii_case(nethash))
    }

    /// The same profile with `nethash` pinned; only called once the hash is known to be valid.
    pub(crate) fn pinned(&self, nethash: &str) -> Profile {
        let mut profile = self.clone();
        profile.chain.nethash = Some(nethash.to_ascii_lowercase());
        profile
    }

    /// Whether `text` is a network hash in the form the SDK pins: 64 lowercase hex digits.
    pub(crate) fn is_nethash(text: &str) -> bool {
        text.len() == 64 && is_lower_hex(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_capabilities() {
        let profile = Profile::devnet(DevnetOptions::default());
        assert_eq!(profile.id(), "devnet");
        assert_eq!(profile.backend().as_str(), "solar-compat");
        assert_eq!(profile.stage().as_str(), "s1");
        assert_eq!(profile.key_scheme().as_str(), "bip32-secp256k1");
        assert_eq!(profile.coin_type(), 1);
        assert_eq!(profile.chain().network_byte, Some(90));
        let caps = profile.capabilities();
        for capability in [
            Capability::Transfer,
            Capability::Vote,
            Capability::Burn,
            Capability::SecondKey,
            Capability::ValidatorNames,
            Capability::MessageSigning,
            Capability::LegacyPassphraseImport,
        ] {
            assert!(caps.has(capability), "{capability}");
        }
        for capability in [
            Capability::Names,
            Capability::Finality,
            Capability::KeyRotation,
            Capability::Multisig,
            Capability::Swaps,
            Capability::TransactionIdBeforeSigning,
        ] {
            assert!(!caps.has(capability), "{capability}");
        }
        assert_eq!(
            profile.message_network().unwrap(),
            "heartwood-devnet-v90".to_owned()
        );
    }

    #[test]
    fn declared_profiles_have_no_capability() {
        let pq = Profile::devnet_pq(DevnetOptions::default());
        let id = Profile::id_devnet(IdDevnetOptions::default());
        assert_eq!(pq.capabilities().iter().count(), 0);
        assert_eq!(id.capabilities().iter().count(), 0);
        assert_eq!(id.chain().hrp, Some(Hrp::Tice));
        assert_eq!(id.coin_type(), 1);
        let error = pq.require(Capability::Transfer).unwrap_err();
        assert_eq!(
            error,
            Error::UnsupportedOnNetwork {
                capability: Capability::Transfer,
                profile: "devnet-pq".into()
            }
        );
        assert!(id.network_byte().is_err());
        assert!(pq.message_network().is_err());
    }

    #[test]
    fn capability_names_round_trip() {
        for capability in Capability::ALL {
            assert_eq!(Capability::parse(capability.as_str()), Some(capability));
        }
        assert_eq!(Capability::parse("teleport"), None);
    }

    #[test]
    fn pinning() {
        let hash = "ab".repeat(32);
        let profile = Profile::devnet(DevnetOptions::default())
            .with_nethash(&hash.to_uppercase())
            .unwrap();
        assert_eq!(profile.chain().nethash.as_deref(), Some(hash.as_str()));
        assert!(profile.accepts_nethash(&hash));
        assert!(!profile.accepts_nethash(&"cd".repeat(32)));
        assert!(
            Profile::devnet(DevnetOptions::default())
                .with_nethash("12")
                .is_err()
        );
    }
}
