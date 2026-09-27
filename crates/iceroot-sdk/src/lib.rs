//! The IceRoot SDK for Rust: the one crate applications depend on.
//!
//! It re-exports the SDK's crates under one name:
//!
//! - the core ([`iceroot_sdk_core`], at the root of this crate): network profiles and
//!   capabilities, recovery phrases and keys, addresses, amounts, transaction drafts and signing,
//!   message signing and the sign-in message, and ownership proofs of Solar addresses
//!   ([`ownership`]);
//! - the node API client ([`api`], the crate `iceroot_sdk_api`): a sans-IO client that builds each
//!   request and decodes each answer into IceRoot-shaped values, with an optional async HTTP
//!   transport (feature `http`, native targets only);
//! - the vote selection library ([`vote`], the crate `iceroot_vote`): the four vote modes that
//!   fill a vote for the holder to review, the network's vote rules and the check that reports
//!   picks that no longer meet their criteria, as pure functions; [`voting`] gives it the rules
//!   in force and a snapshot of a node's validator list;
//! - the keystore (`keystore`, the crate `iceroot_keystore`, feature `keystore`, on by
//!   default): a recovery phrase's entropy ([`Mnemonic::entropy`](phrase::Mnemonic::entropy))
//!   encrypted under a password with Argon2id and XChaCha20-Poly1305. A server that never holds
//!   a user's seed can turn the feature off (`default-features = false`) and build without those
//!   primitives.
//!
//! The core reads what the client decodes ([`node`]): [`Chain::from_node`] loads the chain a node
//! serves, [`OnlineFacts::from_node`] gives a draft its nonce, height and second key, and
//! [`SignedTransaction::to_submit`] prepares a signed transaction for submission.
//!
//! # Example
//!
//! Load a network's configuration, make an account from a recovery phrase, and build and sign a
//! transfer. A node supplies the configuration, the nonce and the height; here they are given.
//!
//! ```
//! use iceroot_sdk::amount::Amount;
//! use iceroot_sdk::fee::FeeChoice;
//! use iceroot_sdk::keys::{Account, AccountOptions};
//! use iceroot_sdk::phrase::Mnemonic;
//! use iceroot_sdk::profile::DevnetOptions;
//! use iceroot_sdk::transaction::{Draft, DraftRequest, OnlineFacts, Operation, Recipient};
//! use iceroot_sdk::{Chain, Profile};
//!
//! # fn main() -> Result<(), iceroot_sdk::Error> {
//! # let configuration = example_configuration();
//! // The node's `/node/configuration/crypto`: the network description and the milestones.
//! let profile = Profile::devnet(DevnetOptions::default());
//! let chain = Chain::load(&profile, &configuration)?;
//! // Keep chain.profile(): it has the network hash pinned from now on.
//!
//! let phrase = Mnemonic::generate()?;
//! let sender = Account::from_phrase(chain.profile(), &phrase, &AccountOptions::default())?;
//! let recipient = Account::from_phrase(
//!     chain.profile(),
//!     &phrase,
//!     &AccountOptions { index: 1, ..AccountOptions::default() },
//! )?;
//!
//! let request = DraftRequest {
//!     operation: Operation::Transfer {
//!         recipients: vec![Recipient {
//!             address: *recipient.address(),
//!             amount: Amount::parse("1.5", chain.token().decimals)?,
//!         }],
//!     },
//!     memo: Some("invoice 42".to_owned()),
//!     fee: FeeChoice::Exact(Amount::parse("0.01", chain.token().decimals)?),
//! };
//! let facts = OnlineFacts {
//!     sender: sender.public_key().clone(),
//!     nonce: 1,
//!     height: 2,
//!     second_key: None,
//! };
//! let draft = Draft::build(&chain, &request, &facts)?;
//! assert_eq!(draft.summary().total_amount, Amount::from_base_units(150_000_000));
//!
//! let signed = draft.sign(&sender, None)?;
//! assert!(signed.is_verified());
//! println!("{} {}", signed.id(), signed.json());
//! # Ok(())
//! # }
//! # fn example_configuration() -> String {
//! #     r#"{
//! #       "network": {
//! #         "name": "devnet", "messagePrefix": "devnet message:\n", "addressCharacter": "d",
//! #         "bip32": { "public": 70617039, "private": 70615956 }, "pubKeyHash": 90,
//! #         "nethash": "c9b03ab996ef3ac216a2ac53eaee71118cbf7995fa44449a7fb7f94bbe18bcca",
//! #         "wif": 252, "slip44": 1,
//! #         "client": { "token": "ROOT", "symbol": "ROOT", "explorer": "" }
//! #       },
//! #       "milestones": [{
//! #         "height": 1, "activeDelegates": 53, "blockTime": 8,
//! #         "block": { "version": 0, "maxTransactions": 150, "maxPayload": 2097152 },
//! #         "epoch": "2026-01-01T00:00:00.000Z", "reward": 0,
//! #         "burn": { "feeBasisPoints": 9000, "txAmount": 2000000 },
//! #         "transfer": { "maximum": 256, "minimum": 1 }
//! #       }]
//! #     }"#.to_owned()
//! # }
//! ```

//!
//! # Ownership proofs
//!
//! The holder of a Solar address proves control of it with a signed message that names the
//! IceRoot account its holding should be bound to. The functions need no network profile.
//!
//! ```
//! use iceroot_sdk::ownership::{self, IceRootAccount, OwnershipProof, ProofRequest, SolarKey};
//!
//! # fn main() -> Result<(), iceroot_sdk::Error> {
//! let now_ms = 1_788_264_000_000; // The caller's clock: 2026-09-01T12:00:00Z.
//! let key = SolarKey::from_passphrase("this is a top secret passphrase")?;
//! let account =
//!     IceRootAccount::parse("ice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r")?;
//! let message = ownership::build(&ProofRequest {
//!     address: key.address(),
//!     account: &account,
//!     nonce: &ownership::random_nonce()?,
//!     issued_at_ms: now_ms,
//! })?;
//! // The holder reads the whole message before it is signed.
//! let proof = ownership::sign(&key, &message, now_ms)?;
//!
//! // Whoever receives the proof as JSON checks it.
//! let received = OwnershipProof::from_json(&proof.to_json())?;
//! let fields = ownership::verify(&received, now_ms)?;
//! assert_eq!(fields.address, "SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC3");
//! assert_eq!(fields.account, account);
//! # Ok(())
//! # }
//! ```
//!
//! # Errors
//!
//! Every error of the SDK's crates has a stable code and structured details, which the
//! TypeScript and Go SDKs report the same way: the core's [`Error`] ([`Error::code`], one of
//! [`ErrorCode`], and [`Error::details`]), the vote library's [`vote::SelectError`],
//! [`vote::SnapshotError`] and [`vote::SplitError`], and the keystore's `keystore::Error` (each
//! with `code()` and `details()`). The codes form one set: a code two crates give has the
//! same meaning in both.
//!
//! | Crate | Codes |
//! |---|---|
//! | Core | The codes of [`ErrorCode`] |
//! | Vote library | `InvalidPickCount`, `ValidatorCannotVote`, `InvalidSnapshot`, `NotEnoughValidators`, `DoesNotFit`, `BreaksRules`; `InvalidVote` (the core's code) for a split that cannot be made |
//! | Keystore | `WrongPasswordOrCorrupt`, `Malformed`, `UnsupportedVersion`, `UnsupportedKdf`, `UnsupportedPayload`, `ParamsOutOfRange`, `InvalidPayload`, `InvalidPassword`, `OutOfMemory`; `RandomnessUnavailable` (the core's code) |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use iceroot_sdk_core::*;

/// The node API client: request builders, typed answers and the backend mappers.
pub use iceroot_sdk_api as api;

pub mod voting;

/// The vote selection library: the vote modes, the network's vote rules, and the check of an
/// earlier selection against newer data. It never recasts a vote; a selection is the holder's to
/// review and sign.
///
/// ```
/// use iceroot_sdk::vote::{Mode, SelectError, SelectRequest, VoteRules, select, split};
/// # use iceroot_sdk::vote::{SnapshotSource, VoteSnapshot};
/// # let snapshot = VoteSnapshot {
/// #     height: 1_000_000,
/// #     window_days: 30,
/// #     seats: 53,
/// #     block_time_seconds: 8,
/// #     source: SnapshotSource::RelayApproximate,
/// #     records: Vec::new(),
/// # };
///
/// // Manual voting: 10,000 basis points shared evenly, in the canonical order.
/// let entries = split(&["alpha", "beta", "gamma"])?;
/// assert_eq!(entries[0].basis_points, 3_334);
///
/// // A mode's selection, refused here with a stable code: the snapshot has no validators.
/// let request = SelectRequest {
///     rules: VoteRules::SOLAR_COMPATIBLE,
///     ..SelectRequest::new(Mode::Diversity, "holder")
/// };
/// let refused = select(&snapshot, &request).unwrap_err();
/// assert_eq!(refused.code(), "NotEnoughValidators");
/// assert!(matches!(refused, SelectError::NotEnoughValidators { available: 0, .. }));
/// # Ok::<(), iceroot_sdk::vote::SplitError>(())
/// ```
pub use iceroot_vote as vote;

/// The keystore (feature `keystore`, on by default): a recovery phrase's entropy encrypted under a
/// password. It stores nothing; the app keeps the bytes where its platform keeps secrets best.
///
/// ```
/// use iceroot_sdk::keystore::{self, Params, Payload};
/// use iceroot_sdk::phrase::Mnemonic;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let phrase = Mnemonic::generate()?;
/// let payload = Payload::bip39_entropy(phrase.entropy())?;
/// // An app passes its platform's preset, such as `Preset::Mobile`. This example uses the lowest
/// // parameters the format accepts, to run quickly.
/// let stored = keystore::encrypt(&payload, "correct horse", Params::new(19 * 1024, 2, 1))?;
///
/// let opened = keystore::decrypt(&stored, "correct horse")?;
/// let again = Mnemonic::from_entropy(opened.secret_bytes())?;
/// assert_eq!(again.phrase(), phrase.phrase());
/// let refused = keystore::decrypt(&stored, "wrong horse").unwrap_err();
/// assert_eq!(refused.code(), "WrongPasswordOrCorrupt");
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "keystore")]
pub use iceroot_keystore as keystore;
