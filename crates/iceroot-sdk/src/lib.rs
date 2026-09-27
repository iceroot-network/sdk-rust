//! The IceRoot SDK for Rust: the one crate applications depend on.
//!
//! It re-exports the SDK's crates under one name:
//!
//! - the core ([`iceroot_sdk_core`], at the root of this crate): network profiles and
//!   capabilities, recovery phrases and keys, addresses, amounts, transaction drafts and signing,
//!   message signing and the sign-in message;
//! - the node API client ([`api`], the crate `iceroot_sdk_api`): a sans-IO client that builds each
//!   request and decodes each answer into IceRoot-shaped values, with an optional async HTTP
//!   transport (feature `http`, native targets only).
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use iceroot_sdk_core::*;

/// The node API client: request builders, typed answers and the backend mappers.
pub use iceroot_sdk_api as api;
