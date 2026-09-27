//! `iceroot-sdk-core`: the core of the IceRoot SDK.
//!
//! Everything an application needs to hold keys and make transactions for an IceRoot network,
//! without any input or output: the node API client builds on it, and so do the WebAssembly and
//! native bindings.
//!
//! - [`profile`]: network profiles, backends, format stages and capabilities.
//! - [`chain`]: a network's loaded configuration, checked against its profile.
//! - [`rules`] and [`economics`]: what the milestone in force allows, and its rewards, donations
//!   and fee burn.
//! - [`phrase`] and [`derivation`]: BIP39 recovery phrases and hardened BIP32 derivation.
//! - [`keys`]: accounts from phrases, and the legacy passphrase import.
//! - [`address`] and [`amount`]: addresses checked against a network, and exact amounts.
//! - [`fee`]: fee choices and their resolution.
//! - [`transaction`]: operations, drafts, signing, serialized drafts and signed transactions.
//! - [`message`] and [`signin`]: message signatures and the sign-in message.
//! - [`node`]: what the node API client (`iceroot-sdk-api`) decodes, read into the core's inputs
//!   and checked on the way: the chain, a draft's online facts, submissions and errors.
//! - [`error`]: the one error type, with stable codes.
//!
//! The values both this crate and the node API client use (asset ids, vote entries, supply
//! figures and rejection reasons) are the client's own types, re-exported here.
//!
//! Every byte and verdict of a transaction, key, address or signature comes from
//! `heartwood-crypto`, Heartwood Core's byte-exact layer; this crate adds only client code.
//!
//! Rules for the whole crate: no unsafe code, no panics on untrusted input, no I/O and no clock
//! (the caller passes the time), no floating point in amounts, and no secret in any `Debug` output
//! or error.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod address;
pub mod amount;
pub mod chain;
pub mod derivation;
pub mod economics;
pub mod error;
pub mod fee;
pub mod keys;
pub mod message;
pub mod node;
pub mod phrase;
pub mod profile;
pub mod rules;
pub mod signin;
pub mod transaction;

mod time;
mod utils;

pub use crate::address::Address;
pub use crate::amount::{Amount, AssetId};
pub use crate::chain::{Chain, Token};
pub use crate::economics::Economics;
pub use crate::error::{Error, ErrorCode};
pub use crate::fee::FeeChoice;
pub use crate::keys::{Account, AccountOptions};
pub use crate::phrase::Mnemonic;
pub use crate::profile::{Capability, Profile, Stage};
pub use crate::rules::Rules;
pub use crate::transaction::{
    Draft, DraftRequest, OnlineFacts, Operation, OperationKind, SignedTransaction,
};

/// The auxiliary randomness of a signature. Outside tests only [`Aux::random`] exists.
pub use heartwood_crypto::Aux;
/// A public key, as `heartwood-crypto` parses it.
pub use heartwood_crypto::PublicKey;
/// The 33 bytes of a compressed public key, not checked to be a valid key.
pub use heartwood_crypto::PublicKeyBytes;
