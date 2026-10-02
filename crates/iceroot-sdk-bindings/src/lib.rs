//! The boundary the IceRoot SDK's bindings share.
//!
//! The SDK's TypeScript interface has two implementations: the WebAssembly module of the
//! TypeScript package, and the native Tauri plugin (`tauri-plugin-iceroot`) behind the same
//! interface for desktop and mobile apps. Both hand the same calls to the SDK's Rust core, so the
//! code that reads their arguments and writes their answers lives here once: each function takes
//! the values the TypeScript wrapper passes (JSON text in the shape of the TypeScript API, bytes,
//! numbers) and returns the answer in the same shape, and each failure is a [`BindingError`] with
//! the core's stable code and structured details. A binding adds only what its host needs: the
//! WebAssembly module its exports and JavaScript values, the plugin its commands and the key
//! handles it keeps.
//!
//! Rules for the whole crate:
//!
//! - Secret keys stay in the binding: a host receives public keys, addresses and signatures only,
//!   and [`keys::Key::release`] and [`ownership::ProofKey::release`] wipe a key where it is held.
//!   Phrases and passwords given as bytes are overwritten with zeros whatever the outcome, and
//!   owned copies of secrets are wiped when a call ends.
//! - Untrusted input never causes a panic: every failure is a [`BindingError`].
//! - No I/O. Requests to a node are built and their answers decoded here ([`api`]); the host sends
//!   them (the TypeScript wrapper with `fetch`, the plugin with reqwest).
//! - Structured values cross as JSON text. Amounts and nonces are decimal strings, because
//!   JavaScript numbers cannot hold every `u64` or `u128`; the TypeScript wrappers make them
//!   `bigint`.
//!
//! The features `fixed-aux` and `keystore-testing` add the test seams of the bindings' test builds
//! (fixed signing randomness, the keystore vectors' salts and nonces); no build that ships enables
//! them.

pub mod address;
pub mod amount;
pub mod api;
pub mod chain;
pub mod draft;
pub mod error;
pub mod json;
pub mod keys;
pub mod keystore;
pub mod link;
pub mod messages;
pub mod ownership;
pub mod phrase;
pub mod profile;
pub mod signin;
pub mod vote;
mod write;

pub use crate::error::{BindingError, Result};
