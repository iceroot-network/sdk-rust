//! A sans-IO client for IceRoot node APIs.
//!
//! The crate builds each request and decodes each answer; the host performs the HTTP exchange
//! with whatever it has (`fetch` in a browser or webview, reqwest natively, `net/http` in Go). One
//! mapping from the node's resources to the SDK's IceRoot-shaped types therefore serves every
//! language the SDK is built for.
//!
//! - [`types`]: accounts, validators, transactions, blocks and node facts in IceRoot's terms.
//! - [`SolarCompat`]: the backend for the reference implementation's REST API, which today's
//!   devnet serves. It prepares one [`Call`] per operation.
//! - [`Relay`], [`Request`], [`Response`]: the values exchanged with the host's transport.
//! - [`RateLimit`], [`RequestBudget`], [`Backoff`]: keeping to the node's request allowance.
//! - `HttpClient` (feature `http`, native targets only): an async reqwest transport that sends
//!   calls to a list of relays.
//!
//! # Feature `serde`
//!
//! With the feature `serde`, the request values ([`Request`], [`Response`], [`Relay`],
//! [`PageRequest`], [`TxFilter`], [`BlockRef`], [`HistoryDirection`], [`SubmitTx`]) and every
//! answer in [`types`] implement `Serialize` and `Deserialize`. The client stays sans-IO: the
//! feature adds no I/O and no dependency, only the JSON form that the SDK's bindings exchange
//! (WebAssembly for TypeScript today). The form is the same for every language:
//!
//! - Field names are in camel case (`senderPublicKey`); enum values are lower-case words joined by
//!   hyphens (`resigned-temporary`, `low-fee`).
//! - Integers of 64 bits and more (amounts, nonces, heights, times, lifetime counters) are decimal
//!   strings, which JavaScript numbers could not hold exactly; smaller integers (ranks, basis
//!   points, page numbers, sizes, wire types) are numbers. On input a wide integer may also be a
//!   number.
//! - An absent optional value is left out; on input `null` means absent too.
//! - An asset id is `ROOT` or 64 hex digits.
//! - A transaction kind is a `kind` field (`transfer`, `vote`, `burn`, `register-second-key`,
//!   `register-validator`, `resign-validator` or `other`), with `typeGroup` and `typeId` beside it
//!   for `other`. [`TxDetails`] are tagged by `kind` the same way, and a [`SubmitOutcome`] by
//!   `status` (`accepted` or `rejected`), next to the transaction's `id`.
//!
#![cfg_attr(feature = "serde", doc = "```")]
#![cfg_attr(not(feature = "serde"), doc = "```ignore")]
//! use iceroot_sdk_api::{Response, SolarCompat};
//!
//! let call = SolarCompat::new(53).account("dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn")?;
//! let answer = Response::new(
//!     200,
//!     r#"{"data":{"address":"dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn","balance":"250000000","nonce":"3",
//!        "attributes":{},"votingFor":{"genesis_7":{"percent":100,"votes":"250000000"}}}}"#,
//! );
//! let account = call.decode(&answer)?;
//! let json = serde_json::to_value(&account).expect("an account serializes");
//! assert_eq!(
//!     json,
//!     serde_json::json!({
//!         "address": "dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn",
//!         "nonce": "3",
//!         "balances": [{ "asset": "ROOT", "amount": "250000000" }],
//!         "vote": [{ "validator": "genesis_7", "basisPoints": 10000 }]
//!     })
//! );
//! # Ok::<(), iceroot_sdk_api::ApiError>(())
//! ```
//!
//! ```
//! use iceroot_sdk_api::{AssetId, Relay, Response, SolarCompat};
//!
//! let api = SolarCompat::new(53);
//! let relay = Relay::parse("http://127.0.0.1:4003/api")?;
//! let call = api.account("dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn")?;
//! let url = relay.url(call.request());
//! assert_eq!(url, "http://127.0.0.1:4003/api/wallets/dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn");
//!
//! // Whatever performs the request hands back the status and body.
//! let answer = Response::new(
//!     200,
//!     r#"{"data":{"address":"dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn","balance":"250000000","nonce":"3",
//!        "attributes":{},"votingFor":{"genesis_7":{"percent":100,"votes":"250000000"}}}}"#,
//! );
//! let account = call.decode(&answer)?;
//! assert_eq!(account.balance(AssetId::ROOT), 250_000_000);
//! assert_eq!(account.vote[0].validator, "genesis_7");
//! assert_eq!(account.vote[0].basis_points, 10_000);
//! # Ok::<(), iceroot_sdk_api::ApiError>(())
//! ```

#![forbid(unsafe_code)]

mod call;
mod error;
mod limits;
mod request;
#[cfg(feature = "serde")]
mod serde_repr;
mod solar_compat;
pub mod types;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod http;

pub use call::Call;
pub use error::ApiError;
pub use limits::{Backoff, RateLimit, RequestBudget};
pub use request::{MAX_RESPONSE_BYTES, Method, Relay, Request, Response};
pub use solar_compat::{MAX_PAGE_LIMIT, PageRequest, SolarCompat, SubmitPlan, SubmitTx, TxFilter};
pub use types::*;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use http::{HttpClient, HttpOptions};
