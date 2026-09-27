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
mod solar_compat;
pub mod types;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod http;

pub use call::Call;
pub use error::ApiError;
pub use limits::{Backoff, RateLimit, RequestBudget};
pub use request::{Method, Relay, Request, Response};
pub use solar_compat::{MAX_PAGE_LIMIT, PageRequest, SolarCompat, SubmitPlan, SubmitTx, TxFilter};
pub use types::*;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use http::{HttpClient, HttpOptions};
