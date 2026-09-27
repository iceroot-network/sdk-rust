//! A prepared API call: the request to send and the decoder for its answer.

use std::fmt;

use crate::error::ApiError;
use crate::request::{Request, Response};

/// What a decoder may need besides the response: the account a history belongs to, the seat
/// count that separates active validators from standby ones, the page asked for, the ids of a
/// submission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Context {
    pub account: Option<String>,
    pub name: Option<String>,
    pub seats: u32,
    pub page: u32,
    pub ids: Vec<String>,
}

/// One API call, prepared but not sent.
///
/// The host sends [`request`](Call::request) with its HTTP stack, then passes the answer to
/// [`decode`](Call::decode). A call can be sent to any relay and decoded any number of times; it
/// holds no connection and no clock.
///
/// ```
/// use iceroot_sdk_api::{Relay, Response, SolarCompat};
///
/// let api = SolarCompat::new(53);
/// let call = api.node_status();
/// let relay = Relay::parse("http://127.0.0.1:4003/api")?;
/// assert_eq!(relay.url(call.request()), "http://127.0.0.1:4003/api/node/status");
///
/// // The host performs the request; here is an answer as the node sends it.
/// let answer = Response::new(200, r#"{"data":{"synced":true,"now":42,"blocksCount":0,"timestamp":330}}"#);
/// let status = call.decode(&answer)?;
/// assert_eq!(status.height, 42);
/// # Ok::<(), iceroot_sdk_api::ApiError>(())
/// ```
pub struct Call<T> {
    request: Request,
    context: Context,
    decode: fn(&Response, &Context) -> Result<T, ApiError>,
}

impl<T> Call<T> {
    pub(crate) fn new(
        request: Request,
        context: Context,
        decode: fn(&Response, &Context) -> Result<T, ApiError>,
    ) -> Self {
        Call {
            request,
            context,
            decode,
        }
    }

    /// The request to send.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Decodes the node's answer to [`request`](Call::request).
    ///
    /// # Errors
    ///
    /// [`ApiError::RateLimited`] for HTTP 429, [`ApiError::NotFound`] for a 404 where the call
    /// expects the resource to exist, [`ApiError::Refused`] for other error statuses and
    /// [`ApiError::BadResponse`] when the body does not have the documented shape.
    pub fn decode(&self, response: &Response) -> Result<T, ApiError> {
        (self.decode)(response, &self.context)
    }
}

impl<T> Clone for Call<T> {
    fn clone(&self) -> Self {
        Call {
            request: self.request.clone(),
            context: self.context.clone(),
            decode: self.decode,
        }
    }
}

impl<T> fmt::Debug for Call<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}
