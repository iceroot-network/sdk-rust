//! A prepared API call: the request to send and the decoder for its answer.

use std::fmt;

use crate::error::ApiError;
use crate::request::{MAX_RESPONSE_BYTES, Request, Response};

/// What a decoder may need besides the response: the account a history belongs to, the seat
/// count that separates active validators from standby ones, the page and page size asked for,
/// the ids of a submission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Context {
    pub account: Option<String>,
    pub name: Option<String>,
    pub seats: u32,
    pub page: u32,
    /// The page size asked for; a page with more items is refused.
    pub limit: u32,
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
    /// [`ApiError::BadResponse`] when the body does not have the documented shape or is longer
    /// than [`MAX_RESPONSE_BYTES`] (checked before it is parsed).
    pub fn decode(&self, response: &Response) -> Result<T, ApiError> {
        check_size(response)?;
        (self.decode)(response, &self.context)
    }
}

/// [`ApiError::BadResponse`] for a body longer than [`MAX_RESPONSE_BYTES`].
pub(crate) fn check_size(response: &Response) -> Result<(), ApiError> {
    let length = response.body().len();
    if length > MAX_RESPONSE_BYTES {
        return Err(ApiError::BadResponse {
            status: response.status(),
            detail: format!("the answer is {length} bytes; at most {MAX_RESPONSE_BYTES} are read"),
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use crate::solar_compat::SolarCompat;

    use super::*;

    #[test]
    fn a_body_longer_than_the_limit_is_refused_before_it_is_parsed() {
        let call = SolarCompat::new(53).node_status();
        let head = r#"{"data":{"synced":true,"now":42,"blocksCount":0,"timestamp":330},"pad":""#;
        let fits = format!(
            "{head}{}\"}}",
            "x".repeat(MAX_RESPONSE_BYTES - head.len() - 2)
        );
        assert_eq!(fits.len(), MAX_RESPONSE_BYTES);
        assert_eq!(call.decode(&Response::new(200, fits)).unwrap().height, 42);
        let long = format!(
            "{head}{}\"}}",
            "x".repeat(MAX_RESPONSE_BYTES - head.len() - 1)
        );
        let error = call.decode(&Response::new(200, long)).unwrap_err();
        assert_eq!(
            error,
            ApiError::BadResponse {
                status: 200,
                detail: format!(
                    "the answer is {} bytes; at most {MAX_RESPONSE_BYTES} are read",
                    MAX_RESPONSE_BYTES + 1
                ),
            }
        );
    }
}
