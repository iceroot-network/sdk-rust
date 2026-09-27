//! Typed errors of the node API client.

use std::time::Duration;

/// An error from building a request, from the node's answer, or (with the `http` feature) from the
/// transport.
///
/// Every variant has a stable [`code`](ApiError::code) that the SDK's error model keeps.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// The request could not be built: an invalid relay URL, a page out of range, an empty
    /// submission or an argument the route does not accept.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// What was wrong.
        reason: String,
    },

    /// The node refused the request because this client exceeded its request budget (HTTP 429).
    #[error("rate limited by the node{}", retry_hint(*.retry_after))]
    RateLimited {
        /// How long the node asked the client to wait, when it said so (`Retry-After`).
        retry_after: Option<Duration>,
    },

    /// The resource does not exist on the node (HTTP 404 where the call expects it to exist).
    #[error("not found: {message}")]
    NotFound {
        /// The node's message.
        message: String,
    },

    /// The node refused the request with a client or server error status other than 404 and 429,
    /// for example 422 for an argument it considers invalid.
    #[error("node refused the request with HTTP {status}: {message}")]
    Refused {
        /// HTTP status code.
        status: u16,
        /// The node's error name (for example `Unprocessable Entity`), empty when absent.
        error: String,
        /// The node's message, empty when absent.
        message: String,
    },

    /// The node's answer does not have the documented shape: not JSON, a missing or mistyped field,
    /// a number out of range, or an unexpected status.
    #[error("bad response (HTTP {status}): {detail}")]
    BadResponse {
        /// HTTP status code of the answer.
        status: u16,
        /// What did not match.
        detail: String,
    },

    /// No relay could be reached (connection refused, DNS failure, TLS failure, a 5xx answer from
    /// every relay).
    #[error("node unavailable: {detail}")]
    NodeUnavailable {
        /// The last transport error.
        detail: String,
    },

    /// The request did not complete in time.
    #[error("request timed out")]
    Timeout,
}

fn retry_hint(retry_after: Option<Duration>) -> String {
    match retry_after {
        Some(wait) => format!(" (retry after {} ms)", wait.as_millis()),
        None => String::new(),
    }
}

impl ApiError {
    /// The stable error code: `InvalidRequest`, `RateLimited`, `NotFound`, `Refused`,
    /// `BadResponse`, `NodeUnavailable` or `Timeout`.
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::InvalidRequest { .. } => "InvalidRequest",
            ApiError::RateLimited { .. } => "RateLimited",
            ApiError::NotFound { .. } => "NotFound",
            ApiError::Refused { .. } => "Refused",
            ApiError::BadResponse { .. } => "BadResponse",
            ApiError::NodeUnavailable { .. } => "NodeUnavailable",
            ApiError::Timeout => "Timeout",
        }
    }

    /// Whether another relay, or the same one later, may answer: rate limits, unavailable nodes,
    /// timeouts and server errors.
    pub fn is_retryable(&self) -> bool {
        match self {
            ApiError::RateLimited { .. } | ApiError::NodeUnavailable { .. } | ApiError::Timeout => {
                true
            }
            ApiError::Refused { status, .. } => *status >= 500,
            _ => false,
        }
    }

    pub(crate) fn bad(status: u16, detail: impl Into<String>) -> Self {
        ApiError::BadResponse {
            status,
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        ApiError::InvalidRequest {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_retry() {
        let limited = ApiError::RateLimited {
            retry_after: Some(Duration::from_millis(1500)),
        };
        assert_eq!(limited.code(), "RateLimited");
        assert!(limited.is_retryable());
        assert_eq!(
            limited.to_string(),
            "rate limited by the node (retry after 1500 ms)"
        );
        let refused = ApiError::Refused {
            status: 422,
            error: "Unprocessable Entity".into(),
            message: "Wallet not valid".into(),
        };
        assert!(!refused.is_retryable());
        assert_eq!(refused.code(), "Refused");
        assert!(
            ApiError::Refused {
                status: 503,
                error: String::new(),
                message: String::new()
            }
            .is_retryable()
        );
        assert_eq!(ApiError::Timeout.code(), "Timeout");
    }
}
