//! Typed errors of the node API client.

use std::time::Duration;

/// The most characters of a node's own text, such as an error message or code, that the client
/// keeps. Longer text is cut and ends with `…`.
pub const MAX_NODE_TEXT_CHARS: usize = 200;

/// The most characters of a decoder's explanation of an answer it refuses.
const MAX_DETAIL_CHARS: usize = 300;

/// An error from building a request, from the node's answer, or (with the `http` feature) from the
/// transport.
///
/// Every variant has a stable [`code`](ApiError::code) that the SDK's error model keeps.
///
/// Text a node chose (the message and name of an error status, the value a decoder refuses) is
/// kept to [`MAX_NODE_TEXT_CHARS`] characters (a decoder's explanation to 300), with control
/// characters and characters that hide or reorder text written as escapes such as `\u{202e}`,
/// and a node's own message is never part of the `Display` text: an application that shows an
/// error's message shows no text a node wrote.
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
    #[error("not found")]
    NotFound {
        /// The node's message, bounded and escaped.
        message: String,
    },

    /// The node refused the request with a client or server error status other than 404 and 429,
    /// for example 422 for an argument it considers invalid.
    #[error("node refused the request with HTTP {status}")]
    Refused {
        /// HTTP status code.
        status: u16,
        /// The node's error name (for example `Unprocessable Entity`), empty when absent; bounded
        /// and escaped.
        error: String,
        /// The node's message, empty when absent; bounded and escaped.
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
            detail: bounded(&detail.into(), MAX_DETAIL_CHARS),
        }
    }

    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        ApiError::InvalidRequest {
            reason: reason.into(),
        }
    }
}

/// Text a node chose, as the client keeps it: at most [`MAX_NODE_TEXT_CHARS`] characters,
/// escaped as [`ApiError`] describes.
pub(crate) fn node_text(text: &str) -> String {
    bounded(text, MAX_NODE_TEXT_CHARS)
}

/// `text` with control characters and characters that hide or reorder text written as escapes
/// (`\u{202e}`), cut to at most `max` characters, the escapes included, and then ending with `…`.
fn bounded(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max.saturating_mul(4)));
    let mut count = 0usize;
    for c in text.chars() {
        let escaped = c.is_control() || hides_or_reorders(c);
        let width = if escaped {
            c.escape_unicode().count()
        } else {
            1
        };
        if count.saturating_add(width) > max {
            out.push('…');
            break;
        }
        count += width;
        if escaped {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether `c` is invisible or changes the order text is shown in: the Unicode bidirectional
/// controls, zero-width characters and the line and paragraph separators.
fn hides_or_reorders(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_text_is_bounded_and_escaped() {
        assert_eq!(node_text("plain text"), "plain text");
        assert_eq!(node_text("a\u{202e}b\nc"), "a\\u{202e}b\\u{a}c");
        let long = node_text(&"é".repeat(500));
        assert_eq!(long.chars().count(), MAX_NODE_TEXT_CHARS + 1);
        assert!(long.ends_with('…'));
        assert_eq!(node_text(""), "");
    }

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
        // The node's own text is not shown.
        assert_eq!(
            refused.to_string(),
            "node refused the request with HTTP 422"
        );
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
