//! Plain request and response values exchanged with the host's HTTP transport.
//!
//! The client never performs I/O itself. A [`Request`] carries a method, a path relative to the
//! relay URL, query parameters and an optional JSON body; the host sends it with whatever HTTP stack
//! it has and hands the status, headers and body back as a [`Response`].

use std::fmt;

use crate::error::ApiError;

/// HTTP method of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "UPPERCASE")
)]
pub enum Method {
    /// `GET`, for every read.
    Get,
    /// `POST`, for transaction submission.
    Post,
}

impl Method {
    /// The method name as it appears on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The base URL of one node API, including its base path (for example `http://127.0.0.1:4003/api`).
///
/// The API base path is part of the node's configuration (`/api` by default), so the client never
/// guesses it: route paths are appended to the relay URL exactly as given.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Relay {
    base: String,
}

impl Relay {
    /// Parses a relay URL.
    ///
    /// The URL must use `http` or `https`, name a host, and carry no query string, fragment,
    /// credentials or whitespace. Trailing slashes are removed.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] when the URL does not meet these rules.
    pub fn parse(url: &str) -> Result<Self, ApiError> {
        let invalid = |reason: &str| ApiError::InvalidRequest {
            reason: format!("relay URL {url:?}: {reason}"),
        };
        let rest = if let Some(rest) = url.strip_prefix("http://") {
            rest
        } else if let Some(rest) = url.strip_prefix("https://") {
            rest
        } else {
            return Err(invalid("must start with http:// or https://"));
        };
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid("contains whitespace or control characters"));
        }
        if url.contains('?') || url.contains('#') {
            return Err(invalid("must not carry a query string or fragment"));
        }
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(invalid("has no host"));
        }
        if authority.contains('@') {
            return Err(invalid("must not carry credentials"));
        }
        Ok(Relay {
            base: url.trim_end_matches('/').to_owned(),
        })
    }

    /// The relay URL without a trailing slash.
    pub fn as_str(&self) -> &str {
        &self.base
    }

    /// The full URL of `request` on this relay: base URL, route path and encoded query string.
    pub fn url(&self, request: &Request) -> String {
        let mut url = String::with_capacity(self.base.len() + request.path.len() + 32);
        url.push_str(&self.base);
        url.push_str(&request.path);
        let mut separator = '?';
        for (name, value) in &request.query {
            url.push(separator);
            separator = '&';
            encode_component(name, &mut url);
            url.push('=');
            encode_component(value, &mut url);
        }
        url
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base)
    }
}

/// One HTTP request, relative to a [`Relay`].
///
/// With the feature `serde` it is `{ method, path, query: [[name, value]], body? }`, the query
/// not yet encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "RequestFields")
)]
pub struct Request {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    body: Option<String>,
}

/// The fields of a [`Request`] before they are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct RequestFields {
    method: Method,
    path: String,
    #[serde(default)]
    query: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<RequestFields> for Request {
    type Error = ApiError;

    /// A request whose path starts with `/` and carries no query string, fragment, white space
    /// or control character.
    fn try_from(fields: RequestFields) -> Result<Request, ApiError> {
        let path_ok = fields.path.starts_with('/')
            && !fields
                .path
                .chars()
                .any(|c| c == '?' || c == '#' || c.is_whitespace() || c.is_control());
        if !path_ok {
            return Err(ApiError::InvalidRequest {
                reason: format!("{:?} is not a route path", fields.path),
            });
        }
        Ok(Request {
            method: fields.method,
            path: fields.path,
            query: fields.query,
            body: fields.body,
        })
    }
}

impl Request {
    /// A `GET` of `path`, where `path` starts with `/` and its dynamic segments are already encoded.
    pub(crate) fn get(path: String) -> Self {
        Request {
            method: Method::Get,
            path,
            query: Vec::new(),
            body: None,
        }
    }

    /// A `POST` of a JSON body to `path`.
    pub(crate) fn post_json(path: String, body: String) -> Self {
        Request {
            method: Method::Post,
            path,
            query: Vec::new(),
            body: Some(body),
        }
    }

    /// Adds one query parameter (encoded when the URL is built).
    pub(crate) fn with_query(mut self, name: &str, value: impl ToString) -> Self {
        self.query.push((name.to_owned(), value.to_string()));
        self
    }

    /// The HTTP method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The route path relative to the relay URL, with dynamic segments percent-encoded.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query parameters in order, not yet encoded.
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// The JSON body of a `POST`, if any. Sent with `Content-Type: application/json`.
    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }

    /// The headers the request needs besides the host's own: `Accept` always, and
    /// `Content-Type` when there is a body.
    pub fn headers(&self) -> Vec<(&'static str, &'static str)> {
        let mut headers = vec![("Accept", "application/json")];
        if self.body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        headers
    }

    /// The path and encoded query string, as used for relative links (for example `/blocks?page=2`).
    pub fn path_and_query(&self) -> String {
        let mut out = self.path.clone();
        let mut separator = '?';
        for (name, value) in &self.query {
            out.push(separator);
            separator = '&';
            encode_component(name, &mut out);
            out.push('=');
            encode_component(value, &mut out);
        }
        out
    }
}

/// An HTTP response as the host's transport received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// A response with a status code and body and no headers.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a response header. Only `Retry-After` and `X-Block-Height` are read.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The headers, in the order they were added.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The first header with this name, compared without regard to ASCII case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The node's chain height when it answered, from the reference implementation's
    /// `X-Block-Height` header, if present and well formed.
    pub fn block_height(&self) -> Option<u64> {
        self.header("X-Block-Height")?.trim().parse().ok()
    }
}

/// Percent-encodes one path segment or query component: everything except the RFC 3986 unreserved
/// characters is encoded.
pub(crate) fn encode_component(value: &str, out: &mut String) {
    fn hex(nibble: u8) -> char {
        char::from_digit(u32::from(nibble & 0x0f), 16)
            .unwrap_or('0')
            .to_ascii_uppercase()
    }
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex(byte >> 4));
            out.push(hex(byte));
        }
    }
}

/// Encodes one dynamic path segment. Values that would change the route (`.` and `..`) are refused.
pub(crate) fn segment(value: &str) -> Result<String, ApiError> {
    if value.is_empty() || value == "." || value == ".." {
        return Err(ApiError::InvalidRequest {
            reason: format!("{value:?} is not a valid path segment"),
        });
    }
    let mut out = String::with_capacity(value.len());
    encode_component(value, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_rules() {
        assert_eq!(
            Relay::parse("http://127.0.0.1:4003/api/").unwrap().as_str(),
            "http://127.0.0.1:4003/api"
        );
        assert!(Relay::parse("https://node.example/api").is_ok());
        for bad in [
            "ftp://x/api",
            "http:///api",
            "http://x/api?x=1",
            "http://x/api#f",
            "http://u:p@x/api",
            "http://x /api",
            "127.0.0.1:4003/api",
        ] {
            assert!(Relay::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn url_encoding() {
        let relay = Relay::parse("http://h:1/api").unwrap();
        let request = Request::get(format!("/delegates/{}", segment("a b/c").unwrap()))
            .with_query("page", 2)
            .with_query("q", "x&y=z");
        assert_eq!(
            relay.url(&request),
            "http://h:1/api/delegates/a%20b%2Fc?page=2&q=x%26y%3Dz"
        );
        assert_eq!(
            request.path_and_query(),
            "/delegates/a%20b%2Fc?page=2&q=x%26y%3Dz"
        );
        assert!(segment("..").is_err());
        assert!(segment("").is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn requests_as_json() {
        let request = Request::get("/wallets/dA".into()).with_query("page", 2);
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "method": "GET", "path": "/wallets/dA", "query": [["page", "2"]] })
        );
        assert_eq!(serde_json::from_value::<Request>(value).unwrap(), request);
        let post = Request::post_json("/transactions".into(), "{}".into());
        let value = serde_json::to_value(&post).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["body"], "{}");
        assert_eq!(serde_json::from_value::<Request>(value).unwrap(), post);
        for path in ["wallets", "/a?b=1", "/a b", "/a#b"] {
            let value = serde_json::json!({ "method": "GET", "path": path });
            assert!(serde_json::from_value::<Request>(value).is_err(), "{path}");
        }
    }

    #[test]
    fn response_headers() {
        let response = Response::new(200, "{}").with_header("x-block-height", " 42 ");
        assert_eq!(response.block_height(), Some(42));
        assert_eq!(response.header("X-BLOCK-HEIGHT"), Some(" 42 "));
        assert_eq!(Response::new(200, "").block_height(), None);
    }
}
