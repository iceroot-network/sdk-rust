//! An async HTTP client over reqwest (feature `http`, native targets only).
//!
//! It sends [`Call`]s to a list of relays: reads go to the first relay that answers, a relay that
//! cannot be reached or answers with a server error is skipped, and HTTP 429 is retried after a
//! [`Backoff`]; a relay whose retries are spent, or that asks for a wait longer than
//! [`Backoff::MAX_RETRY_AFTER`], is skipped too. Requests are spent against a [`RequestBudget`]
//! before they leave, so a busy client waits instead of being refused.
//!
//! A client of more than one relay keeps to one chain, so that a failover never takes reads, draft
//! facts or submissions to a relay of another chain (a devnet generated again, say). Each relay is
//! asked for its node configuration before its first use, and a relay whose configuration names
//! another network hash or address byte is never asked anything else by that client. The chain
//! is the one given ([`HttpClient::for_chain`], or [`HttpOptions::identity`]: a loaded chain's
//! `Chain::relay_identity` in the core, or a pinned network hash and byte), or else the one of the
//! first relay the client checks, which it learns then (trust on first use;
//! [`HttpClient::identity`] says which). A client of one relay without an identity checks nothing,
//! since it has no relay to fail over to.
//! The other hosts of the SDK (the TypeScript package, the Tauri plugin and the Go SDK) hold
//! every relay to the chain they connected to in the same way.
//!
//! Requests go to the relays and nowhere else: the client never follows a redirect (the node API
//! does not redirect), and a relay that answers with one is skipped like a relay that cannot be
//! reached. An answer is read up to [`MAX_RESPONSE_BYTES`] and never decompressed: a relay that
//! declares or sends a longer body is skipped the same way, so no relay can make the client hold
//! more than that. A proxy named in the process's environment (`HTTP_PROXY`, `HTTPS_PROXY` or
//! `ALL_PROXY`, with `NO_PROXY` for exceptions) is used, as curl uses it: a plain-HTTP request,
//! its headers included, then passes through that proxy, and an HTTPS request passes through it
//! encrypted.
//!
//! HTTPS certificates are verified by the platform's verifier on Linux, macOS, Windows and iOS
//! (on Linux that verifier has no revocation lists, so it checks no revocation). On Android, where
//! that verifier needs the application's Java environment, the client trusts the Mozilla root
//! certificates it was built with (the `webpki-root-certs` crate) instead, with three consequences
//! there:
//!
//! - a relay whose certificate chains to a private or user-installed authority is refused;
//! - the roots are fixed when the application is built: a root Mozilla adds or distrusts later
//!   reaches the application only when it is rebuilt with a newer `webpki-root-certs` (the version
//!   in the application's `Cargo.lock`; `cargo update -p webpki-root-certs` before each release);
//! - no revocation is checked: a revoked certificate of a relay is accepted until it expires.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::call::Call;
use crate::error::ApiError;
use crate::limits::{Backoff, RateLimit, RequestBudget};
use crate::request::{MAX_RESPONSE_BYTES, Method, Relay, Request, Response};
use crate::solar_compat::{SolarCompat, SubmitPlan};
use crate::types::{RelayIdentity, SubmitReport, TxRecord};

/// Settings of an [`HttpClient`]. Its `Debug` output names the extra headers but never shows
/// their values, which may be tokens.
#[derive(Clone)]
pub struct HttpOptions {
    /// Time allowed for one request, connection included. Default 15 s.
    pub timeout: Duration,
    /// The allowance to keep to. Default: the reference implementation's 100 requests a minute.
    pub rate_limit: RateLimit,
    /// Retries after HTTP 429.
    pub backoff: Backoff,
    /// The `User-Agent` header.
    pub user_agent: String,
    /// Extra headers sent to every relay with every request, as `(name, value)` pairs: for a
    /// relay behind a proxy that asks for a token. The values never show in the `Debug` output
    /// of the options or of the client (they are marked sensitive). They reach the relays only,
    /// since the client follows no redirect, and over plain HTTP a proxy the environment names.
    /// Default: none.
    ///
    /// ```no_run
    /// use iceroot_sdk_api::{HttpClient, HttpOptions, Relay};
    ///
    /// # fn run(token: &str) -> Result<(), iceroot_sdk_api::ApiError> {
    /// let options = HttpOptions {
    ///     headers: vec![("authorization".to_owned(), format!("Bearer {token}"))],
    ///     ..HttpOptions::default()
    /// };
    /// let relays = vec![Relay::parse("https://devnet.example/api")?];
    /// let client = HttpClient::with_options(relays, options)?;
    /// # Ok(())
    /// # }
    /// ```
    pub headers: Vec<(String, String)>,
    /// The chain every relay must serve. The client asks each relay for its node configuration
    /// before the relay's first use: a relay that names another network hash or byte is skipped
    /// for the client's lifetime, and one that cannot be checked now (it cannot be reached, or its
    /// answer is refused) is skipped this time and checked again on the next request.
    ///
    /// Default: none. A client of more than one relay then learns the chain from the first relay
    /// it checks, the first one that answers, and holds every other relay to it; a client of one
    /// relay checks nothing. Set it when the chain is known beforehand (a pinned network hash, or
    /// a chain loaded earlier), so that the first relay is held to it too.
    ///
    /// ```no_run
    /// use iceroot_sdk_api::{RelayIdentity, HttpClient, HttpOptions, Relay};
    ///
    /// # fn run(nethash: String) -> Result<(), iceroot_sdk_api::ApiError> {
    /// let options = HttpOptions {
    ///     identity: Some(RelayIdentity { nethash, network_byte: 90 }),
    ///     ..HttpOptions::default()
    /// };
    /// let relays = vec![
    ///     Relay::parse("https://devnet.example/api")?,
    ///     Relay::parse("https://backup.example/api")?,
    /// ];
    /// let client = HttpClient::with_options(relays, options)?;
    /// # Ok(())
    /// # }
    /// ```
    pub identity: Option<RelayIdentity>,
}

impl std::fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("HttpOptions")
            .field("timeout", &self.timeout)
            .field("rate_limit", &self.rate_limit)
            .field("backoff", &self.backoff)
            .field("user_agent", &self.user_agent)
            .field("headers", &headers)
            .field("identity", &self.identity)
            .finish()
    }
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            timeout: Duration::from_secs(15),
            rate_limit: RateLimit::REFERENCE_DEFAULT,
            backoff: Backoff::default(),
            user_agent: concat!("iceroot-sdk-api/", env!("CARGO_PKG_VERSION")).to_owned(),
            headers: Vec::new(),
            identity: None,
        }
    }
}

/// Sends [`Call`]s over HTTP.
#[derive(Debug)]
pub struct HttpClient {
    http: reqwest::Client,
    relays: Vec<Relay>,
    budget: Mutex<RequestBudget>,
    backoff: Backoff,
    started: Instant,
    /// The chain every relay must serve, and what is known of each relay's (see
    /// [`HttpOptions::identity`]).
    chain: ChainCheck,
    checked: Vec<AtomicU8>,
}

/// How an [`HttpClient`] holds its relays to one chain.
#[derive(Debug)]
enum ChainCheck {
    /// One relay and no identity: nothing to fail over to, so nothing is checked.
    None,
    /// Every relay must serve the chain given.
    Given(RelayIdentity),
    /// Every relay must serve the chain of the first relay checked, learned then.
    Learned(OnceLock<RelayIdentity>),
}

/// A relay whose chain is not known yet.
const UNCHECKED: u8 = 0;
/// A relay that serves the client's chain.
const SAME_CHAIN: u8 = 1;
/// A relay that serves another chain: never asked again.
const OTHER_CHAIN: u8 = 2;

impl HttpClient {
    /// A client for `relays`, tried in order, with default options. With more than one relay, it
    /// learns the chain from the first relay it checks and holds the others to it (see
    /// [`HttpOptions::identity`]); where the chain is known, [`HttpClient::for_chain`] holds every
    /// relay to it from the start.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] without relays; [`ApiError::NodeUnavailable`] when the HTTP
    /// stack cannot be set up (for example no TLS roots).
    pub fn new(relays: Vec<Relay>) -> Result<Self, ApiError> {
        HttpClient::with_options(relays, HttpOptions::default())
    }

    /// A client for `relays` of the chain `identity`, with default options otherwise: each relay,
    /// the first one included, is used only once its node configuration names that chain. Give a
    /// loaded chain's identity (`Chain::relay_identity` in the core), or a pinned network hash
    /// with the address byte.
    ///
    /// ```no_run
    /// use iceroot_sdk_api::{HttpClient, Relay, RelayIdentity};
    ///
    /// # fn run(nethash: String) -> Result<(), iceroot_sdk_api::ApiError> {
    /// let relays = vec![
    ///     Relay::parse("https://devnet.example/api")?,
    ///     Relay::parse("https://backup.example/api")?,
    /// ];
    /// let client = HttpClient::for_chain(relays, RelayIdentity { nethash, network_byte: 90 })?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`HttpClient::new`].
    pub fn for_chain(relays: Vec<Relay>, identity: RelayIdentity) -> Result<Self, ApiError> {
        let options = HttpOptions {
            identity: Some(identity),
            ..HttpOptions::default()
        };
        HttpClient::with_options(relays, options)
    }

    /// A client for `relays` with explicit options.
    ///
    /// # Errors
    ///
    /// As [`HttpClient::new`], and [`ApiError::InvalidRequest`] for an extra header whose name or
    /// value HTTP does not allow (the error names the header, never its value).
    pub fn with_options(relays: Vec<Relay>, options: HttpOptions) -> Result<Self, ApiError> {
        if relays.is_empty() {
            return Err(ApiError::invalid("at least one relay is needed"));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &options.headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ApiError::invalid(format!("{name:?} is not an HTTP header name")))?;
            let mut value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                ApiError::invalid(format!(
                    "the value of the header {name} is not valid in HTTP"
                ))
            })?;
            value.set_sensitive(true);
            headers.append(name, value);
        }
        let builder = reqwest::Client::builder()
            .timeout(options.timeout)
            .user_agent(options.user_agent)
            .default_headers(headers)
            // A redirect would take the request, its headers and its body to a host the relay
            // list does not name; `fetch` skips a relay that answers with one.
            .redirect(reqwest::redirect::Policy::none())
            // Answers are read as sent, so their size limit holds for what is held in memory,
            // even where another dependency turns reqwest's decompression features on.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();
        #[cfg(target_os = "android")]
        let builder = builder.tls_certs_only(bundled_roots());
        let http = builder.build().map_err(|e| ApiError::NodeUnavailable {
            detail: format!("HTTP client: {e}"),
        })?;
        let checked = relays.iter().map(|_| AtomicU8::new(UNCHECKED)).collect();
        let chain = match options.identity {
            Some(identity) => ChainCheck::Given(identity),
            None if relays.len() > 1 => ChainCheck::Learned(OnceLock::new()),
            None => ChainCheck::None,
        };
        Ok(HttpClient {
            http,
            relays,
            budget: Mutex::new(RequestBudget::new(options.rate_limit)),
            backoff: options.backoff,
            started: Instant::now(),
            chain,
            checked,
        })
    }

    /// The relays, in the order they are tried.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// The chain the client holds its relays to: the one it was given, or the one it learned from
    /// the first relay it checked (the network hash in lowercase). `None` before a client that
    /// learns has checked a relay, and for a client of one relay without an identity, which
    /// checks nothing.
    pub fn identity(&self) -> Option<RelayIdentity> {
        match &self.chain {
            ChainCheck::None => None,
            ChainCheck::Given(identity) => Some(identity.clone()),
            ChainCheck::Learned(learned) => learned.get().cloned(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    async fn spend(&self) {
        loop {
            let wait = {
                let mut budget = match self.budget.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match budget.acquire(self.now_ms()) {
                    Ok(()) => return,
                    Err(wait) => wait,
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    fn block(&self, wait: Duration) {
        let mut budget = match self.budget.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        budget.block_for(self.now_ms(), wait);
    }

    async fn fetch(&self, relay: &Relay, call_request: &Request) -> Result<Response, ApiError> {
        let url = relay.url(call_request);
        let mut builder = match call_request.method() {
            Method::Get => self.http.get(&url),
            Method::Post => self.http.post(&url),
        };
        for (name, value) in call_request.headers() {
            builder = builder.header(name, value);
        }
        if let Some(body) = call_request.body() {
            builder = builder.body(body.to_owned());
        }
        let mut answer = builder.send().await.map_err(|e| transport_error(&e))?;
        let status = answer.status().as_u16();
        if answer.status().is_redirection() {
            return Err(ApiError::NodeUnavailable {
                detail: format!(
                    "{url} answered with a redirect (HTTP {status}), which the client does not follow"
                ),
            });
        }
        let headers: Vec<(&str, String)> = ["Retry-After", "X-Block-Height"]
            .into_iter()
            .filter_map(|name| {
                let value = answer.headers().get(name)?.to_str().ok()?;
                Some((name, value.to_owned()))
            })
            .collect();
        let too_long = |length: u64| ApiError::NodeUnavailable {
            detail: format!(
                "{url} answered with a body of {length} bytes or more; at most {MAX_RESPONSE_BYTES} are read"
            ),
        };
        let limit = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
        let declared = answer.content_length();
        if let Some(length) = declared.filter(|length| *length > limit) {
            return Err(too_long(length));
        }
        let expected = declared.map_or(0, |length| usize::try_from(length).unwrap_or(0));
        let mut body = Vec::with_capacity(expected);
        while let Some(chunk) = answer.chunk().await.map_err(|e| transport_error(&e))? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                let read = body.len().saturating_add(chunk.len());
                return Err(too_long(u64::try_from(read).unwrap_or(u64::MAX)));
            }
            body.extend_from_slice(&chunk);
        }
        let mut response = Response::new(status, body);
        for (name, value) in headers {
            response = response.with_header(name, value);
        }
        Ok(response)
    }

    /// Sends a call and decodes the answer.
    ///
    /// Relays are tried in order: one that cannot be reached, times out, answers with a redirect
    /// or answers 5xx is skipped. A 429 is retried on the same relay after the backoff; when
    /// retries are spent, or the relay asks for a wait longer than [`Backoff::MAX_RETRY_AFTER`],
    /// the next relay is tried, and after the last one the error is [`ApiError::RateLimited`].
    /// In a client of more than one relay, or one given [`HttpOptions::identity`], a relay is
    /// first checked to serve the client's chain, and skipped when it does not, or cannot be
    /// checked now.
    ///
    /// # Errors
    ///
    /// The decoder's errors, [`ApiError::RateLimited`], and [`ApiError::NodeUnavailable`] or
    /// [`ApiError::Timeout`] when no relay answered.
    pub async fn send<T>(&self, call: &Call<T>) -> Result<T, ApiError> {
        self.exchange(call.request(), |response| call.decode(response))
            .await
    }

    /// Sends `request` and decodes the answer with `decode`, exactly as [`HttpClient::send`] sends
    /// a call: for a host that keeps its calls in another form, such as the SDK's bindings, which
    /// hold each call with a decoder that writes its answer as JSON. `decode` is called once per
    /// answer received, so it may be called again after a 429 or on the next relay.
    ///
    /// # Errors
    ///
    /// As [`HttpClient::send`].
    pub async fn exchange<T>(
        &self,
        request: &Request,
        decode: impl Fn(&Response) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let mut last = ApiError::NodeUnavailable {
            detail: "no relay was tried".into(),
        };
        for (relay, checked) in self.relays.iter().zip(&self.checked) {
            if let Err(error) = self.identify(relay, checked).await {
                last = error;
                continue;
            }
            match self.attempt(relay, request, &decode).await {
                Ok(result) => return result,
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Sends `request` to `relay` alone, with the retries of HTTP 429: the decoded result, or the
    /// error that skips the relay (it cannot be reached, answers 5xx or with a redirect, or its
    /// retries are spent).
    async fn attempt<T>(
        &self,
        relay: &Relay,
        request: &Request,
        decode: &impl Fn(&Response) -> Result<T, ApiError>,
    ) -> Result<Result<T, ApiError>, ApiError> {
        let mut attempt = 0u32;
        loop {
            self.spend().await;
            let response = self.fetch(relay, request).await?;
            match decode(&response) {
                Err(ApiError::RateLimited { retry_after }) => {
                    match self.backoff.delay(attempt, retry_after) {
                        Some(wait) => {
                            self.block(wait);
                            attempt = attempt.saturating_add(1);
                        }
                        // Retries spent, or a wait longer than the client keeps: another relay
                        // may answer, and none is blocked for this one.
                        None => return Err(ApiError::RateLimited { retry_after }),
                    }
                }
                Err(error @ ApiError::Refused { status, .. }) if status >= 500 => {
                    return Err(error);
                }
                result => return Ok(result),
            }
        }
    }

    /// Whether `relay` may be used: only once its node configuration names the client's chain,
    /// the one given or, for the first relay checked, the one it names, which the client learns.
    /// A relay of another chain is refused for the client's lifetime; one that cannot be checked
    /// now is refused with the check's error, and checked again next time.
    async fn identify(&self, relay: &Relay, checked: &AtomicU8) -> Result<(), ApiError> {
        if matches!(self.chain, ChainCheck::None) {
            return Ok(());
        }
        let other_chain = || ApiError::NodeUnavailable {
            detail: format!("{} serves another chain than the client's", relay.as_str()),
        };
        match checked.load(Ordering::Relaxed) {
            SAME_CHAIN => return Ok(()),
            OTHER_CHAIN => return Err(other_chain()),
            _ => {}
        }
        let call = SolarCompat::new(0).node_configuration();
        let node = self
            .attempt(relay, call.request(), &|response| call.decode(response))
            .await
            .and_then(|result| result)?;
        let identity = match &self.chain {
            ChainCheck::Given(identity) => identity,
            ChainCheck::Learned(learned) => {
                learned.get_or_init(|| RelayIdentity::of(&node.network))
            }
            ChainCheck::None => return Ok(()),
        };
        if identity.matches(&node.network) {
            checked.store(SAME_CHAIN, Ordering::Relaxed);
            Ok(())
        } else {
            checked.store(OTHER_CHAIN, Ordering::Relaxed);
            Err(other_chain())
        }
    }

    /// Sends every call of a submission plan and joins the outcomes in submission order.
    ///
    /// # Errors
    ///
    /// As [`HttpClient::send`], for the first request that fails. Earlier requests of the plan
    /// may have reached the pool; look their transactions up before submitting them again.
    pub async fn submit(&self, plan: &SubmitPlan) -> Result<SubmitReport, ApiError> {
        let mut reports = Vec::with_capacity(plan.calls().len());
        for call in plan.calls() {
            reports.push(self.send(call).await?);
        }
        Ok(plan.finish(reports))
    }

    /// Finds a transaction in a block, or else in the node's pool.
    ///
    /// # Errors
    ///
    /// As [`HttpClient::send`], and [`ApiError::InvalidRequest`] for an empty id.
    pub async fn find_transaction(
        &self,
        api: &SolarCompat,
        id: &str,
    ) -> Result<Option<TxRecord>, ApiError> {
        if let Some(record) = self.send(&api.transaction(id)?).await? {
            return Ok(Some(record));
        }
        self.send(&api.unconfirmed_transaction(id)?).await
    }
}

fn transport_error(error: &reqwest::Error) -> ApiError {
    if error.is_timeout() {
        ApiError::Timeout
    } else {
        ApiError::NodeUnavailable {
            detail: error.to_string(),
        }
    }
}

/// The Mozilla root certificates the crate is built with, which the client trusts on Android.
/// There the platform's verifier (reqwest's default) must first be given the application's Java
/// environment, which a library cannot do; without it, the first TLS handshake panics. The set is
/// the one of the `webpki-root-certs` version the application was built with, and no revocation
/// list is given, so none is checked (see the module documentation).
#[cfg(any(target_os = "android", test))]
fn bundled_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_options_debug_output_names_headers_without_their_values() {
        let options = HttpOptions {
            headers: vec![("x-api-key".to_owned(), "s3cret-token".to_owned())],
            ..HttpOptions::default()
        };
        let shown = format!("{options:?}");
        assert!(shown.contains("x-api-key"), "{shown}");
        assert!(!shown.contains("s3cret-token"), "{shown}");
        let client = HttpClient::with_options(
            vec![Relay::parse("http://127.0.0.1:4003/api").unwrap()],
            options,
        )
        .unwrap();
        assert!(!format!("{client:?}").contains("s3cret-token"));
    }

    #[test]
    fn the_bundled_roots_make_a_client() {
        let roots = bundled_roots();
        assert_eq!(roots.len(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
        assert!(roots.len() > 100);
        // Every root is accepted by rustls: the Android client builds.
        reqwest::Client::builder()
            .tls_certs_only(roots)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
    }
}
