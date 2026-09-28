//! An async HTTP client over reqwest (feature `http`, native targets only).
//!
//! It sends [`Call`]s to a list of relays: reads go to the first relay that answers, a relay that
//! cannot be reached or answers with a server error is skipped, and HTTP 429 is retried after a
//! [`Backoff`]. Requests are spent against a [`RequestBudget`] before they leave, so a busy client
//! waits instead of being refused.
//!
//! Requests go to the relays and nowhere else: the client never follows a redirect (the node API
//! does not redirect), and a relay that answers with one is skipped like a relay that cannot be
//! reached.
//!
//! HTTPS certificates are verified by the platform's verifier on Linux, macOS, Windows and iOS.
//! On Android, where that verifier needs the application's Java environment, the client trusts the
//! Mozilla root certificates it was built with (the `webpki-root-certs` crate) instead: a relay
//! whose certificate chains to a private or user-installed authority is refused there.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::call::Call;
use crate::error::ApiError;
use crate::limits::{Backoff, RateLimit, RequestBudget};
use crate::request::{Method, Relay, Request, Response};
use crate::solar_compat::{SolarCompat, SubmitPlan};
use crate::types::{SubmitReport, TxRecord};

/// Settings of an [`HttpClient`].
#[derive(Debug, Clone)]
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
    /// relay behind a proxy that asks for a token. The values are marked sensitive, so the
    /// client's `Debug` output never shows them. They reach the relays only, since the client
    /// follows no redirect. Default: none.
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
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            timeout: Duration::from_secs(15),
            rate_limit: RateLimit::REFERENCE_DEFAULT,
            backoff: Backoff::default(),
            user_agent: concat!("iceroot-sdk-api/", env!("CARGO_PKG_VERSION")).to_owned(),
            headers: Vec::new(),
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
}

impl HttpClient {
    /// A client for `relays`, tried in order, with default options.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] without relays; [`ApiError::NodeUnavailable`] when the HTTP
    /// stack cannot be set up (for example no TLS roots).
    pub fn new(relays: Vec<Relay>) -> Result<Self, ApiError> {
        HttpClient::with_options(relays, HttpOptions::default())
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
            .redirect(reqwest::redirect::Policy::none());
        #[cfg(target_os = "android")]
        let builder = builder.tls_certs_only(bundled_roots());
        let http = builder.build().map_err(|e| ApiError::NodeUnavailable {
            detail: format!("HTTP client: {e}"),
        })?;
        Ok(HttpClient {
            http,
            relays,
            budget: Mutex::new(RequestBudget::new(options.rate_limit)),
            backoff: options.backoff,
            started: Instant::now(),
        })
    }

    /// The relays, in the order they are tried.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
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
        let answer = builder.send().await.map_err(|e| transport_error(&e))?;
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
        let body = answer.bytes().await.map_err(|e| transport_error(&e))?;
        let mut response = Response::new(status, body.to_vec());
        for (name, value) in headers {
            response = response.with_header(name, value);
        }
        Ok(response)
    }

    /// Sends a call and decodes the answer.
    ///
    /// Relays are tried in order: one that cannot be reached, times out, answers with a redirect
    /// or answers 5xx is skipped. A 429 is retried on the same relay after the backoff; when
    /// retries are spent the error is [`ApiError::RateLimited`].
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
        for relay in &self.relays {
            let mut attempt = 0u32;
            loop {
                self.spend().await;
                let response = match self.fetch(relay, request).await {
                    Ok(response) => response,
                    Err(error) => {
                        last = error;
                        break;
                    }
                };
                match decode(&response) {
                    Err(ApiError::RateLimited { retry_after }) => {
                        match self.backoff.delay(attempt, retry_after) {
                            Some(wait) => {
                                self.block(wait);
                                attempt = attempt.saturating_add(1);
                            }
                            None => return Err(ApiError::RateLimited { retry_after }),
                        }
                    }
                    Err(error @ ApiError::Refused { status, .. }) if status >= 500 => {
                        last = error;
                        break;
                    }
                    result => return result,
                }
            }
        }
        Err(last)
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
/// environment, which a library cannot do; without it, the first TLS handshake panics.
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
