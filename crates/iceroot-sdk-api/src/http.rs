//! An async HTTP client over reqwest (feature `http`, native targets only).
//!
//! It sends [`Call`]s to a list of relays: reads go to the first relay that answers, a relay that
//! cannot be reached or answers with a server error is skipped, and HTTP 429 is retried after a
//! [`Backoff`]. Requests are spent against a [`RequestBudget`] before they leave, so a busy client
//! waits instead of being refused.

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
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            timeout: Duration::from_secs(15),
            rate_limit: RateLimit::REFERENCE_DEFAULT,
            backoff: Backoff::default(),
            user_agent: concat!("iceroot-sdk-api/", env!("CARGO_PKG_VERSION")).to_owned(),
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
    /// As [`HttpClient::new`].
    pub fn with_options(relays: Vec<Relay>, options: HttpOptions) -> Result<Self, ApiError> {
        if relays.is_empty() {
            return Err(ApiError::invalid("at least one relay is needed"));
        }
        let http = reqwest::Client::builder()
            .timeout(options.timeout)
            .user_agent(options.user_agent)
            .build()
            .map_err(|e| ApiError::NodeUnavailable {
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
    /// Relays are tried in order: one that cannot be reached, times out or answers 5xx is skipped.
    /// A 429 is retried on the same relay after the backoff; when retries are spent the error is
    /// [`ApiError::RateLimited`].
    ///
    /// # Errors
    ///
    /// The decoder's errors, [`ApiError::RateLimited`], and [`ApiError::NodeUnavailable`] or
    /// [`ApiError::Timeout`] when no relay answered.
    pub async fn send<T>(&self, call: &Call<T>) -> Result<T, ApiError> {
        let mut last = ApiError::NodeUnavailable {
            detail: "no relay was tried".into(),
        };
        for relay in &self.relays {
            let mut attempt = 0u32;
            loop {
                self.spend().await;
                let response = match self.fetch(relay, call.request()).await {
                    Ok(response) => response,
                    Err(error) => {
                        last = error;
                        break;
                    }
                };
                match call.decode(&response) {
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
