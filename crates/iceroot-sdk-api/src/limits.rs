//! The node's request rate limit and how the client keeps to it.
//!
//! The reference implementation allows each client address a fixed number of requests per window
//! (100 per 60 seconds by default) and answers HTTP 429 beyond that, without a `Retry-After`
//! header. [`RequestBudget`] spends requests against that allowance before they are sent, and
//! [`Backoff`] spaces retries after a 429. Both are sans-IO: the caller passes the time, as
//! milliseconds on any monotonic clock.
//!
//! A `Retry-After` is honoured up to [`Backoff::MAX_RETRY_AFTER`] (one minute, the reference
//! implementation's window). A longer one, which a proxy or a hostile relay may send, is not
//! waited for: the retries of that relay end there, and the HTTP client tries the next relay or
//! reports [`crate::ApiError::RateLimited`] with the wait the node asked for.

use std::collections::VecDeque;
use std::time::Duration;

/// A request allowance: at most `requests` per `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Requests allowed per window.
    pub requests: u32,
    /// The window.
    pub window: Duration,
}

impl RateLimit {
    /// The reference implementation's default: 100 requests per 60 seconds per client address.
    pub const REFERENCE_DEFAULT: RateLimit = RateLimit {
        requests: 100,
        window: Duration::from_secs(60),
    };
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit::REFERENCE_DEFAULT
    }
}

/// Spends requests against a [`RateLimit`] over a sliding window.
///
/// ```
/// use std::time::Duration;
/// use iceroot_sdk_api::{RateLimit, RequestBudget};
///
/// let mut budget = RequestBudget::new(RateLimit { requests: 2, window: Duration::from_secs(10) });
/// assert!(budget.acquire(0).is_ok());
/// assert!(budget.acquire(1_000).is_ok());
/// assert_eq!(budget.acquire(2_000), Err(Duration::from_millis(8_000)));
/// assert!(budget.acquire(10_000).is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct RequestBudget {
    limit: RateLimit,
    sent: VecDeque<u64>,
    blocked_until: u64,
}

impl RequestBudget {
    /// An unused budget.
    pub fn new(limit: RateLimit) -> Self {
        RequestBudget {
            limit,
            sent: VecDeque::new(),
            blocked_until: 0,
        }
    }

    /// The allowance this budget keeps to.
    pub fn limit(&self) -> RateLimit {
        self.limit
    }

    fn window_ms(&self) -> u64 {
        u64::try_from(self.limit.window.as_millis()).unwrap_or(u64::MAX)
    }

    /// Takes one request at time `now_ms`, or says how long to wait before one is available.
    ///
    /// # Errors
    ///
    /// The wait, when the window is spent or the node asked the client to back off.
    pub fn acquire(&mut self, now_ms: u64) -> Result<(), Duration> {
        if now_ms < self.blocked_until {
            return Err(Duration::from_millis(self.blocked_until - now_ms));
        }
        let window = self.window_ms();
        while let Some(&oldest) = self.sent.front() {
            if now_ms.saturating_sub(oldest) >= window {
                self.sent.pop_front();
            } else {
                break;
            }
        }
        let allowed = usize::try_from(self.limit.requests).unwrap_or(usize::MAX);
        if allowed == 0 {
            return Err(self.limit.window);
        }
        if self.sent.len() >= allowed {
            let oldest = self.sent.front().copied().unwrap_or(now_ms);
            let free_at = oldest.saturating_add(window);
            return Err(Duration::from_millis(free_at.saturating_sub(now_ms).max(1)));
        }
        self.sent.push_back(now_ms);
        Ok(())
    }

    /// Records a 429 at `now_ms`: no request is allowed for `wait`, at most
    /// [`Backoff::MAX_RETRY_AFTER`].
    pub fn block_for(&mut self, now_ms: u64, wait: Duration) {
        let wait = wait.min(Backoff::MAX_RETRY_AFTER);
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        self.blocked_until = self.blocked_until.max(now_ms.saturating_add(wait_ms));
    }
}

/// How to space retries after the node refused a request with HTTP 429.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Wait before the first retry.
    pub initial: Duration,
    /// Longest wait between retries.
    pub max: Duration,
    /// Retries before the rate limit is reported as an error.
    pub max_retries: u32,
}

impl Default for Backoff {
    /// 2 s, doubling up to 30 s, three retries.
    fn default() -> Self {
        Backoff {
            initial: Duration::from_secs(2),
            max: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

impl Backoff {
    /// The longest `Retry-After` a client waits for: one minute, the reference implementation's
    /// rate limit window.
    pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

    /// The wait before retry number `attempt` (from 0), or `None` when retries are spent or the
    /// node asked for a wait longer than [`Backoff::MAX_RETRY_AFTER`]. A `Retry-After` from the
    /// node wins when it is longer than the schedule's wait.
    pub fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Option<Duration> {
        if attempt >= self.max_retries {
            return None;
        }
        let factor = 2u32.checked_pow(attempt).unwrap_or(u32::MAX);
        let exponential = self.initial.saturating_mul(factor).min(self.max);
        match retry_after {
            Some(asked) if asked > Backoff::MAX_RETRY_AFTER => None,
            Some(asked) if asked > exponential => Some(asked),
            _ => Some(exponential),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_windows() {
        let mut budget = RequestBudget::new(RateLimit::REFERENCE_DEFAULT);
        for i in 0..100 {
            assert!(budget.acquire(i * 10).is_ok());
        }
        assert_eq!(budget.acquire(1_000), Err(Duration::from_millis(59_000)));
        assert!(budget.acquire(60_000).is_ok());
        assert!(budget.acquire(60_001).is_err());
        assert!(budget.acquire(60_010).is_ok());
    }

    #[test]
    fn blocking_after_429() {
        let mut budget = RequestBudget::new(RateLimit::REFERENCE_DEFAULT);
        budget.block_for(1_000, Duration::from_secs(5));
        assert_eq!(budget.acquire(2_000), Err(Duration::from_millis(4_000)));
        assert!(budget.acquire(6_000).is_ok());
        let mut none = RequestBudget::new(RateLimit {
            requests: 0,
            window: Duration::from_secs(1),
        });
        assert_eq!(none.acquire(0), Err(Duration::from_secs(1)));
    }

    #[test]
    fn backoff_schedule() {
        let b = Backoff::default();
        assert_eq!(b.delay(0, None), Some(Duration::from_secs(2)));
        assert_eq!(b.delay(1, None), Some(Duration::from_secs(4)));
        assert_eq!(
            b.delay(2, Some(Duration::from_secs(20))),
            Some(Duration::from_secs(20))
        );
        assert_eq!(b.delay(3, None), None);
        let long = Backoff {
            max_retries: 40,
            ..b
        };
        assert_eq!(long.delay(39, None), Some(Duration::from_secs(30)));
    }

    #[test]
    fn a_retry_after_beyond_a_minute_is_not_waited_for() {
        let b = Backoff::default();
        let minute = Duration::from_secs(60);
        assert_eq!(b.delay(0, Some(minute)), Some(minute));
        for asked in [61, 3_600, 3_000_000_000, u64::MAX] {
            assert_eq!(
                b.delay(0, Some(Duration::from_secs(asked))),
                None,
                "{asked}"
            );
        }
        // Nothing blocks a budget for longer than a minute.
        let mut budget = RequestBudget::new(RateLimit::REFERENCE_DEFAULT);
        budget.block_for(1_000, Duration::from_secs(u64::MAX));
        assert_eq!(budget.acquire(1_000), Err(minute));
        assert!(budget.acquire(61_000).is_ok());
    }
}
