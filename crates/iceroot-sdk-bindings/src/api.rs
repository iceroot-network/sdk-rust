//! The node API client: requests built and answers decoded by the SDK's Rust client, as JSON.
//!
//! The client is sans-IO. [`PreparedCall`] prepares one call of the Solar-compatible backend and
//! gives the request to send; the host performs it (with `fetch` in TypeScript, with reqwest in the
//! Tauri plugin) and hands the status, headers and body back to [`PreparedCall::decode`], which
//! returns the answer in the JSON form every
//! binding of the SDK shares (the `serde` feature of `iceroot-sdk-api`: camel-case fields, 64-bit
//! and wider integers as decimal strings, absent values left out). [`Submission`] splits a
//! submission into requests the pool accepts, and [`Budget`] and [`backoff_delay`]
//! keep the host to the node's rate limit.
//!
//! Answers only leave as JSON; nothing is read back from JSON with `serde`. Arguments are read by
//! hand, and the values the core needs from a node (the chain, the node's identity, a draft's
//! facts, submission reports) stay in Rust. Deserializers for each type would add more to the
//! module than they save.

use std::time::Duration;

use iceroot_sdk::api::{
    ApiError, Backoff, BlockRef, Call, HistoryDirection, PageRequest, PoolLimits, RateLimit, Relay,
    Request, RequestBudget, Response, SolarCompat, SubmitPlan, SubmitReport, SubmitTx, TxFilter,
    TxKind,
};
use iceroot_sdk::{Error, SignedTransaction};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::error::{BindingError, Result};
use crate::json;

type Decoder = Box<dyn Fn(&Response) -> std::result::Result<String, ApiError>>;

/// One prepared call: the request to send and the decoder of its answer.
pub struct PreparedCall {
    request: Request,
    decode: Decoder,
}

impl std::fmt::Debug for PreparedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCall")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// A call whose answer is written as JSON.
fn erase<T: Serialize + 'static>(call: Call<T>) -> PreparedCall {
    PreparedCall {
        request: call.request().clone(),
        decode: Box::new(move |response| {
            let value = call.decode(response)?;
            serde_json::to_string(&value).map_err(|error| ApiError::BadResponse {
                status: response.status(),
                detail: error.to_string(),
            })
        }),
    }
}

impl PreparedCall {
    /// Prepares `operation` of the Solar-compatible backend for a chain with `seats` validator
    /// seats, with its arguments `args` (a JSON object):
    ///
    /// | Operation | Arguments | Answer |
    /// |---|---|---|
    /// | `nodeStatus`, `nodeConfiguration`, `cryptoConfiguration`, `supply` | | `NodeStatus`, `NodeConfiguration`, `CryptoConfiguration`, `Supply` |
    /// | `feeStatistics` | `days?` | `FeeStatistics` |
    /// | `account` | `address` | `AccountInfo` |
    /// | `history` | `address`, `direction?` (`all`, `sent`, `received`), `page?` | `Page<TxRecord>` |
    /// | `accountVotes` | `address`, `page?` | `Page<TxRecord>` |
    /// | `transaction`, `unconfirmedTransaction`, `vote` | `id` | `TxRecord` or `null` |
    /// | `transactions` | `filter?`, `page?` | `Page<TxRecord>` |
    /// | `unconfirmedTransactions`, `votes` | `page?` | `Page<TxRecord>` |
    /// | `latestBlock`, `genesisBlock` | | `BlockInfo` |
    /// | `block` | `block` (`{ height }` or `{ id }`) | `BlockInfo` or `null` |
    /// | `blocks` | `page?` | `Page<BlockInfo>` |
    /// | `blockTransactions` | `block`, `page?` | `Page<TxRecord>` |
    /// | `missedSlots` | `page?` | `Page<MissedSlot>` |
    /// | `validators` | `page?` | `Page<ValidatorInfo>` |
    /// | `validator` | `id` (name, address or public key) | `ValidatorInfo` or `null` |
    /// | `voters` | `id`, `page?` | `Page<AccountInfo>` |
    /// | `validatorBlocks` | `id`, `page?` | `Page<BlockInfo>` |
    /// | `validatorMissedSlots` | `id`, `page?` | `Page<MissedSlot>` |
    /// | `resolveName` | `name` | `ResolvedName` or `null` |
    /// | `roundValidators` | `round` | `RoundValidator[]` |
    ///
    /// A page is `{ page, limit }`; without one the first page of 100 items is read. A filter is
    /// `{ sender?, recipient?, kind?, typeGroup?, typeId?, blockId?, oldestFirst? }`.
    pub fn prepare(seats: u32, operation: &str, args: &str) -> Result<PreparedCall> {
        let api = SolarCompat::new(seats);
        let args = json::parse_object(args, "the arguments")?;
        let page = || page_arg(&args);
        let text = |key: &str| json::string(&args, key);
        Ok(match operation {
            "nodeStatus" => erase(api.node_status()),
            "nodeConfiguration" => erase(api.node_configuration()),
            "cryptoConfiguration" => erase(api.crypto_configuration()),
            "supply" => erase(api.supply()),
            "feeStatistics" => erase(
                api.fee_statistics(small(&args, "days")?)
                    .map_err(Error::from)?,
            ),
            "account" => erase(api.account(text("address")?).map_err(Error::from)?),
            "history" => erase(
                api.history(text("address")?, direction_arg(&args)?, page()?)
                    .map_err(Error::from)?,
            ),
            "accountVotes" => erase(
                api.account_votes(text("address")?, page()?)
                    .map_err(Error::from)?,
            ),
            "transaction" => erase(api.transaction(text("id")?).map_err(Error::from)?),
            "unconfirmedTransaction" => erase(
                api.unconfirmed_transaction(text("id")?)
                    .map_err(Error::from)?,
            ),
            "unconfirmedTransactions" => erase(api.unconfirmed_transactions(page()?)),
            "transactions" => erase(api.transactions(&filter_arg(&args)?, page()?)),
            "votes" => erase(api.votes(page()?)),
            "vote" => erase(api.vote(text("id")?).map_err(Error::from)?),
            "latestBlock" => erase(api.latest_block()),
            "genesisBlock" => erase(api.genesis_block()),
            "block" => erase(api.block(&block_arg(&args)?).map_err(Error::from)?),
            "blocks" => erase(api.blocks(page()?)),
            "blockTransactions" => erase(
                api.block_transactions(&block_arg(&args)?, page()?)
                    .map_err(Error::from)?,
            ),
            "missedSlots" => erase(api.missed_slots(page()?)),
            "validators" => erase(api.validators(page()?)),
            "validator" => erase(api.validator(text("id")?).map_err(Error::from)?),
            "voters" => erase(api.voters(text("id")?, page()?).map_err(Error::from)?),
            "validatorBlocks" => erase(
                api.validator_blocks(text("id")?, page()?)
                    .map_err(Error::from)?,
            ),
            "validatorMissedSlots" => erase(
                api.validator_missed_slots(text("id")?, page()?)
                    .map_err(Error::from)?,
            ),
            "resolveName" => erase(api.resolve_name(text("name")?).map_err(Error::from)?),
            "roundValidators" => erase(
                api.round_validators(json::unsigned(&args, "round", u64::MAX)?)
                    .map_err(Error::from)?,
            ),
            other => {
                return Err(BindingError::argument(format!(
                    "no node API operation is {other:?}"
                )));
            }
        })
    }

    /// The request to send, in JSON: `{ method, path, query, body?, target, headers }`. `target`
    /// is the path with its encoded query string, to append to the relay URL; `headers` are the
    /// headers the request needs, as `[name, value]` pairs.
    pub fn request(&self) -> String {
        request_json(&self.request).to_string()
    }

    /// Decodes the answer to [`PreparedCall::request`]: the HTTP status, the response headers as a JSON
    /// array of `[name, value]` pairs (only `Retry-After` and `X-Block-Height` are read), and the
    /// body. Returns the answer in JSON; a refusal is an error with the client's code
    /// (`RateLimited`, `NotFound`, `Refused`, `BadResponse`).
    pub fn decode(&self, status: u16, headers: &str, body: &[u8]) -> Result<String> {
        let response = response(status, headers, body)?;
        self.decode_response(&response)
    }

    /// The request to send, for a host that performs it natively.
    pub fn raw_request(&self) -> &Request {
        &self.request
    }

    /// Decodes a response a native host received for [`PreparedCall::raw_request`], as
    /// [`PreparedCall::decode`] does.
    pub fn decode_response(&self, response: &Response) -> Result<String> {
        Ok((self.decode)(response).map_err(Error::from)?)
    }
}

/// A submission split into requests within the pool's limits.
///
/// Transactions are added one by one, then [`Submission::plan`] splits them; each answer
/// decoded by [`Submission::decode`] is kept, and [`Submission::finish`] joins them
/// with the refusals in submission order.
#[derive(Debug, Clone)]
pub struct Submission {
    limits: PoolLimits,
    transactions: Vec<SubmitTx>,
    plan: Option<SubmitPlan>,
    reports: Vec<Option<SubmitReport>>,
}

impl Submission {
    /// A submission to a pool that takes at most `max_transactions_per_request` transactions per
    /// request and refuses a transaction above `max_transaction_bytes` (the node configuration's
    /// `pool.maxTransactionsPerRequest` and `pool.maxTransactionBytes`).
    pub fn new(max_transactions_per_request: u32, max_transaction_bytes: u32) -> Submission {
        Submission {
            // Only these two limits bound a submission; the others bound the pool itself.
            limits: PoolLimits {
                max_transactions_in_pool: u32::MAX,
                max_transactions_per_sender: u32::MAX,
                max_transactions_per_request,
                max_transaction_age: u32::MAX,
                max_transaction_bytes,
            },
            transactions: Vec::new(),
            plan: None,
            reports: Vec::new(),
        }
    }

    /// Adds a signed transaction, before [`Submission::plan`].
    pub fn add(&mut self, signed: &SignedTransaction) -> Result<()> {
        if self.plan.is_some() {
            return Err(BindingError::argument("the submission is already planned"));
        }
        self.transactions.push(crate::draft::to_submit(signed)?);
        Ok(())
    }

    /// Splits the transactions into requests and returns how many to send. A transaction larger
    /// than the pool's size limit is refused here, with reason `too-large`, and never sent.
    pub fn plan(&mut self) -> Result<u32> {
        let plan = SolarCompat::new(0)
            .submit(&self.transactions, &self.limits)
            .map_err(Error::from)?;
        let count = plan.calls().len();
        self.reports = vec![None; count];
        self.plan = Some(plan);
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Request number `index`, as [`PreparedCall::request`] writes it.
    pub fn request(&self, index: u32) -> Result<String> {
        Ok(request_json(self.call(index)?.request()).to_string())
    }

    /// Decodes and keeps the answer to request number `index`, and returns its report in JSON:
    /// `{ outcomes: [{ id, status: "accepted", broadcast } | { id, status: "rejected", reason,
    /// nodeCode, message }] }`.
    pub fn decode(
        &mut self,
        index: u32,
        status: u16,
        headers: &str,
        body: &[u8],
    ) -> Result<String> {
        let response = response(status, headers, body)?;
        self.decode_response(index, &response)
    }

    /// Request number `index`, for a host that performs it natively.
    pub fn raw_request(&self, index: u32) -> Result<&Request> {
        Ok(self.call(index)?.request())
    }

    /// Decodes and keeps the answer a native host received for request number `index`, as
    /// [`Submission::decode`] does.
    pub fn decode_response(&mut self, index: u32, response: &Response) -> Result<String> {
        let report = self.call(index)?.decode(response).map_err(Error::from)?;
        let text = to_text(&report)?;
        if let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|index| self.reports.get_mut(index))
        {
            *slot = Some(report);
        }
        Ok(text)
    }

    /// The transactions refused before sending, as a submission report in JSON.
    pub fn refused(&self) -> Result<String> {
        to_text(self.planned()?.refused())
    }

    /// Every outcome so far in submission order, in JSON: the refusals and the decoded answers. A
    /// transaction whose request was not decoded has no outcome.
    pub fn finish(&self) -> Result<String> {
        let reports = self.reports.iter().flatten().cloned();
        to_text(&self.planned()?.finish(reports))
    }
}

impl Submission {
    fn planned(&self) -> Result<&SubmitPlan> {
        self.plan
            .as_ref()
            .ok_or_else(|| BindingError::argument("the submission is not planned yet"))
    }

    fn call(&self, index: u32) -> Result<&Call<SubmitReport>> {
        let calls = self.planned()?.calls();
        usize::try_from(index)
            .ok()
            .and_then(|index| calls.get(index))
            .ok_or_else(|| BindingError::argument(format!("the plan has no request {index}")))
    }
}

/// The node's request allowance, spent before each request (the reference implementation allows
/// 100 requests per 60 seconds per client address by default).
#[derive(Debug, Clone)]
pub struct Budget {
    budget: RequestBudget,
}

impl Budget {
    /// A budget of `requests` per `window_ms` milliseconds.
    pub fn new(requests: u32, window_ms: f64) -> Budget {
        Budget {
            budget: RequestBudget::new(RateLimit {
                requests,
                window: Duration::from_millis(milliseconds(window_ms)),
            }),
        }
    }

    /// Takes one request at `now_ms` (any monotonic clock): 0 when granted, else the milliseconds
    /// to wait before asking again.
    pub fn acquire(&mut self, now_ms: f64) -> f64 {
        match self.budget.acquire(milliseconds(now_ms)) {
            Ok(()) => 0.0,
            Err(wait) => wait_ms(wait),
        }
    }

    /// Records that the node asked to wait `wait_ms` milliseconds at `now_ms`.
    pub fn block_for(&mut self, now_ms: f64, wait_ms: f64) {
        self.budget.block_for(
            milliseconds(now_ms),
            Duration::from_millis(milliseconds(wait_ms)),
        );
    }
}

/// The wait in milliseconds before retry number `attempt` (from 0) after HTTP 429, or `undefined`
/// when the retries are spent: 2 s doubling up to 30 s, three retries, or the node's own
/// `Retry-After` when that is longer.
pub fn backoff_delay(attempt: u32, retry_after_ms: Option<f64>) -> Option<f64> {
    Backoff::default()
        .delay(
            attempt,
            retry_after_ms.map(|ms| Duration::from_millis(milliseconds(ms))),
        )
        .map(wait_ms)
}

/// `url` as a relay URL: `http` or `https`, a host, no credentials, query string or fragment;
/// trailing slashes removed.
pub fn check_relay(url: &str) -> Result<String> {
    Ok(Relay::parse(url).map_err(Error::from)?.as_str().to_owned())
}

/// `value` in the client's JSON form.
pub(crate) fn to_text<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| BindingError::argument(error.to_string()))
}

/// A response from its status, its headers (a JSON array of `[name, value]` pairs, or empty) and
/// its body.
pub(crate) fn response(status: u16, headers: &str, body: &[u8]) -> Result<Response> {
    let mut response = Response::new(status, body.to_vec());
    if headers.trim().is_empty() {
        return Ok(response);
    }
    let bad = || BindingError::argument("the response headers are not [name, value] pairs");
    let pairs: Value = serde_json::from_str(headers).map_err(|_| bad())?;
    for pair in pairs.as_array().ok_or_else(bad)? {
        match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(name), Value::String(value)]) => {
                response = response.with_header(name.clone(), value.clone());
            }
            _ => return Err(bad()),
        }
    }
    Ok(response)
}

/// The optional integer argument `key`, at most `u32::MAX`.
fn small(args: &Map<String, Value>, key: &str) -> Result<Option<u32>> {
    json::optional(args, key)
        .map(|_| {
            u32::try_from(json::unsigned(args, key, u64::from(u32::MAX))?)
                .map_err(|_| BindingError::argument(format!("{key} is out of range")))
        })
        .transpose()
}

/// The page argument: `{ page, limit }`, the first page of 100 items when absent.
fn page_arg(args: &Map<String, Value>) -> Result<PageRequest> {
    let Some(page) = json::optional(args, "page") else {
        return Ok(PageRequest::default());
    };
    let page = json::object(page, "page")?;
    let number = |key: &str| {
        small(page, key)?.ok_or_else(|| BindingError::argument(format!("{key} is missing")))
    };
    Ok(PageRequest::new(number("page")?, number("limit")?).map_err(Error::from)?)
}

/// The history direction: `all` (the default), `sent` or `received`.
fn direction_arg(args: &Map<String, Value>) -> Result<HistoryDirection> {
    match json::optional_string(args, "direction")? {
        None | Some("all") => Ok(HistoryDirection::All),
        Some("sent") => Ok(HistoryDirection::Sent),
        Some("received") => Ok(HistoryDirection::Received),
        Some(other) => Err(BindingError::argument(format!(
            "no history direction is {other:?}"
        ))),
    }
}

/// A block by height (a number or a decimal string) or by id: `{ height }` or `{ id }`.
fn block_arg(args: &Map<String, Value>) -> Result<BlockRef> {
    let block = json::object(json::member(args, "block")?, "block")?;
    if let Some(id) = json::optional_string(block, "id")? {
        return Ok(BlockRef::Id(id.to_owned()));
    }
    let height = json::member(block, "height")?;
    let height = match height.as_u64() {
        Some(height) => height,
        None => u64::try_from(json::decimal(height, "height")?)
            .map_err(|_| BindingError::argument("height is out of range"))?,
    };
    Ok(BlockRef::Height(height))
}

/// A transaction kind: `kind`, with `typeGroup` and `typeId` for `other`.
fn kind_arg(object: &Map<String, Value>) -> Result<Option<TxKind>> {
    let Some(kind) = json::optional_string(object, "kind")? else {
        return Ok(None);
    };
    if kind == "other" {
        let group = small(object, "typeGroup")?;
        let id = small(object, "typeId")?.and_then(|id| u16::try_from(id).ok());
        return match (group, id) {
            (Some(type_group), Some(type_id)) => Ok(Some(TxKind::Other {
                type_group,
                type_id,
            })),
            _ => Err(BindingError::argument(
                "a kind \"other\" needs typeGroup and typeId",
            )),
        };
    }
    TxKind::from_name(kind)
        .map(Some)
        .ok_or_else(|| BindingError::argument(format!("no transaction kind is {kind:?}")))
}

/// The filter of a transaction listing.
fn filter_arg(args: &Map<String, Value>) -> Result<TxFilter> {
    let Some(filter) = json::optional(args, "filter") else {
        return Ok(TxFilter::default());
    };
    let filter = json::object(filter, "filter")?;
    let text = |key: &str| -> Result<Option<String>> {
        Ok(json::optional_string(filter, key)?.map(str::to_owned))
    };
    Ok(TxFilter {
        sender: text("sender")?,
        recipient: text("recipient")?,
        kind: kind_arg(filter)?,
        block_id: text("blockId")?,
        oldest_first: match json::optional(filter, "oldestFirst") {
            None => false,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| BindingError::argument("oldestFirst is not a boolean"))?,
        },
    })
}

fn request_json(request: &Request) -> Value {
    let mut value = serde_json::to_value(request).unwrap_or_else(|_| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("target".into(), Value::String(request.path_and_query()));
        object.insert("headers".into(), json!(request.headers()));
    }
    value
}

/// Milliseconds from JavaScript: negative and non-finite values are 0.
fn milliseconds(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        // A float-to-integer `as` saturates, so no value can overflow.
        value.floor() as u64
    } else {
        0
    }
}

fn wait_ms(wait: Duration) -> f64 {
    let millis = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    // Waits are far below 2^53 milliseconds; a larger one is still a long wait.
    millis as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::devnet;
    use crate::keys::Key;
    use iceroot_sdk::Aux;

    const NODE_STATUS: &str =
        r#"{"data":{"synced":true,"now":80,"blocksCount":0,"timestamp":656}}"#;

    #[test]
    fn prepared_calls_have_requests_and_decoders() {
        let call = PreparedCall::prepare(53, "nodeStatus", "{}").unwrap();
        let request: Value = serde_json::from_str(&call.request()).unwrap();
        assert_eq!(request["method"], "GET");
        assert_eq!(request["target"], "/node/status");
        assert_eq!(request["headers"], json!([["Accept", "application/json"]]));
        let status: Value =
            serde_json::from_str(&call.decode(200, "[]", NODE_STATUS.as_bytes()).unwrap()).unwrap();
        assert_eq!(
            status,
            json!({ "height": "80", "synced": true, "blocksBehind": "0", "chainTime": "656" })
        );

        let history = PreparedCall::prepare(
            53,
            "history",
            r#"{"address":"dA b","direction":"sent","page":{"page":2,"limit":5}}"#,
        )
        .unwrap();
        let request: Value = serde_json::from_str(&history.request()).unwrap();
        assert_eq!(
            request["target"],
            "/wallets/dA%20b/transactions/sent?page=2&limit=5&orderBy=timestamp%3Adesc&transform=true"
        );
        for block in [r#"{"height":"82"}"#, r#"{"height":82}"#] {
            let call =
                PreparedCall::prepare(53, "block", &format!(r#"{{"block":{block}}}"#)).unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&call.request()).unwrap()["path"],
                "/blocks/82"
            );
        }
        let by_id =
            PreparedCall::prepare(53, "blockTransactions", r#"{"block":{"id":"ab"}}"#).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&by_id.request()).unwrap()["path"],
            "/blocks/ab/transactions"
        );
        let filtered = PreparedCall::prepare(
            53,
            "transactions",
            r#"{"filter":{"kind":"vote","sender":"dA","oldestFirst":true},"page":{"page":1,"limit":5}}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&filtered.request()).unwrap()["target"],
            "/transactions?page=1&limit=5&senderId=dA&typeGroup=2&type=2&orderBy=timestamp%3Aasc&transform=true"
        );
        let legacy = PreparedCall::prepare(
            53,
            "transactions",
            r#"{"filter":{"kind":"other","typeGroup":1,"typeId":0}}"#,
        )
        .unwrap();
        assert!(
            serde_json::from_str::<Value>(&legacy.request()).unwrap()["target"]
                .as_str()
                .unwrap()
                .contains("typeGroup=1&type=0")
        );
        let missing = PreparedCall::prepare(53, "transaction", r#"{"id":"ab"}"#).unwrap();
        assert_eq!(
            missing
                .decode(
                    404,
                    "",
                    br#"{"statusCode":404,"error":"Not Found","message":"x"}"#
                )
                .unwrap(),
            "null"
        );
    }

    #[test]
    fn bad_arguments_and_refusals_have_codes() {
        for (operation, args) in [
            ("nodeStatuses", "{}"),
            ("account", "{}"),
            ("account", r#"{"address":""}"#),
            ("blocks", r#"{"page":{"page":0,"limit":5}}"#),
            ("blocks", r#"{"page":{"page":1}}"#),
            ("block", r#"{"block":{"height":"x"}}"#),
            ("block", r#"{"block":{}}"#),
            ("feeStatistics", r#"{"days":31}"#),
            ("feeStatistics", r#"{"days":"7"}"#),
            ("roundValidators", r#"{"round":0}"#),
            ("history", r#"{"address":"dA","direction":"up"}"#),
            ("transactions", r#"{"filter":{"kind":"delegate"}}"#),
            ("transactions", r#"{"filter":{"kind":"other"}}"#),
            ("transactions", r#"{"filter":{"oldestFirst":1}}"#),
            ("nodeStatus", "[]"),
        ] {
            let error = PreparedCall::prepare(53, operation, args).unwrap_err();
            assert!(
                matches!(error.code(), "InvalidArgument" | "InvalidRequest"),
                "{operation} {args}: {}",
                error.code()
            );
        }
        let call = PreparedCall::prepare(53, "nodeStatus", "{}").unwrap();
        let limited = call
            .decode(429, r#"[["Retry-After","3"]]"#, b"{}")
            .unwrap_err();
        assert_eq!(limited.code(), "RateLimited");
        assert_eq!(limited.details(), &json!({ "retryAfterSeconds": 3 }));
        let refused = call
            .decode(
                503,
                "[]",
                br#"{"error":"Service Unavailable","message":"busy"}"#,
            )
            .unwrap_err();
        assert_eq!(refused.code(), "Refused");
        assert_eq!(refused.details()["status"], 503);
        assert_eq!(
            call.decode(200, "[]", b"{").unwrap_err().code(),
            "BadResponse"
        );
        for headers in ["{", "[[1,2]]", r#"[["a"]]"#, "{}"] {
            assert_eq!(
                call.decode(200, headers, b"{}").unwrap_err().code(),
                "InvalidArgument",
                "{headers}"
            );
        }
    }

    fn signed(nonce: u64) -> SignedTransaction {
        let chain = devnet();
        let key =
            Key::from_legacy_passphrase(chain.profile(), "probe passphrase".to_owned()).unwrap();
        let public_key: String = key
            .public_key()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let request = json!({
            "operation": { "kind": "burn", "amount": "100000000" },
            "fee": { "kind": "exact", "amount": "1000000" },
        });
        let facts = json!({ "sender": public_key, "nonce": nonce.to_string(), "height": 2 });
        let draft = crate::draft::build(&chain, &request.to_string(), &facts.to_string()).unwrap();
        crate::draft::sign(&draft, &key, None, Aux::random()).unwrap()
    }

    #[test]
    fn submissions_keep_to_the_pool_limits() {
        let transactions = [signed(1), signed(2), signed(3)];
        let ids: Vec<String> = transactions.iter().map(SignedTransaction::id).collect();
        let size = u32::try_from(transactions[0].bytes().len()).unwrap();

        let mut plan = Submission::new(2, size);
        assert_eq!(plan.refused().unwrap_err().code(), "InvalidArgument");
        for tx in &transactions {
            plan.add(tx).unwrap();
        }
        assert_eq!(plan.plan().unwrap(), 2);
        assert!(plan.add(&transactions[0]).is_err());
        let first: Value = serde_json::from_str(&plan.request(0).unwrap()).unwrap();
        assert_eq!(first["method"], "POST");
        let body: Value = serde_json::from_str(first["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["transactions"].as_array().unwrap().len(), 2);
        assert_eq!(body["transactions"][0]["id"], ids[0].as_str());
        assert!(plan.request(2).is_err());

        let answer = format!(
            r#"{{"data":{{"accept":["{a}"],"broadcast":["{a}"],"excess":[],"invalid":["{b}"]}},
                "errors":{{"{b}":{{"type":"ERR_LOW_FEE","message":"low"}}}}}}"#,
            a = ids[0],
            b = ids[1]
        );
        plan.decode(0, 200, "[]", answer.as_bytes()).unwrap();
        let partial: Value = serde_json::from_str(&plan.finish().unwrap()).unwrap();
        assert_eq!(partial["outcomes"].as_array().unwrap().len(), 2);
        let answer = format!(
            r#"{{"data":{{"accept":["{c}"],"broadcast":[],"excess":[],"invalid":[]}}}}"#,
            c = ids[2]
        );
        plan.decode(1, 200, "", answer.as_bytes()).unwrap();
        let report: Value = serde_json::from_str(&plan.finish().unwrap()).unwrap();
        assert_eq!(
            report,
            json!({ "outcomes": [
                { "id": ids[0], "status": "accepted", "broadcast": true },
                { "id": ids[1], "status": "rejected", "reason": "low-fee", "nodeCode": "ERR_LOW_FEE", "message": "low" },
                { "id": ids[2], "status": "accepted", "broadcast": false },
            ] })
        );

        let mut small = Submission::new(40, size - 1);
        small.add(&transactions[0]).unwrap();
        assert_eq!(small.plan().unwrap(), 0);
        let refused: Value = serde_json::from_str(&small.finish().unwrap()).unwrap();
        assert_eq!(refused["outcomes"][0]["reason"], "too-large");
        assert_eq!(
            Submission::new(40, 100).plan().unwrap_err().code(),
            "InvalidRequest"
        );
    }

    #[test]
    fn budget_backoff_and_relays() {
        let mut budget = Budget::new(2, 10_000.0);
        assert_eq!(budget.acquire(0.0), 0.0);
        assert_eq!(budget.acquire(1_000.0), 0.0);
        assert_eq!(budget.acquire(2_000.0), 8_000.0);
        budget.block_for(10_000.0, 5_000.0);
        assert_eq!(budget.acquire(11_000.0), 4_000.0);
        assert_eq!(budget.acquire(f64::NAN), 15_000.0);
        assert_eq!(backoff_delay(0, None), Some(2_000.0));
        assert_eq!(backoff_delay(1, Some(9_000.0)), Some(9_000.0));
        assert_eq!(backoff_delay(3, None), None);
        assert_eq!(
            check_relay("http://127.0.0.1:4003/api/").unwrap(),
            "http://127.0.0.1:4003/api"
        );
        assert_eq!(
            check_relay("http://u:p@h/api").unwrap_err().code(),
            "InvalidRequest"
        );
    }
}
