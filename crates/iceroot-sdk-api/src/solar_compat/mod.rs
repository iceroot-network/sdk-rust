//! The Solar-compatible backend: the REST API of the reference implementation, which today's
//! devnet serves under the base path `/api`.
//!
//! [`SolarCompat`] prepares one [`Call`] per operation. Its mappers translate the reference's
//! terms into IceRoot's: a delegate is a validator, a username is a name, vote percentages become
//! whole basis points and amount strings become integers in base units.

mod map;
mod wire;

use serde_json::value::RawValue;

use crate::call::{Call, Context};
use crate::error::ApiError;
use crate::request::{Request, segment};
use crate::types::{
    AccountInfo, BlockInfo, BlockRef, CryptoConfiguration, FeeStatistics, HistoryDirection,
    MissedSlot, NodeConfiguration, NodeStatus, Page, PoolLimits, RejectReason, ResolvedName,
    RoundValidator, SubmitOutcome, SubmitReport, SubmitStatus, Supply, TxKind, TxRecord,
    ValidatorInfo,
};

/// The largest page the reference implementation serves.
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Which page of a listing to fetch.
///
/// With the feature `serde` it is `{ page, limit }`, checked as [`PageRequest::new`] checks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "PageFields")
)]
pub struct PageRequest {
    page: u32,
    limit: u32,
}

/// The fields of a [`PageRequest`] before they are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct PageFields {
    page: u32,
    limit: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<PageFields> for PageRequest {
    type Error = ApiError;

    fn try_from(fields: PageFields) -> Result<PageRequest, ApiError> {
        PageRequest::new(fields.page, fields.limit)
    }
}

impl PageRequest {
    /// Page `page` (from 1) of `limit` items (1 to [`MAX_PAGE_LIMIT`]).
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] when either number is out of range.
    pub fn new(page: u32, limit: u32) -> Result<Self, ApiError> {
        if page == 0 {
            return Err(ApiError::invalid("pages are numbered from 1"));
        }
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(ApiError::invalid(format!(
                "a page holds 1 to {MAX_PAGE_LIMIT} items, not {limit}"
            )));
        }
        Ok(PageRequest { page, limit })
    }

    /// The first page of `limit` items, with `limit` clamped to 1 ..= [`MAX_PAGE_LIMIT`].
    pub fn first(limit: u32) -> Self {
        PageRequest {
            page: 1,
            limit: limit.clamp(1, MAX_PAGE_LIMIT),
        }
    }

    /// The page after this one.
    pub fn next(self) -> Self {
        PageRequest {
            page: self.page.saturating_add(1),
            limit: self.limit,
        }
    }

    /// The page number.
    pub fn page(self) -> u32 {
        self.page
    }

    /// The page size.
    pub fn limit(self) -> u32 {
        self.limit
    }

    fn apply(self, request: Request) -> Request {
        request
            .with_query("page", self.page)
            .with_query("limit", self.limit)
    }
}

impl Default for PageRequest {
    /// The first page of [`MAX_PAGE_LIMIT`] items.
    fn default() -> Self {
        PageRequest::first(MAX_PAGE_LIMIT)
    }
}

/// Filters for [`SolarCompat::transactions`]. Every field narrows the listing.
///
/// With the feature `serde` it is `{ sender?, recipient?, kind?, typeGroup?, typeId?, blockId?,
/// oldestFirst? }`, the kind written as everywhere else (see the crate documentation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct TxFilter {
    /// Only transactions from this address.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sender: Option<String>,
    /// Only transactions whose primary recipient is this address. Transfers to several recipients
    /// are listed for an account by [`SolarCompat::history`] instead.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub recipient: Option<String>,
    /// Only this kind.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: Option<TxKind>,
    /// Only transactions of this block (by id).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub block_id: Option<String>,
    /// Newest first (the default) or oldest first.
    #[cfg_attr(feature = "serde", serde(default))]
    pub oldest_first: bool,
}

/// A signed transaction ready for submission.
///
/// With the feature `serde` it is `{ id, json, size }`, `json` being the transaction's JSON object
/// itself, checked as [`SubmitTx::new`] checks it.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SubmitFields")
)]
pub struct SubmitTx {
    id: String,
    json: Box<RawValue>,
    size: usize,
}

/// The fields of a [`SubmitTx`] before they are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct SubmitFields {
    id: String,
    json: Box<RawValue>,
    size: usize,
}

#[cfg(feature = "serde")]
impl TryFrom<SubmitFields> for SubmitTx {
    type Error = ApiError;

    fn try_from(fields: SubmitFields) -> Result<SubmitTx, ApiError> {
        SubmitTx::new(fields.id, fields.json.get(), fields.size)
    }
}

impl SubmitTx {
    /// A transaction to submit: its id, its JSON as the SDK's core produced it, and its serialized
    /// size in bytes (which the pool limits).
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] when the id is empty or holds whitespace, or the JSON is not
    /// a JSON object.
    pub fn new(id: impl Into<String>, json: &str, size: usize) -> Result<Self, ApiError> {
        let id = id.into();
        if id.is_empty() || id.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ApiError::invalid(format!("{id:?} is not a transaction id")));
        }
        let json = RawValue::from_string(json.trim().to_owned())
            .map_err(|e| ApiError::invalid(format!("transaction {id}: {e}")))?;
        if !json.get().starts_with('{') {
            return Err(ApiError::invalid(format!(
                "transaction {id}: JSON must be an object"
            )));
        }
        Ok(SubmitTx { id, json, size })
    }

    /// The transaction id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The serialized size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// A submission split into requests the pool accepts, plus the transactions the client refused
/// before sending.
#[derive(Debug, Clone)]
pub struct SubmitPlan {
    calls: Vec<Call<SubmitReport>>,
    refused: SubmitReport,
    order: Vec<String>,
}

impl SubmitPlan {
    /// The requests to send, each within the pool's per-request limit.
    pub fn calls(&self) -> &[Call<SubmitReport>] {
        &self.calls
    }

    /// Transactions refused before sending (larger than the pool's size limit).
    pub fn refused(&self) -> &SubmitReport {
        &self.refused
    }

    /// Joins the decoded reports of [`calls`](SubmitPlan::calls) with the refusals, in submission
    /// order.
    pub fn finish(&self, reports: impl IntoIterator<Item = SubmitReport>) -> SubmitReport {
        let mut all: Vec<SubmitOutcome> = self.refused.outcomes.clone();
        for report in reports {
            all.extend(report.outcomes);
        }
        let mut outcomes = Vec::with_capacity(self.order.len());
        for id in &self.order {
            if let Some(at) = all.iter().position(|o| &o.id == id) {
                outcomes.push(all.swap_remove(at));
            }
        }
        SubmitReport { outcomes }
    }
}

/// Prepares calls to the reference implementation's REST API.
///
/// Every method returns a [`Call`]: the request to send and the decoder for the answer. Nothing is
/// sent by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolarCompat {
    seats: u32,
}

impl SolarCompat {
    /// A client for a chain with `seats` validator seats per round, which separates active
    /// validators from standby ones. Read it from [`NodeConfiguration::seats`], or use
    /// [`SolarCompat::for_configuration`].
    pub const fn new(seats: u32) -> Self {
        SolarCompat { seats }
    }

    /// A client for the chain a node's configuration describes.
    pub fn for_configuration(configuration: &NodeConfiguration) -> Self {
        SolarCompat::new(configuration.seats)
    }

    /// The seat count this client uses.
    pub fn seats(&self) -> u32 {
        self.seats
    }

    fn context(&self) -> Context {
        Context {
            seats: self.seats,
            ..Context::default()
        }
    }

    fn paged(&self, page: PageRequest) -> Context {
        Context {
            page: page.page,
            limit: page.limit,
            ..self.context()
        }
    }

    // --------------------------------------------------------------------------------------------
    // Node

    /// `GET /node/status`: height, sync state and chain time.
    pub fn node_status(&self) -> Call<NodeStatus> {
        Call::new(
            Request::get("/node/status".into()),
            self.context(),
            map::node_status,
        )
    }

    /// `GET /node/configuration`: chain identity, token labels, the milestone at the tip, pool
    /// limits (including `maxTransactionsPerRequest` and `maxTransactionBytes`) and pool fees.
    ///
    /// The seat count plays no part in this call, so a first contact can use any client, for
    /// example `SolarCompat::new(0)`, and then build the real one with
    /// [`SolarCompat::for_configuration`].
    pub fn node_configuration(&self) -> Call<NodeConfiguration> {
        Call::new(
            Request::get("/node/configuration".into()),
            self.context(),
            map::node_configuration,
        )
    }

    /// `GET /node/configuration/crypto`: the chain definition (network, milestones, genesis block,
    /// exceptions) as JSON text for the SDK core's loaders.
    pub fn crypto_configuration(&self) -> Call<CryptoConfiguration> {
        Call::new(
            Request::get("/node/configuration/crypto".into()),
            self.context(),
            map::crypto_configuration,
        )
    }

    /// `GET /node/fees`: fee statistics per transaction kind, over the last `days` days (1 to 30),
    /// or over each kind's recent transactions when `days` is `None`.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] when `days` is outside 1 to 30.
    pub fn fee_statistics(&self, days: Option<u32>) -> Result<Call<FeeStatistics>, ApiError> {
        let mut request = Request::get("/node/fees".into());
        if let Some(days) = days {
            if !(1..=30).contains(&days) {
                return Err(ApiError::invalid(format!(
                    "fee statistics cover 1 to 30 days, not {days}"
                )));
            }
            request = request.with_query("days", days);
        }
        Ok(Call::new(request, self.context(), map::fee_statistics))
    }

    /// `GET /blockchain`: the supply and the burned amounts at the tip.
    pub fn supply(&self) -> Call<Supply> {
        Call::new(
            Request::get("/blockchain".into()),
            self.context(),
            map::supply,
        )
    }

    // --------------------------------------------------------------------------------------------
    // Accounts

    /// `GET /wallets/{address}`: balance, nonce, vote, second key and validator name. An address the
    /// chain has never seen is a fresh account with nothing in it.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty address.
    pub fn account(&self, address: &str) -> Result<Call<AccountInfo>, ApiError> {
        let path = format!("/wallets/{}", segment(address)?);
        Ok(Call::new(
            Request::get(path),
            self.context(),
            map::account_info,
        ))
    }

    /// `GET /wallets/{address}/transactions` (or `/sent`, `/received`): an account's history,
    /// newest first, each record with its direction relative to the account.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty address.
    pub fn history(
        &self,
        address: &str,
        direction: HistoryDirection,
        page: PageRequest,
    ) -> Result<Call<Page<TxRecord>>, ApiError> {
        let suffix = match direction {
            HistoryDirection::All => "",
            HistoryDirection::Sent => "/sent",
            HistoryDirection::Received => "/received",
        };
        let path = format!("/wallets/{}/transactions{suffix}", segment(address)?);
        let request = page
            .apply(Request::get(path))
            .with_query("orderBy", "timestamp:desc")
            .with_query("transform", "true");
        let context = Context {
            account: Some(address.to_owned()),
            ..self.paged(page)
        };
        Ok(Call::new(request, context, map::transaction_page))
    }

    /// `GET /wallets/{address}/votes`: the vote transactions an account sent, newest first.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty address.
    pub fn account_votes(
        &self,
        address: &str,
        page: PageRequest,
    ) -> Result<Call<Page<TxRecord>>, ApiError> {
        let path = format!("/wallets/{}/votes", segment(address)?);
        let request = page
            .apply(Request::get(path))
            .with_query("orderBy", "timestamp:desc")
            .with_query("transform", "true");
        let context = Context {
            account: Some(address.to_owned()),
            ..self.paged(page)
        };
        Ok(Call::new(request, context, map::transaction_page))
    }

    // --------------------------------------------------------------------------------------------
    // Transactions

    /// `GET /transactions/{id}`: a confirmed transaction, or `None` when no block holds it. Look in
    /// the pool with [`unconfirmed_transaction`](SolarCompat::unconfirmed_transaction) next.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id.
    pub fn transaction(&self, id: &str) -> Result<Call<Option<TxRecord>>, ApiError> {
        let path = format!("/transactions/{}", segment(id)?);
        let request = Request::get(path).with_query("transform", "true");
        Ok(Call::new(
            request,
            self.context(),
            map::transaction_optional,
        ))
    }

    /// `GET /transactions/unconfirmed/{id}`: a transaction waiting in the node's pool, or `None`.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id.
    pub fn unconfirmed_transaction(&self, id: &str) -> Result<Call<Option<TxRecord>>, ApiError> {
        let path = format!("/transactions/unconfirmed/{}", segment(id)?);
        Ok(Call::new(
            Request::get(path),
            self.context(),
            map::transaction_optional,
        ))
    }

    /// `GET /transactions/unconfirmed`: the node's pool, highest priority first.
    pub fn unconfirmed_transactions(&self, page: PageRequest) -> Call<Page<TxRecord>> {
        let request = page.apply(Request::get("/transactions/unconfirmed".into()));
        Call::new(request, self.paged(page), map::transaction_page)
    }

    /// `GET /transactions`: confirmed transactions matching `filter`.
    pub fn transactions(&self, filter: &TxFilter, page: PageRequest) -> Call<Page<TxRecord>> {
        let mut request = page.apply(Request::get("/transactions".into()));
        if let Some(sender) = &filter.sender {
            request = request.with_query("senderId", sender);
        }
        if let Some(recipient) = &filter.recipient {
            request = request.with_query("recipientId", recipient);
        }
        if let Some(kind) = filter.kind {
            let (group, id) = map::wire_type(kind);
            request = request
                .with_query("typeGroup", group)
                .with_query("type", id);
        }
        if let Some(block_id) = &filter.block_id {
            request = request.with_query("blockId", block_id);
        }
        let order = if filter.oldest_first {
            "timestamp:asc"
        } else {
            "timestamp:desc"
        };
        let request = request
            .with_query("orderBy", order)
            .with_query("transform", "true");
        Call::new(request, self.paged(page), map::transaction_page)
    }

    /// `GET /votes`: vote transactions, newest first.
    pub fn votes(&self, page: PageRequest) -> Call<Page<TxRecord>> {
        let request = page
            .apply(Request::get("/votes".into()))
            .with_query("orderBy", "timestamp:desc")
            .with_query("transform", "true");
        Call::new(request, self.paged(page), map::transaction_page)
    }

    /// `GET /votes/{id}`: one vote transaction, or `None`.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id.
    pub fn vote(&self, id: &str) -> Result<Call<Option<TxRecord>>, ApiError> {
        let path = format!("/votes/{}", segment(id)?);
        let request = Request::get(path).with_query("transform", "true");
        Ok(Call::new(
            request,
            self.context(),
            map::transaction_optional,
        ))
    }

    /// `POST /transactions`: prepares a submission within the pool's limits.
    ///
    /// Transactions larger than `limits.max_transaction_bytes` are refused here, with reason
    /// `too-large`, and never sent. The rest are split into requests of at most
    /// `limits.max_transactions_per_request`. Send every call, decode each answer and join them
    /// with [`SubmitPlan::finish`].
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty submission, a repeated id or a pool that admits
    /// no transaction per request.
    pub fn submit(
        &self,
        transactions: &[SubmitTx],
        limits: &PoolLimits,
    ) -> Result<SubmitPlan, ApiError> {
        if transactions.is_empty() {
            return Err(ApiError::invalid("nothing to submit"));
        }
        let per_request =
            usize::try_from(limits.max_transactions_per_request).unwrap_or(usize::MAX);
        if per_request == 0 {
            return Err(ApiError::invalid(
                "the pool accepts no transactions per request",
            ));
        }
        let max_bytes = usize::try_from(limits.max_transaction_bytes).unwrap_or(usize::MAX);
        let mut order: Vec<String> = Vec::with_capacity(transactions.len());
        let mut refused = SubmitReport::default();
        let mut sendable: Vec<&SubmitTx> = Vec::with_capacity(transactions.len());
        for tx in transactions {
            if order.contains(&tx.id) {
                return Err(ApiError::invalid(format!(
                    "transaction {} is submitted twice",
                    tx.id
                )));
            }
            order.push(tx.id.clone());
            if tx.size > max_bytes {
                refused.outcomes.push(SubmitOutcome {
                    id: tx.id.clone(),
                    status: SubmitStatus::Rejected {
                        reason: RejectReason::TooLarge,
                        node_code: "ERR_TOO_LARGE".into(),
                        message: format!(
                            "{} bytes exceed the pool's limit of {} bytes",
                            tx.size, limits.max_transaction_bytes
                        ),
                    },
                });
            } else {
                sendable.push(tx);
            }
        }
        let calls = sendable
            .chunks(per_request)
            .map(|batch| {
                let mut body = String::from("{\"transactions\":[");
                for (i, tx) in batch.iter().enumerate() {
                    if i > 0 {
                        body.push(',');
                    }
                    body.push_str(tx.json.get());
                }
                body.push_str("]}");
                let context = Context {
                    ids: batch.iter().map(|tx| tx.id.clone()).collect(),
                    ..self.context()
                };
                Call::new(
                    Request::post_json("/transactions".into(), body),
                    context,
                    map::submit_report,
                )
            })
            .collect();
        Ok(SubmitPlan {
            calls,
            refused,
            order,
        })
    }

    // --------------------------------------------------------------------------------------------
    // Blocks

    /// `GET /blocks/last`: the node's last block.
    pub fn latest_block(&self) -> Call<BlockInfo> {
        let request = Request::get("/blocks/last".into()).with_query("transform", "true");
        Call::new(request, self.context(), map::block_info)
    }

    /// `GET /blocks/first`: the genesis block.
    pub fn genesis_block(&self) -> Call<BlockInfo> {
        let request = Request::get("/blocks/first".into()).with_query("transform", "true");
        Call::new(request, self.context(), map::block_info)
    }

    /// `GET /blocks/{id or height}`: one block, or `None`.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id or height 0.
    pub fn block(&self, block: &BlockRef) -> Result<Call<Option<BlockInfo>>, ApiError> {
        let request = Request::get(format!("/blocks/{}", block_segment(block)?))
            .with_query("transform", "true");
        Ok(Call::new(request, self.context(), map::block_optional))
    }

    /// `GET /blocks`: blocks, highest first.
    pub fn blocks(&self, page: PageRequest) -> Call<Page<BlockInfo>> {
        let request = page
            .apply(Request::get("/blocks".into()))
            .with_query("orderBy", "height:desc")
            .with_query("transform", "true");
        Call::new(request, self.paged(page), map::block_page)
    }

    /// `GET /blocks/{id or height}/transactions`: the transactions of one block, in block order.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id or height 0.
    pub fn block_transactions(
        &self,
        block: &BlockRef,
        page: PageRequest,
    ) -> Result<Call<Page<TxRecord>>, ApiError> {
        let path = format!("/blocks/{}/transactions", block_segment(block)?);
        let request = page
            .apply(Request::get(path))
            .with_query("transform", "true");
        Ok(Call::new(request, self.paged(page), map::transaction_page))
    }

    /// `GET /blocks/missed`: missed slots of every validator, newest first.
    pub fn missed_slots(&self, page: PageRequest) -> Call<Page<MissedSlot>> {
        let request = page
            .apply(Request::get("/blocks/missed".into()))
            .with_query("orderBy", "height:desc");
        Call::new(request, self.paged(page), map::missed_page)
    }

    // --------------------------------------------------------------------------------------------
    // Validators, names and rounds

    /// `GET /delegates`: registered validators in rank order.
    pub fn validators(&self, page: PageRequest) -> Call<Page<ValidatorInfo>> {
        let request = page.apply(Request::get("/delegates".into()));
        Call::new(request, self.paged(page), map::validator_page)
    }

    /// `GET /delegates/{id}`: one validator by name, address or public key, or `None`.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty id.
    pub fn validator(
        &self,
        name_or_address: &str,
    ) -> Result<Call<Option<ValidatorInfo>>, ApiError> {
        let path = format!("/delegates/{}", segment(name_or_address)?);
        Ok(Call::new(
            Request::get(path),
            self.context(),
            map::validator_optional,
        ))
    }

    /// `GET /delegates/{name}/voters`: the accounts voting for a validator.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty name.
    pub fn voters(
        &self,
        name_or_address: &str,
        page: PageRequest,
    ) -> Result<Call<Page<AccountInfo>>, ApiError> {
        let path = format!("/delegates/{}/voters", segment(name_or_address)?);
        Ok(Call::new(
            page.apply(Request::get(path)),
            self.paged(page),
            map::account_page,
        ))
    }

    /// `GET /delegates/{name}/blocks`: the blocks a validator produced, highest first.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty name.
    pub fn validator_blocks(
        &self,
        name_or_address: &str,
        page: PageRequest,
    ) -> Result<Call<Page<BlockInfo>>, ApiError> {
        let path = format!("/delegates/{}/blocks", segment(name_or_address)?);
        let request = page
            .apply(Request::get(path))
            .with_query("orderBy", "height:desc")
            .with_query("transform", "true");
        Ok(Call::new(request, self.paged(page), map::block_page))
    }

    /// `GET /delegates/{name}/blocks/missed`: the slots a validator missed, newest first.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty name.
    pub fn validator_missed_slots(
        &self,
        name_or_address: &str,
        page: PageRequest,
    ) -> Result<Call<Page<MissedSlot>>, ApiError> {
        let path = format!("/delegates/{}/blocks/missed", segment(name_or_address)?);
        let request = page
            .apply(Request::get(path))
            .with_query("orderBy", "height:desc");
        Ok(Call::new(request, self.paged(page), map::missed_page))
    }

    /// `GET /delegates/{name}`: resolves a validator name to its account, or `None`. On this backend
    /// only validators have names.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for an empty name.
    pub fn resolve_name(&self, name: &str) -> Result<Call<Option<ResolvedName>>, ApiError> {
        let path = format!("/delegates/{}", segment(name)?);
        let context = Context {
            name: Some(name.to_owned()),
            ..self.context()
        };
        Ok(Call::new(Request::get(path), context, map::resolved_name))
    }

    /// `GET /rounds/{round}/delegates`: the validator set of a round.
    ///
    /// # Errors
    ///
    /// [`ApiError::InvalidRequest`] for round 0 (rounds are numbered from 1).
    pub fn round_validators(&self, round: u64) -> Result<Call<Vec<RoundValidator>>, ApiError> {
        if round == 0 {
            return Err(ApiError::invalid("rounds are numbered from 1"));
        }
        Ok(Call::new(
            Request::get(format!("/rounds/{round}/delegates")),
            self.context(),
            map::round_validators,
        ))
    }
}

fn block_segment(block: &BlockRef) -> Result<String, ApiError> {
    match block {
        BlockRef::Height(0) => Err(ApiError::invalid("block heights start at 1")),
        BlockRef::Height(height) => Ok(height.to_string()),
        BlockRef::Id(id) => segment(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Method, Relay, Response};

    const LIMITS: PoolLimits = PoolLimits {
        max_transactions_in_pool: 15000,
        max_transactions_per_sender: 150,
        max_transactions_per_request: 2,
        max_transaction_age: 2700,
        max_transaction_bytes: 200,
    };

    fn tx(id: &str, size: usize) -> SubmitTx {
        SubmitTx::new(id, &format!(r#"{{"id":"{id}"}}"#), size).unwrap()
    }

    #[test]
    fn page_requests() {
        assert!(PageRequest::new(0, 10).is_err());
        assert!(PageRequest::new(1, 0).is_err());
        assert!(PageRequest::new(1, 101).is_err());
        let p = PageRequest::new(3, 20).unwrap();
        assert_eq!((p.page(), p.limit()), (3, 20));
        assert_eq!(p.next().page(), 4);
        assert_eq!(PageRequest::first(1000).limit(), 100);
        assert_eq!(PageRequest::default().limit(), 100);
    }

    #[test]
    fn request_shapes() {
        let api = SolarCompat::new(53);
        let relay = Relay::parse("http://h/api").unwrap();
        let page = PageRequest::new(2, 10).unwrap();
        let history = api.history("dAbc", HistoryDirection::Sent, page).unwrap();
        assert_eq!(
            relay.url(history.request()),
            "http://h/api/wallets/dAbc/transactions/sent?page=2&limit=10&orderBy=timestamp%3Adesc&transform=true"
        );
        let filter = TxFilter {
            sender: Some("dA".into()),
            kind: Some(TxKind::Vote),
            oldest_first: true,
            ..TxFilter::default()
        };
        assert_eq!(
            api.transactions(&filter, PageRequest::first(5))
                .request()
                .path_and_query(),
            "/transactions?page=1&limit=5&senderId=dA&typeGroup=2&type=2&orderBy=timestamp%3Aasc&transform=true"
        );
        assert_eq!(
            api.block(&BlockRef::Height(82)).unwrap().request().path(),
            "/blocks/82"
        );
        assert!(api.block(&BlockRef::Height(0)).is_err());
        assert!(api.round_validators(0).is_err());
        assert!(api.fee_statistics(Some(31)).is_err());
        assert_eq!(
            api.fee_statistics(Some(7))
                .unwrap()
                .request()
                .path_and_query(),
            "/node/fees?days=7"
        );
        assert!(api.account("").is_err());
        assert!(api.validator("..").is_err());
    }

    #[test]
    fn submit_plan_batches_and_refuses() {
        let api = SolarCompat::new(53);
        let txs = [tx("a", 100), tx("b", 300), tx("c", 150), tx("d", 50)];
        let plan = api.submit(&txs, &LIMITS).unwrap();
        assert_eq!(plan.calls().len(), 2);
        let first = plan.calls()[0].request();
        assert_eq!(first.method(), Method::Post);
        assert_eq!(
            first.body(),
            Some(r#"{"transactions":[{"id":"a"},{"id":"c"}]}"#)
        );
        assert_eq!(
            plan.calls()[1].request().body(),
            Some(r#"{"transactions":[{"id":"d"}]}"#)
        );
        assert_eq!(plan.refused().outcomes.len(), 1);

        let answer_1 = Response::new(
            200,
            r#"{"data":{"accept":["a"],"broadcast":[],"excess":[],"invalid":["c"]},"errors":{"c":{"type":"ERR_LOW_FEE","message":"low"}}}"#,
        );
        let answer_2 = Response::new(
            200,
            r#"{"data":{"accept":["d"],"broadcast":["d"],"excess":[],"invalid":[]}}"#,
        );
        let reports = [
            plan.calls()[0].decode(&answer_1).unwrap(),
            plan.calls()[1].decode(&answer_2).unwrap(),
        ];
        let report = plan.finish(reports);
        let ids: Vec<&str> = report.outcomes.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c", "d"]);
        assert_eq!(
            report.outcomes[0].status,
            SubmitStatus::Accepted { broadcast: false }
        );
        assert!(matches!(
            report.outcomes[1].status,
            SubmitStatus::Rejected {
                reason: RejectReason::TooLarge,
                ..
            }
        ));
        assert!(matches!(
            report.outcomes[2].status,
            SubmitStatus::Rejected {
                reason: RejectReason::LowFee,
                ..
            }
        ));
        assert!(!report.all_accepted());
    }

    #[test]
    fn submit_rules() {
        let api = SolarCompat::new(53);
        assert!(api.submit(&[], &LIMITS).is_err());
        assert!(api.submit(&[tx("a", 1), tx("a", 1)], &LIMITS).is_err());
        let none = PoolLimits {
            max_transactions_per_request: 0,
            ..LIMITS
        };
        assert!(api.submit(&[tx("a", 1)], &none).is_err());
        assert!(SubmitTx::new("a", "[1]", 1).is_err());
        assert!(SubmitTx::new("a", "{", 1).is_err());
        assert!(SubmitTx::new("a b", "{}", 1).is_err());
        assert!(SubmitTx::new("", "{}", 1).is_err());
    }

    #[test]
    fn rejections_under_another_id_follow_submission_order() {
        let api = SolarCompat::new(53);
        let plan = api
            .submit(&[tx("a", 1), tx("b", 1), tx("c", 1)], &LIMITS_WIDE)
            .unwrap();
        let answer = Response::new(
            200,
            r#"{"data":{"accept":["b"],"broadcast":["b"],"excess":[],"invalid":["x","y"]},
               "errors":{"x":{"type":"ERR_BAD_DATA","message":"bad a"},"y":{"type":"ERR_APPLY","message":"bad c"}}}"#,
        );
        let report = plan.calls()[0].decode(&answer).unwrap();
        let messages: Vec<&str> = report
            .outcomes
            .iter()
            .map(|o| match &o.status {
                SubmitStatus::Rejected { message, .. } => message.as_str(),
                SubmitStatus::Accepted { .. } => "accepted",
            })
            .collect();
        assert_eq!(messages, ["bad a", "accepted", "bad c"]);

        let accepted_elsewhere = Response::new(
            200,
            r#"{"data":{"accept":["z","b"],"broadcast":[],"excess":[],"invalid":["x"]}}"#,
        );
        assert!(matches!(
            plan.calls()[0].decode(&accepted_elsewhere),
            Err(ApiError::BadResponse { .. })
        ));
    }

    const LIMITS_WIDE: PoolLimits = PoolLimits {
        max_transactions_per_request: 40,
        ..LIMITS
    };

    #[cfg(feature = "serde")]
    #[test]
    fn request_values_as_json() {
        use serde_json::json;

        let page: PageRequest = serde_json::from_value(json!({ "page": 2, "limit": 25 })).unwrap();
        assert_eq!(page, PageRequest::new(2, 25).unwrap());
        assert_eq!(
            serde_json::to_value(page).unwrap(),
            json!({ "page": 2, "limit": 25 })
        );
        for bad in [
            json!({ "page": 0, "limit": 1 }),
            json!({ "page": 1, "limit": 101 }),
        ] {
            assert!(serde_json::from_value::<PageRequest>(bad).is_err());
        }

        let filter = TxFilter {
            sender: Some("dA".into()),
            kind: Some(TxKind::Other {
                type_group: 1,
                type_id: 4,
            }),
            oldest_first: true,
            ..TxFilter::default()
        };
        let value = serde_json::to_value(&filter).unwrap();
        assert_eq!(
            value,
            json!({ "sender": "dA", "kind": "other", "typeGroup": 1, "typeId": 4, "oldestFirst": true })
        );
        assert_eq!(serde_json::from_value::<TxFilter>(value).unwrap(), filter);
        assert_eq!(
            serde_json::from_value::<TxFilter>(json!({})).unwrap(),
            TxFilter::default()
        );
        assert_eq!(
            serde_json::from_value::<TxFilter>(json!({ "kind": "vote", "blockId": "ab" })).unwrap(),
            TxFilter {
                kind: Some(TxKind::Vote),
                block_id: Some("ab".into()),
                ..TxFilter::default()
            }
        );
        assert_eq!(
            serde_json::to_value(TxFilter::default()).unwrap(),
            json!({ "oldestFirst": false })
        );

        let text = r#"{"id":"a1","json":{"id":"a1","fee":"5"},"size":120}"#;
        let tx: SubmitTx = serde_json::from_str(text).unwrap();
        assert_eq!((tx.id(), tx.size()), ("a1", 120));
        assert_eq!(serde_json::to_string(&tx).unwrap(), text);
        assert!(serde_json::from_str::<SubmitTx>(r#"{"id":"a 1","json":{},"size":1}"#).is_err());
        assert!(serde_json::from_str::<SubmitTx>(r#"{"id":"a1","json":[],"size":1}"#).is_err());
    }

    #[test]
    fn unreported_transaction_is_a_bad_response() {
        let api = SolarCompat::new(53);
        let plan = api.submit(&[tx("a", 1)], &LIMITS).unwrap();
        let answer = Response::new(
            200,
            r#"{"data":{"accept":[],"broadcast":[],"excess":[],"invalid":[]}}"#,
        );
        assert!(matches!(
            plan.calls()[0].decode(&answer),
            Err(ApiError::BadResponse { .. })
        ));
    }
}
