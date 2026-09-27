//! Mappers from the reference implementation's resources to the SDK's IceRoot-shaped types.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

use crate::call::Context;
use crate::error::ApiError;
use crate::request::Response;
use crate::types::{
    AccountInfo, AssetId, Balance, BlockInfo, Burned, CryptoConfiguration, Donation, Earnings,
    FeeStatistic, FeeStatistics, LastBlock, MissedSlot, NetworkIdentity, NodeConfiguration,
    NodeStatus, Page, Payment, PoolFees, PoolLimits, RejectReason, Resignation, ResolvedName,
    RoundValidator, SubmitOutcome, SubmitReport, SubmitStatus, Supply, Timestamp, TokenLabels,
    TxBlock, TxDetails, TxKind, TxRecord, TxStatus, ValidatorInfo, ValidatorStatus, VoteEntry,
};

use super::wire;

// ------------------------------------------------------------------------------------------------
// Status and body handling

/// Turns a non-2xx answer into the matching error.
fn error_for(response: &Response) -> ApiError {
    let status = response.status();
    let body: Option<wire::ErrorBody> = serde_json::from_slice(response.body()).ok();
    let (error, message) = body
        .map(|b| (b.error.unwrap_or_default(), b.message.unwrap_or_default()))
        .unwrap_or_default();
    match status {
        429 => ApiError::RateLimited {
            retry_after: response
                .header("Retry-After")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        },
        404 => ApiError::NotFound { message },
        400..=599 => ApiError::Refused {
            status,
            error,
            message,
        },
        _ => ApiError::bad(status, "unexpected HTTP status"),
    }
}

fn is_success(response: &Response) -> bool {
    (200..300).contains(&response.status())
}

/// Parses the body of a successful answer.
fn body<T: DeserializeOwned>(response: &Response) -> Result<T, ApiError> {
    if !is_success(response) {
        return Err(error_for(response));
    }
    serde_json::from_slice(response.body())
        .map_err(|e| ApiError::bad(response.status(), e.to_string()))
}

/// Parses `{ "data": T }`.
fn data<T: DeserializeOwned>(response: &Response) -> Result<T, ApiError> {
    body::<wire::Envelope<T>>(response).map(|e| e.data)
}

/// Parses `{ "data": T }`, or `None` for a 404.
fn optional_data<T: DeserializeOwned>(response: &Response) -> Result<Option<T>, ApiError> {
    if response.status() == 404 {
        return Ok(None);
    }
    data(response).map(Some)
}

/// Parses a paginated listing and maps each item.
fn page<W: DeserializeOwned, T>(
    response: &Response,
    context: &Context,
    mut map: impl FnMut(W) -> Result<T, String>,
) -> Result<Page<T>, ApiError> {
    let status = response.status();
    let paged: wire::Paged<W> = body(response)?;
    let items = paged
        .data
        .into_iter()
        .map(&mut map)
        .collect::<Result<Vec<T>, String>>()
        .map_err(|e| ApiError::bad(status, e))?;
    Ok(Page {
        items,
        page: context.page.max(1),
        page_count: paged.meta.page_count,
        total: paged.meta.total_count,
        total_is_estimate: paged.meta.total_count_is_estimate,
        has_next: paged.meta.next.is_some(),
    })
}

fn mapped<W, T>(
    response: &Response,
    value: W,
    map: impl FnOnce(W) -> Result<T, String>,
) -> Result<T, ApiError> {
    map(value).map_err(|e| ApiError::bad(response.status(), e))
}

// ------------------------------------------------------------------------------------------------
// Numbers

fn to_u64(value: u128, what: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{what} {value} does not fit in 64 bits"))
}

/// A JSON number as an exact decimal: `mantissa × 10^exponent`.
fn decimal(number: &serde_json::Number) -> Result<(u128, i32), String> {
    let text = number.to_string();
    let bad = || format!("{text} is not a non-negative decimal number");
    let (mantissa_text, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().map_err(|_| bad())?),
        None => (text.as_str(), 0),
    };
    let (whole, fraction) = mantissa_text.split_once('.').unwrap_or((mantissa_text, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.len() > 38 {
        return Err(format!("{text} has too many digits"));
    }
    let mantissa = if digits.is_empty() {
        0
    } else {
        digits.parse::<u128>().map_err(|_| bad())?
    };
    let fraction_len = i32::try_from(fraction.len()).map_err(|_| bad())?;
    Ok((mantissa, exponent.saturating_sub(fraction_len)))
}

/// A percentage as basis points, exactly: 18.1 gives 1,810; 18.105 is refused.
fn percent_to_basis_points_exact(number: &serde_json::Number) -> Result<u32, String> {
    let (mantissa, exponent) = decimal(number)?;
    if mantissa == 0 {
        return Ok(0);
    }
    let shift = exponent.saturating_add(2);
    let value = if shift >= 0 {
        10u128
            .checked_pow(shift.unsigned_abs())
            .and_then(|p| mantissa.checked_mul(p))
    } else {
        10u128
            .checked_pow(shift.unsigned_abs())
            .filter(|p| mantissa % p == 0)
            .map(|p| mantissa / p)
    };
    value
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("{number} is not a whole number of basis points"))
}

/// A percentage as basis points, rounded half up (for figures the node already rounded).
fn percent_to_basis_points_rounded(number: &serde_json::Number) -> Result<u32, String> {
    let (mantissa, exponent) = decimal(number)?;
    if mantissa == 0 {
        return Ok(0);
    }
    let shift = exponent.saturating_add(2);
    let value = if shift >= 0 {
        10u128
            .checked_pow(shift.unsigned_abs())
            .and_then(|p| mantissa.checked_mul(p))
    } else if shift < -38 {
        Some(0)
    } else {
        10u128.checked_pow(shift.unsigned_abs()).map(|p| {
            let (q, r) = (mantissa / p, mantissa % p);
            if r.saturating_mul(2) >= p { q + 1 } else { q }
        })
    };
    value
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("{number} is out of range for basis points"))
}

fn timestamp(t: wire::Timestamp) -> Timestamp {
    Timestamp {
        chain: t.epoch,
        unix: t.unix,
    }
}

fn raw_text(raw: &RawValue) -> String {
    raw.get().to_owned()
}

// ------------------------------------------------------------------------------------------------
// Node

pub(crate) fn node_status(response: &Response, _: &Context) -> Result<NodeStatus, ApiError> {
    let s: wire::NodeStatus = data(response)?;
    Ok(NodeStatus {
        height: s.now,
        synced: s.synced,
        blocks_behind: u64::try_from(s.blocks_count).unwrap_or(0),
        chain_time: s.timestamp,
    })
}

pub(crate) fn node_configuration(
    response: &Response,
    _: &Context,
) -> Result<NodeConfiguration, ApiError> {
    let c: wire::NodeConfiguration = data(response)?;
    let facts: wire::MilestoneFacts = serde_json::from_str(c.constants.get())
        .map_err(|e| ApiError::bad(response.status(), format!("constants: {e}")))?;
    let fees = c.pool.dynamic_fees;
    let mut addon_bytes: Vec<(TxKind, u64)> = fees
        .addon_bytes
        .0
        .into_iter()
        .filter_map(|(key, bytes)| kind_of_key(&key).map(|kind| (kind, bytes)))
        .collect();
    addon_bytes.sort_by_key(|(kind, _)| wire_type(*kind));
    Ok(NodeConfiguration {
        core_version: c.core.and_then(|v| v.version).unwrap_or_default(),
        network: NetworkIdentity {
            nethash: c.nethash,
            network_byte: c.version,
            slip44: c.slip44,
            wif: c.wif,
        },
        token: TokenLabels {
            name: c.token,
            symbol: c.symbol,
        },
        explorer: c.explorer.filter(|e| !e.is_empty()),
        seats: facts.active_delegates,
        block_time: facts.block_time,
        milestone_json: raw_text(&c.constants),
        pool: PoolLimits {
            max_transactions_in_pool: c.pool.max_transactions_in_pool,
            max_transactions_per_sender: c.pool.max_transactions_per_sender,
            max_transactions_per_request: c.pool.max_transactions_per_request,
            max_transaction_age: c.pool.max_transaction_age,
            max_transaction_bytes: c.pool.max_transaction_bytes,
        },
        pool_fees: PoolFees {
            dynamic: fees.enabled,
            min_fee_pool: if fees.enabled {
                fees.min_fee_pool.unwrap_or(0)
            } else {
                0
            },
            min_fee_broadcast: if fees.enabled {
                fees.min_fee_broadcast.unwrap_or(0)
            } else {
                0
            },
            addon_bytes: if fees.enabled {
                addon_bytes
            } else {
                Vec::new()
            },
        },
    })
}

pub(crate) fn crypto_configuration(
    response: &Response,
    _: &Context,
) -> Result<CryptoConfiguration, ApiError> {
    let c: wire::CryptoConfiguration = data(response)?;
    let network: wire::NetworkFacts = serde_json::from_str(c.network.get())
        .map_err(|e| ApiError::bad(response.status(), format!("network: {e}")))?;
    Ok(CryptoConfiguration {
        nethash: network.nethash,
        network_byte: network.pub_key_hash,
        network_json: raw_text(&c.network),
        milestones_json: raw_text(&c.milestones),
        genesis_block_json: raw_text(&c.genesis_block),
        exceptions_json: c.exceptions.as_deref().map(raw_text),
    })
}

pub(crate) fn supply(response: &Response, _: &Context) -> Result<Supply, ApiError> {
    let b: wire::Blockchain = data(response)?;
    Ok(Supply {
        height: b.block.height,
        block_id: b.block.id,
        supply: b.supply.0,
        burned: Burned {
            fees: b.burned.fees.0,
            transactions: b.burned.transactions.0,
            total: b.burned.total.0,
        },
    })
}

/// The reference implementation's handler keys and their wire types.
const TYPE_KEYS: [(&str, u32, u16); 13] = [
    ("legacyTransfer", 1, 0),
    ("secondSignature", 1, 1),
    ("delegateRegistration", 1, 2),
    ("legacyVote", 1, 3),
    ("multiSignature", 1, 4),
    ("ipfs", 1, 5),
    ("transfer", 1, 6),
    ("delegateResignation", 1, 7),
    ("htlcLock", 1, 8),
    ("htlcClaim", 1, 9),
    ("htlcRefund", 1, 10),
    ("burn", 2, 0),
    ("vote", 2, 2),
];

/// The kind of a reference implementation handler key (`transfer`, `delegateRegistration`, ...).
fn kind_of_key(key: &str) -> Option<TxKind> {
    TYPE_KEYS
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|&(_, group, id)| kind_of(group, id))
}

pub(crate) fn kind_of(type_group: u32, type_id: u16) -> TxKind {
    match (type_group, type_id) {
        (1, 6) => TxKind::Transfer,
        (2, 2) => TxKind::Vote,
        (2, 0) => TxKind::Burn,
        (1, 1) => TxKind::RegisterSecondKey,
        (1, 2) => TxKind::RegisterValidator,
        (1, 7) => TxKind::ResignValidator,
        _ => TxKind::Other {
            type_group,
            type_id,
        },
    }
}

/// The wire type of a kind the SDK models.
pub(crate) fn wire_type(kind: TxKind) -> (u32, u16) {
    match kind {
        TxKind::Transfer => (1, 6),
        TxKind::Vote => (2, 2),
        TxKind::Burn => (2, 0),
        TxKind::RegisterSecondKey => (1, 1),
        TxKind::RegisterValidator => (1, 2),
        TxKind::ResignValidator => (1, 7),
        TxKind::Other {
            type_group,
            type_id,
        } => (type_group, type_id),
    }
}

/// Statistics of handler keys this client does not know are left out: they belong to no kind.
pub(crate) fn fee_statistics(response: &Response, _: &Context) -> Result<FeeStatistics, ApiError> {
    let s: wire::FeeStatisticsBody = body(response)?;
    let mut entries = Vec::new();
    for (group_key, figures_by_key) in s.data.0 {
        let group: u32 = group_key
            .parse()
            .map_err(|_| ApiError::bad(response.status(), format!("type group {group_key:?}")))?;
        for (key, f) in figures_by_key.0 {
            let Some(&(_, type_group, type_id)) =
                TYPE_KEYS.iter().find(|(k, g, _)| *k == key && *g == group)
            else {
                continue;
            };
            entries.push(FeeStatistic {
                kind: kind_of(type_group, type_id),
                avg: f.avg.0,
                min: f.min.0,
                max: f.max.0,
                sum: f.sum.0,
                burned: f.burned.0,
            });
        }
    }
    Ok(FeeStatistics {
        days: s.meta.and_then(|m| m.days),
        entries,
    })
}

// ------------------------------------------------------------------------------------------------
// Accounts

fn account(w: wire::Wallet) -> Result<AccountInfo, String> {
    let vote = w
        .voting_for
        .0
        .into_iter()
        .map(|(validator, v)| {
            let basis_points = percent_to_basis_points_exact(&v.percent)?;
            let basis_points = u16::try_from(basis_points)
                .map_err(|_| format!("vote share {basis_points} basis points is above 10,000"))?;
            Ok(VoteEntry {
                validator,
                basis_points,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(AccountInfo {
        nonce: to_u64(w.nonce.0, "nonce")?,
        balances: vec![Balance {
            asset: AssetId::ROOT,
            amount: w.balance.0,
        }],
        address: w.address,
        public_key: w.public_key,
        vote,
        second_public_key: w.attributes.second_public_key,
        validator_name: w.attributes.delegate.map(|d| d.username),
    })
}

pub(crate) fn account_info(response: &Response, _: &Context) -> Result<AccountInfo, ApiError> {
    let w: wire::Wallet = data(response)?;
    mapped(response, w, account)
}

pub(crate) fn account_page(
    response: &Response,
    context: &Context,
) -> Result<Page<AccountInfo>, ApiError> {
    page(response, context, account)
}

// ------------------------------------------------------------------------------------------------
// Transactions

fn asset<T: DeserializeOwned>(t: &wire::Transaction, what: &str) -> Result<T, String> {
    let raw = t
        .asset
        .as_deref()
        .ok_or_else(|| format!("transaction {} has no {what} asset", t.id))?;
    serde_json::from_str(raw.get()).map_err(|e| format!("transaction {}: {what} asset: {e}", t.id))
}

fn details(t: &wire::Transaction) -> Result<TxDetails, String> {
    Ok(match kind_of(t.type_group, t.type_id) {
        TxKind::Transfer => {
            let a: wire::TransferAsset = asset(t, "transfer")?;
            TxDetails::Transfer {
                recipients: a
                    .transfers
                    .into_iter()
                    .map(|p| Payment {
                        address: p.recipient_id,
                        amount: p.amount.0,
                    })
                    .collect(),
            }
        }
        TxKind::Vote => {
            let a: wire::VoteAsset = asset(t, "vote")?;
            TxDetails::Vote {
                entries: a
                    .votes
                    .0
                    .into_iter()
                    .map(|(validator, percent)| {
                        let bp = percent_to_basis_points_exact(&percent)?;
                        let basis_points = u16::try_from(bp)
                            .map_err(|_| format!("vote share {bp} basis points is above 10,000"))?;
                        Ok(VoteEntry {
                            validator,
                            basis_points,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            }
        }
        TxKind::Burn => TxDetails::Burn {
            amount: t.amount.unwrap_or_default().0,
        },
        TxKind::RegisterSecondKey => {
            let a: wire::SecondKeyAsset = asset(t, "second key")?;
            TxDetails::RegisterSecondKey {
                public_key: a.signature.public_key,
            }
        }
        TxKind::RegisterValidator => {
            let a: wire::RegistrationAsset = asset(t, "registration")?;
            TxDetails::RegisterValidator {
                name: a.delegate.username,
            }
        }
        TxKind::ResignValidator => {
            // A temporary resignation carries no asset: its type, 0, is the default.
            let kind = match &t.asset {
                Some(_) => asset::<wire::ResignationAsset>(t, "resignation")?.resignation_type,
                None => None,
            };
            TxDetails::ResignValidator {
                resignation: match kind.unwrap_or(0) {
                    0 => Resignation::Temporary,
                    1 => Resignation::Permanent,
                    2 => Resignation::Revoke,
                    other => return Err(format!("transaction {}: resignation type {other}", t.id)),
                },
            }
        }
        TxKind::Other {
            type_group,
            type_id,
        } => TxDetails::Other {
            type_group,
            type_id,
            asset_json: t.asset.as_deref().map(raw_text),
        },
    })
}

fn transaction(t: wire::Transaction, context: &Context) -> Result<TxRecord, String> {
    let details = details(&t)?;
    let sender = t
        .sender
        .ok_or_else(|| format!("transaction {} has no sender", t.id))?;
    let block = match (t.block_id, t.block_height) {
        (Some(id), Some(height)) => Some(TxBlock {
            id,
            height,
            confirmations: t.confirmations.unwrap_or(0),
            time: t.timestamp.map(timestamp),
        }),
        (None, None) => None,
        _ => return Err(format!("transaction {} has half a block reference", t.id)),
    };
    let nonce = t
        .nonce
        .ok_or_else(|| format!("transaction {} has no nonce", t.id))?;
    let mut record = TxRecord {
        status: if block.is_some() {
            TxStatus::Confirmed
        } else {
            TxStatus::Pending
        },
        block,
        direction: None,
        sender,
        sender_public_key: t.sender_public_key,
        nonce: to_u64(nonce.0, "nonce")?,
        fee: t.fee.0,
        burned_fee: t.burned_fee.map(|u| u.0),
        memo: t.memo.filter(|m| !m.is_empty()),
        second_signed: t.sign_signature.is_some() || t.second_signature.is_some(),
        version: t
            .version
            .ok_or_else(|| format!("transaction {} has no version", t.id))?,
        details,
        id: t.id,
    };
    if let Some(account) = &context.account {
        record.direction = Some(record.direction_for(account));
    }
    Ok(record)
}

pub(crate) fn transaction_optional(
    response: &Response,
    context: &Context,
) -> Result<Option<TxRecord>, ApiError> {
    match optional_data::<wire::Transaction>(response)? {
        Some(t) => mapped(response, t, |t| transaction(t, context)).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn transaction_page(
    response: &Response,
    context: &Context,
) -> Result<Page<TxRecord>, ApiError> {
    page(response, context, |t| transaction(t, context))
}

fn reject_reason(code: &str, message: &str) -> RejectReason {
    match code {
        "ERR_LOW_FEE" => RejectReason::LowFee,
        "ERR_DUPLICATE" | "ERR_COOLDOWN" => RejectReason::Duplicate,
        "ERR_TOO_LARGE" => RejectReason::TooLarge,
        "ERR_POOL_FULL" | "ERR_EXCEEDS_MAX_COUNT" => RejectReason::PoolFull,
        "ERR_WRONG_NETWORK" => RejectReason::WrongNetwork,
        "ERR_BAD_DATA" => RejectReason::Invalid,
        "ERR_APPLY" => {
            if message.contains("Cannot apply a transaction with nonce") {
                RejectReason::Nonce
            } else if message.contains("Insufficient balance")
                || message.contains("not allowed to spend before funding is confirmed")
            {
                RejectReason::Balance
            } else if message.contains("Transaction fee is too low") {
                RejectReason::LowFee
            } else {
                RejectReason::Invalid
            }
        }
        _ => RejectReason::Other,
    }
}

/// Maps the pool's answer to one outcome per submitted transaction, in submission order.
///
/// The node reports a transaction under the id it computed. For a transaction whose content does
/// not match its id (a corrupted signature, for example) that id differs from the submitted one;
/// such rejections are matched to the unreported transactions in submission order, which is the
/// order the node processed them in.
pub(crate) fn submit_report(
    response: &Response,
    context: &Context,
) -> Result<SubmitReport, ApiError> {
    let result: wire::StoreResult = body(response)?;
    let errors = result.errors.map(|e| e.0).unwrap_or_default();
    let submitted = &context.ids;
    let keys_of = |index: usize, id: &str, key: &str| key == id || key == index.to_string();
    let is_submitted = |key: &str| {
        submitted
            .iter()
            .enumerate()
            .any(|(i, id)| keys_of(i, id, key))
    };
    let rejection = |key: &str| match errors.iter().find(|(k, _)| k == key) {
        Some((_, e)) => SubmitStatus::Rejected {
            reason: reject_reason(&e.code, &e.message),
            node_code: e.code.clone(),
            message: e.message.clone(),
        },
        None => SubmitStatus::Rejected {
            reason: RejectReason::Other,
            node_code: String::new(),
            message: String::new(),
        },
    };

    let mut statuses: Vec<Option<SubmitStatus>> = Vec::with_capacity(submitted.len());
    for (index, id) in submitted.iter().enumerate() {
        let status = if result.data.accept.iter().any(|a| a == id) {
            Some(SubmitStatus::Accepted {
                broadcast: result.data.broadcast.iter().any(|b| b == id),
            })
        } else if let Some((key, _)) = errors.iter().find(|(k, _)| keys_of(index, id, k)) {
            Some(rejection(key))
        } else {
            result
                .data
                .invalid
                .iter()
                .chain(&result.data.excess)
                .find(|k| keys_of(index, id, k))
                .map(|key| rejection(key))
        };
        statuses.push(status);
    }

    let unreported: Vec<usize> = (0..statuses.len())
        .filter(|&i| statuses.get(i).is_some_and(Option::is_none))
        .collect();
    if !unreported.is_empty() {
        if let Some(other) = result.data.accept.iter().find(|a| !is_submitted(a)) {
            return Err(ApiError::bad(
                response.status(),
                format!(
                    "the node accepted transaction {other}, which does not match a submitted id"
                ),
            ));
        }
        let unknown: Vec<&String> = result
            .data
            .invalid
            .iter()
            .filter(|k| !is_submitted(k))
            .collect();
        if unknown.len() != unreported.len() {
            let first = unreported
                .first()
                .and_then(|&i| submitted.get(i))
                .map_or("", String::as_str);
            return Err(ApiError::bad(
                response.status(),
                format!("the node did not report transaction {first}"),
            ));
        }
        for (&slot, key) in unreported.iter().zip(unknown) {
            if let Some(status) = statuses.get_mut(slot) {
                *status = Some(rejection(key));
            }
        }
    }

    let outcomes = submitted
        .iter()
        .zip(statuses)
        .filter_map(|(id, status)| {
            status.map(|status| SubmitOutcome {
                id: id.clone(),
                status,
            })
        })
        .collect();
    Ok(SubmitReport { outcomes })
}

// ------------------------------------------------------------------------------------------------
// Blocks

fn block(b: wire::Block) -> Result<BlockInfo, String> {
    let mut donations: Vec<Donation> = b
        .forged
        .donations
        .0
        .into_iter()
        .map(|(address, amount)| Donation {
            address,
            amount: amount.0,
        })
        .collect();
    donations.sort_by(|x, y| x.address.cmp(&y.address));
    let previous = b
        .previous
        .filter(|p| !p.is_empty() && !p.bytes().all(|c| c == b'0'));
    Ok(BlockInfo {
        id: b.id,
        height: b.height,
        version: b.version,
        previous,
        producer_name: b.generator.username,
        producer_public_key: b.generator.public_key,
        reward: b.forged.reward.0,
        donations,
        total_fee: b.forged.fee.0,
        burned_fee: b.forged.burned_fee.0,
        total_amount: b.forged.amount.0,
        producer_earned: b.forged.total.0,
        transaction_count: b.transactions,
        payload_hash: b.payload.hash,
        payload_length: b.payload.length,
        signature: b.signature,
        confirmations: b.confirmations,
        time: timestamp(b.timestamp),
    })
}

pub(crate) fn block_info(response: &Response, _: &Context) -> Result<BlockInfo, ApiError> {
    let b: wire::Block = data(response)?;
    mapped(response, b, block)
}

pub(crate) fn block_optional(
    response: &Response,
    _: &Context,
) -> Result<Option<BlockInfo>, ApiError> {
    match optional_data::<wire::Block>(response)? {
        Some(b) => mapped(response, b, block).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn block_page(
    response: &Response,
    context: &Context,
) -> Result<Page<BlockInfo>, ApiError> {
    page(response, context, block)
}

pub(crate) fn missed_page(
    response: &Response,
    context: &Context,
) -> Result<Page<MissedSlot>, ApiError> {
    page(response, context, |m: wire::MissedBlock| {
        Ok(MissedSlot {
            height: m.height,
            time: timestamp(m.timestamp),
            validator: m.username,
        })
    })
}

// ------------------------------------------------------------------------------------------------
// Validators and rounds

fn validator(d: wire::Delegate, seats: u32) -> Result<ValidatorInfo, String> {
    let status = if d.is_resigned {
        match d.resignation_type.as_deref() {
            Some("permanent") => ValidatorStatus::ResignedPermanent,
            _ => ValidatorStatus::ResignedTemporary,
        }
    } else {
        match d.rank {
            Some(rank) if rank >= 1 && rank <= seats => ValidatorStatus::Active,
            _ => ValidatorStatus::Standby,
        }
    };
    let productivity_basis_points = match &d.blocks.productivity {
        Some(p) => Some(
            u16::try_from(percent_to_basis_points_rounded(p)?)
                .map_err(|_| format!("productivity {p} is above 100 %"))?,
        ),
        None => None,
    };
    let last_block = d.blocks.last.map(|last| match last {
        wire::LastBlockRef::Id(id) => LastBlock {
            id,
            height: None,
            time: None,
        },
        wire::LastBlockRef::Full {
            id,
            height,
            timestamp: t,
        } => LastBlock {
            id,
            height,
            time: t.map(timestamp),
        },
    });
    Ok(ValidatorInfo {
        vote_share_basis_points: percent_to_basis_points_rounded(&d.votes_received.percent)?,
        name: d.username,
        address: d.address,
        public_key: d.public_key,
        rank: d.rank,
        status,
        vote_weight: d.votes_received.votes.0,
        voters: d.votes_received.voters,
        production: crate::types::Production {
            produced: d.blocks.produced,
            missed: d.blocks.missed.unwrap_or(0),
            productivity_basis_points,
            last_block,
        },
        earnings: Earnings {
            rewards: d.forged.rewards.0,
            fees: d.forged.fees.0,
            burned_fees: d.forged.burned_fees.0,
            donations: d.forged.donations.0,
            total: d.forged.total.0,
        },
        version: d.version,
    })
}

pub(crate) fn validator_optional(
    response: &Response,
    context: &Context,
) -> Result<Option<ValidatorInfo>, ApiError> {
    match optional_data::<wire::Delegate>(response)? {
        Some(d) => mapped(response, d, |d| validator(d, context.seats)).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn validator_page(
    response: &Response,
    context: &Context,
) -> Result<Page<ValidatorInfo>, ApiError> {
    page(response, context, |d| validator(d, context.seats))
}

pub(crate) fn resolved_name(
    response: &Response,
    context: &Context,
) -> Result<Option<ResolvedName>, ApiError> {
    let Some(d) = optional_data::<wire::Delegate>(response)? else {
        return Ok(None);
    };
    // The route also finds validators by address or public key; a name resolves only by name.
    if context.name.as_deref() != Some(d.username.as_str()) {
        return Ok(None);
    }
    Ok(Some(ResolvedName {
        name: d.username,
        address: d.address,
        public_key: d.public_key,
    }))
}

pub(crate) fn round_validators(
    response: &Response,
    _: &Context,
) -> Result<Vec<RoundValidator>, ApiError> {
    let seats: Vec<wire::RoundDelegate> = data(response)?;
    Ok(seats
        .into_iter()
        .map(|s| RoundValidator {
            public_key: s.public_key,
            vote_weight: s.votes.0,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(text: &str) -> serde_json::Number {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn exact_basis_points() {
        assert_eq!(percent_to_basis_points_exact(&num("50")).unwrap(), 5000);
        assert_eq!(percent_to_basis_points_exact(&num("18.1")).unwrap(), 1810);
        assert_eq!(percent_to_basis_points_exact(&num("0.01")).unwrap(), 1);
        assert_eq!(percent_to_basis_points_exact(&num("100")).unwrap(), 10000);
        assert_eq!(percent_to_basis_points_exact(&num("0")).unwrap(), 0);
        assert_eq!(percent_to_basis_points_exact(&num("0.0")).unwrap(), 0);
        assert_eq!(percent_to_basis_points_exact(&num("1.5e1")).unwrap(), 1500);
        assert!(percent_to_basis_points_exact(&num("18.105")).is_err());
        assert!(percent_to_basis_points_exact(&num("-1")).is_err());
        assert!(percent_to_basis_points_exact(&num("1e300")).is_err());
    }

    #[test]
    fn rounded_basis_points() {
        assert_eq!(percent_to_basis_points_rounded(&num("1.234")).unwrap(), 123);
        assert_eq!(percent_to_basis_points_rounded(&num("1.235")).unwrap(), 124);
        assert_eq!(
            percent_to_basis_points_rounded(&num("99.99")).unwrap(),
            9999
        );
        assert_eq!(percent_to_basis_points_rounded(&num("1e-7")).unwrap(), 0);
        assert_eq!(percent_to_basis_points_rounded(&num("0.005")).unwrap(), 1);
    }

    #[test]
    fn reasons() {
        assert_eq!(reject_reason("ERR_LOW_FEE", ""), RejectReason::LowFee);
        assert_eq!(reject_reason("ERR_COOLDOWN", ""), RejectReason::Duplicate);
        assert_eq!(
            reject_reason(
                "ERR_APPLY",
                "x cannot be applied: Cannot apply a transaction with nonce 12: the sender has nonce 2"
            ),
            RejectReason::Nonce
        );
        assert_eq!(
            reject_reason(
                "ERR_APPLY",
                "x cannot be applied: Insufficient balance in the wallet"
            ),
            RejectReason::Balance
        );
        assert_eq!(
            reject_reason(
                "ERR_APPLY",
                "x cannot be applied: Failed to apply transaction"
            ),
            RejectReason::Invalid
        );
        assert_eq!(
            reject_reason("ERR_EXCEEDS_MAX_COUNT", ""),
            RejectReason::PoolFull
        );
        assert_eq!(
            reject_reason("ERR_WRONG_NETWORK", ""),
            RejectReason::WrongNetwork
        );
        assert_eq!(reject_reason("ERR_OTHER", ""), RejectReason::Other);
    }

    #[test]
    fn type_table_round_trips() {
        for (_, group, id) in TYPE_KEYS {
            assert_eq!(wire_type(kind_of(group, id)), (group, id));
        }
    }
}
