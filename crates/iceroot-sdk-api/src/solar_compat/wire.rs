//! The reference implementation's REST API resources, as served under its `/api` base path.
//!
//! These types mirror the JSON exactly and stay private to the crate: the public API is the
//! IceRoot-shaped model in [`crate::types`], which the mappers in `map.rs` fill from them. Unknown
//! fields are ignored, so additive changes on the node do not break the client.

use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

/// `{ "data": T }`.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope<T> {
    pub data: T,
}

/// `{ "meta": { ... }, "data": [T] }`, the paginated envelope.
#[derive(Debug, Deserialize)]
pub(crate) struct Paged<T> {
    pub meta: PageMeta,
    pub data: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PageMeta {
    #[serde(default)]
    pub total_count_is_estimate: bool,
    #[serde(default)]
    pub page_count: u32,
    #[serde(default)]
    pub total_count: u64,
    #[serde(default)]
    pub next: Option<String>,
}

/// The error body of a refused request: `{ "statusCode", "error", "message" }`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ErrorBody {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

/// An unsigned integer the API sends either as a decimal string or as a JSON number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Units(pub u128);

impl<'de> Deserialize<'de> for Units {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnitsVisitor;

        impl Visitor<'_> for UnitsVisitor {
            type Value = Units;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a non-negative integer as a number or a decimal string")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Units, E> {
                Ok(Units(u128::from(v)))
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Units, E> {
                Ok(Units(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Units, E> {
                u128::try_from(v)
                    .map(Units)
                    .map_err(|_| E::custom(format!("negative amount {v}")))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Units, E> {
                Err(E::custom(format!("amount {v} is not an integer")))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Units, E> {
                parse_units(v).map(Units).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(UnitsVisitor)
    }
}

/// Parses a decimal string of base units: ASCII digits only, no sign, at most 39 digits.
pub(crate) fn parse_units(text: &str) -> Result<u128, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{text:?} is not a non-negative decimal integer"));
    }
    text.parse::<u128>()
        .map_err(|_| format!("{text:?} is out of range"))
}

/// A JSON object read as a list of entries in the order the node sent them.
#[derive(Debug)]
pub(crate) struct Ordered<V>(pub Vec<(String, V)>);

impl<V> Default for Ordered<V> {
    fn default() -> Self {
        Ordered(Vec::new())
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Ordered<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor<V>(PhantomData<V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for OrderedVisitor<V> {
            type Value = Ordered<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered<V>, A::Error> {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0).min(256));
                while let Some((key, value)) = map.next_entry::<String, V>()? {
                    entries.push((key, value));
                }
                Ok(Ordered(entries))
            }
        }

        deserializer.deserialize_map(OrderedVisitor(PhantomData))
    }
}

/// `{ "epoch", "unix", "human" }`.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct Timestamp {
    pub epoch: u64,
    pub unix: i64,
}

// ------------------------------------------------------------------------------------------------
// Node

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeStatus {
    pub synced: bool,
    pub now: u64,
    #[serde(default)]
    pub blocks_count: i64,
    pub timestamp: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeConfiguration {
    #[serde(default)]
    pub core: Option<CoreVersion>,
    pub nethash: String,
    pub slip44: u32,
    pub wif: u8,
    pub token: String,
    pub symbol: String,
    #[serde(default)]
    pub explorer: Option<String>,
    /// The address network byte (`pubKeyHash`).
    pub version: u8,
    pub constants: Box<RawValue>,
    pub pool: PoolConfiguration,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CoreVersion {
    #[serde(default)]
    pub version: Option<String>,
}

/// The fields of a milestone the client reads itself; the whole milestone stays raw JSON.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MilestoneFacts {
    pub active_delegates: u32,
    pub block_time: u32,
}

// The node drops `false` values from this document, so every boolean defaults to false.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PoolConfiguration {
    #[serde(default)]
    pub dynamic_fees: DynamicFees,
    pub max_transactions_in_pool: u32,
    pub max_transactions_per_sender: u32,
    pub max_transactions_per_request: u32,
    pub max_transaction_age: u32,
    pub max_transaction_bytes: u32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DynamicFees {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub min_fee_pool: Option<u64>,
    #[serde(default)]
    pub min_fee_broadcast: Option<u64>,
    #[serde(default)]
    pub addon_bytes: Ordered<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CryptoConfiguration {
    pub network: Box<RawValue>,
    pub milestones: Box<RawValue>,
    pub genesis_block: Box<RawValue>,
    #[serde(default)]
    pub exceptions: Option<Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkFacts {
    pub nethash: String,
    pub pub_key_hash: u8,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Blockchain {
    pub block: BlockPointer,
    pub burned: Burned,
    pub supply: Units,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BlockPointer {
    pub height: u64,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Burned {
    pub fees: Units,
    pub transactions: Units,
    pub total: Units,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FeeStatisticsBody {
    #[serde(default)]
    pub meta: Option<FeeMeta>,
    pub data: Ordered<Ordered<FeeFigures>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FeeMeta {
    #[serde(default)]
    pub days: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FeeFigures {
    pub avg: Units,
    pub burned: Units,
    pub max: Units,
    pub min: Units,
    pub sum: Units,
}

// ------------------------------------------------------------------------------------------------
// Wallets

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Wallet {
    pub address: String,
    #[serde(default)]
    pub public_key: Option<String>,
    pub balance: Units,
    pub nonce: Units,
    #[serde(default)]
    pub attributes: WalletAttributes,
    #[serde(default)]
    pub voting_for: Ordered<VotingFor>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletAttributes {
    #[serde(default)]
    pub second_public_key: Option<String>,
    #[serde(default)]
    pub delegate: Option<DelegateAttribute>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DelegateAttribute {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VotingFor {
    pub percent: serde_json::Number,
}

// ------------------------------------------------------------------------------------------------
// Transactions

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Transaction {
    pub id: String,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_id: Option<String>,
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(rename = "type")]
    pub type_id: u16,
    pub type_group: u32,
    #[serde(default)]
    pub amount: Option<Units>,
    pub fee: Units,
    #[serde(default)]
    pub burned_fee: Option<Units>,
    /// `sender` in the transformed resource; `senderId` in the raw one.
    #[serde(default, alias = "senderId")]
    pub sender: Option<String>,
    pub sender_public_key: String,
    #[serde(default)]
    pub sign_signature: Option<String>,
    #[serde(default)]
    pub second_signature: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub asset: Option<Box<RawValue>>,
    #[serde(default)]
    pub confirmations: Option<u64>,
    #[serde(default)]
    pub timestamp: Option<Timestamp>,
    #[serde(default)]
    pub nonce: Option<Units>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransferAsset {
    pub transfers: Vec<TransferItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferItem {
    pub amount: Units,
    pub recipient_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VoteAsset {
    pub votes: Ordered<serde_json::Number>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecondKeyAsset {
    pub signature: SecondKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecondKey {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationAsset {
    pub delegate: DelegateAttribute,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResignationAsset {
    #[serde(default)]
    pub resignation_type: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoreResult {
    pub data: StoreLists,
    #[serde(default)]
    pub errors: Option<Ordered<StoreError>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoreLists {
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub broadcast: Vec<String>,
    #[serde(default)]
    pub invalid: Vec<String>,
    #[serde(default)]
    pub excess: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoreError {
    #[serde(rename = "type")]
    pub code: String,
    #[serde(default)]
    pub message: String,
}

// ------------------------------------------------------------------------------------------------
// Blocks

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Block {
    pub id: String,
    pub version: u32,
    pub height: u64,
    #[serde(default)]
    pub previous: Option<String>,
    pub forged: Forged,
    pub payload: Payload,
    pub generator: Generator,
    pub signature: String,
    #[serde(default)]
    pub confirmations: u64,
    pub transactions: u32,
    pub timestamp: Timestamp,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Forged {
    pub reward: Units,
    #[serde(default)]
    pub donations: Ordered<Units>,
    pub fee: Units,
    #[serde(default)]
    pub burned_fee: Units,
    pub amount: Units,
    pub total: Units,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Payload {
    pub hash: String,
    pub length: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Generator {
    #[serde(default)]
    pub username: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MissedBlock {
    pub height: u64,
    pub timestamp: Timestamp,
    pub username: String,
}

// ------------------------------------------------------------------------------------------------
// Delegates (validators) and rounds

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Delegate {
    pub username: String,
    pub address: String,
    pub public_key: String,
    pub votes_received: VotesReceived,
    #[serde(default)]
    pub rank: Option<u32>,
    #[serde(default)]
    pub is_resigned: bool,
    #[serde(default)]
    pub resignation_type: Option<String>,
    pub blocks: DelegateBlocks,
    pub forged: DelegateForged,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VotesReceived {
    pub percent: serde_json::Number,
    pub votes: Units,
    pub voters: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DelegateBlocks {
    #[serde(default)]
    pub produced: u64,
    #[serde(default)]
    pub missed: Option<u64>,
    #[serde(default)]
    pub productivity: Option<serde_json::Number>,
    #[serde(default)]
    pub last: Option<LastBlockRef>,
}

/// The last block of a delegate: the node sends the block id, and some versions an object.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum LastBlockRef {
    Id(String),
    Full {
        id: String,
        #[serde(default)]
        height: Option<u64>,
        #[serde(default)]
        timestamp: Option<Timestamp>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DelegateForged {
    pub fees: Units,
    pub burned_fees: Units,
    pub rewards: Units,
    pub donations: Units,
    pub total: Units,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RoundDelegate {
    pub public_key: String,
    pub votes: Units,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_forms() {
        let parse = |s: &str| serde_json::from_str::<Units>(s).map(|u| u.0);
        assert_eq!(parse("\"1000026\"").unwrap(), 1_000_026);
        assert_eq!(parse("42").unwrap(), 42);
        assert_eq!(parse("\"0\"").unwrap(), 0);
        for bad in [
            "-1", "1.5", "\"-1\"", "\"1.0\"", "\"\"", "\" 1\"", "\"1e3\"", "null", "\"+1\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse(&format!("\"{}\"", u128::MAX)).is_ok());
        assert!(parse(&format!("\"{}0\"", u128::MAX)).is_err());
    }

    #[test]
    fn ordered_keeps_order() {
        let map: Ordered<u8> = serde_json::from_str(r#"{"b":1,"a":2,"c":3}"#).unwrap();
        let keys: Vec<&str> = map.0.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["b", "a", "c"]);
        assert!(serde_json::from_str::<Ordered<u8>>("[1]").is_err());
    }
}
