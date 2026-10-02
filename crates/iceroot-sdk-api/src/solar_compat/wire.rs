//! The reference implementation's REST API resources, as served under its `/api` base path.
//!
//! These types mirror the JSON exactly and stay private to the crate: the public API is the
//! IceRoot-shaped model in [`crate::types`], which the mappers in `map.rs` fill from them. Unknown
//! fields are ignored, so additive changes on the node do not break the client.
//!
//! A body is parsed once into a [`serde_json::Value`], and each resource is read from it by hand
//! ([`FromJson`]). The result is the same as a derived deserializer, but the code is much smaller,
//! which matters in the WebAssembly module every web application loads. The rules match serde's:
//! a missing required field or a value of the wrong type is an error, a missing optional field is
//! absent, and `null` counts as absent for optional fields.

use serde_json::{Map, Number, Value};

/// What was wrong with the node's JSON: the first problem a reader found.
///
/// Readers return `Option` and note the problem here, rather than returning `Result<T, String>`:
/// with a hundred or so fields, carrying an error value through each one costs far more module
/// size than a null check.
#[derive(Debug, Default)]
pub(crate) struct Why(Option<String>);

impl Why {
    /// Notes `problem`, unless an earlier one was noted, and returns `None` for the reader to
    /// pass on.
    #[cold]
    #[inline(never)]
    pub(crate) fn note<T>(&mut self, problem: String) -> Option<T> {
        self.0.get_or_insert(problem);
        None
    }

    /// Adds `context` in front of the noted problem.
    #[cold]
    #[inline(never)]
    fn within(&mut self, context: &str) {
        if let Some(problem) = &mut self.0 {
            problem.insert_str(0, context);
        }
    }

    /// The noted problem.
    pub(crate) fn into_message(self) -> String {
        self.0
            .unwrap_or_else(|| "the answer does not have the documented shape".to_owned())
    }
}

/// A resource read from the node's JSON.
pub(crate) trait FromJson: Sized {
    /// Reads the resource from `value`, or notes what is wrong with it in `why`.
    fn from_json(value: &Value, why: &mut Why) -> Option<Self>;
}

/// Reads `T` from `value`, or says what is wrong.
pub(crate) fn read<T: FromJson>(value: &Value) -> Result<T, String> {
    let mut why = Why::default();
    T::from_json(value, &mut why).ok_or_else(|| why.into_message())
}

/// The fields of a JSON object, named `what` in errors.
pub(crate) struct Fields<'a> {
    map: &'a Map<String, Value>,
    what: &'static str,
}

impl<'a> Fields<'a> {
    /// The object `value`, or `None` when it is not one.
    pub(crate) fn of(value: &'a Value, what: &'static str, why: &mut Why) -> Option<Fields<'a>> {
        match value.as_object() {
            Some(map) => Some(Fields { map, what }),
            None => why.note(format!("{what}: {}", expected("an object", value))),
        }
    }

    // The readers are kept out of line: inlined at each of the hundred or so fields, they would
    // make the WebAssembly module larger for no gain in speed that matters here.

    #[inline(never)]
    fn read<T: FromJson>(&self, key: &str, value: &Value, why: &mut Why) -> Option<T> {
        let read = T::from_json(value, why);
        if read.is_none() {
            why.within(&format!("{}.{key}: ", self.what));
        }
        read
    }

    /// The field `key`, which must be present.
    #[inline(never)]
    pub(crate) fn req<T: FromJson>(&self, key: &str, why: &mut Why) -> Option<T> {
        match self.map.get(key) {
            Some(value) => self.read(key, value, why),
            None => why.note(format!("{}.{key}: missing field", self.what)),
        }
    }

    /// The field `key`, absent or `null` being `None`. `Some(None)` is an absent field;
    /// `None` a field that is present but wrong.
    #[inline(never)]
    pub(crate) fn opt<T: FromJson>(&self, key: &str, why: &mut Why) -> Option<Option<T>> {
        match self.map.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(value) => self.read(key, value, why).map(Some),
        }
    }

    /// The field `key`, absent or `null` being the default.
    #[inline(never)]
    pub(crate) fn or_default<T: FromJson + Default>(&self, key: &str, why: &mut Why) -> Option<T> {
        Some(self.opt(key, why)?.unwrap_or_default())
    }
}

fn expected(what: &str, value: &Value) -> String {
    let found = match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    };
    format!("expected {what}, found {found}")
}

impl FromJson for String {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        match value.as_str() {
            Some(text) => Some(text.to_owned()),
            None => why.note(expected("a string", value)),
        }
    }
}

impl FromJson for bool {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        match value.as_bool() {
            Some(flag) => Some(flag),
            None => why.note(expected("a boolean", value)),
        }
    }
}

impl FromJson for u64 {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        match value.as_u64() {
            Some(number) => Some(number),
            None => why.note(expected("a non-negative integer", value)),
        }
    }
}

impl FromJson for i64 {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        match value.as_i64() {
            Some(number) => Some(number),
            None => why.note(expected("an integer", value)),
        }
    }
}

macro_rules! narrow_integer {
    ($($t:ty),*) => {$(
        impl FromJson for $t {
            fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
                let wide = u64::from_json(value, why)?;
                match <$t>::try_from(wide) {
                    Ok(narrow) => Some(narrow),
                    Err(_) => why.note(format!("{wide} is out of range")),
                }
            }
        }
    )*};
}

narrow_integer!(u8, u16, u32);

impl FromJson for Number {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        match value {
            Value::Number(number) => Some(number.clone()),
            other => why.note(expected("a number", other)),
        }
    }
}

/// A JSON value kept as it is, such as a milestone or a transaction's asset.
impl FromJson for Value {
    fn from_json(value: &Value, _: &mut Why) -> Option<Self> {
        Some(value.clone())
    }
}

impl<T: FromJson> FromJson for Vec<T> {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let Some(items) = value.as_array() else {
            return why.note(expected("an array", value));
        };
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            match T::from_json(item, why) {
                Some(read) => out.push(read),
                None => {
                    why.within(&format!("[{index}]: "));
                    return None;
                }
            }
        }
        Some(out)
    }
}

/// `{ "data": T }`.
#[derive(Debug)]
pub(crate) struct Envelope<T> {
    pub data: T,
}

impl<T: FromJson> FromJson for Envelope<T> {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "body", why)?;
        Some(Envelope {
            data: f.req("data", why)?,
        })
    }
}

/// `{ "meta": { ... }, "data": [T] }`, the paginated envelope.
#[derive(Debug)]
pub(crate) struct Paged<T> {
    pub meta: PageMeta,
    pub data: Vec<T>,
}

impl<T: FromJson> FromJson for Paged<T> {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "body", why)?;
        Some(Paged {
            meta: f.req("meta", why)?,
            data: f.req("data", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PageMeta {
    pub total_count_is_estimate: bool,
    pub page_count: u32,
    pub total_count: u64,
    pub next: Option<String>,
}

impl FromJson for PageMeta {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "meta", why)?;
        Some(PageMeta {
            total_count_is_estimate: f.or_default("totalCountIsEstimate", why)?,
            page_count: f.or_default("pageCount", why)?,
            total_count: f.or_default("totalCount", why)?,
            next: f.opt("next", why)?,
        })
    }
}

/// The error body of a refused request: `{ "statusCode", "error", "message" }`.
#[derive(Debug)]
pub(crate) struct ErrorBody {
    pub error: Option<String>,
    pub message: Option<String>,
}

impl FromJson for ErrorBody {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "error", why)?;
        Some(ErrorBody {
            error: f.opt("error", why)?,
            message: f.opt("message", why)?,
        })
    }
}

/// An unsigned integer the API sends either as a decimal string or as a JSON number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Units(pub u128);

impl FromJson for Units {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let units = match value {
            Value::String(text) => parse_units(text),
            Value::Number(number) => match number.as_u64() {
                Some(v) => Ok(u128::from(v)),
                None if number.as_i64().is_some() => Err(format!("negative amount {number}")),
                None => Err(format!("amount {number} is not an integer")),
            },
            other => Err(expected(
                "a non-negative integer as a number or a decimal string",
                other,
            )),
        };
        match units {
            Ok(units) => Some(Units(units)),
            Err(problem) => why.note(problem),
        }
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

impl<V: FromJson> FromJson for Ordered<V> {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let Some(map) = value.as_object() else {
            return why.note(expected("an object", value));
        };
        let mut entries = Vec::with_capacity(map.len());
        for (key, value) in map {
            match V::from_json(value, why) {
                Some(read) => entries.push((key.clone(), read)),
                None => {
                    why.within(&format!("{key}: "));
                    return None;
                }
            }
        }
        Some(Ordered(entries))
    }
}

/// `{ "epoch", "unix", "human" }`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timestamp {
    pub epoch: u64,
    pub unix: i64,
}

impl FromJson for Timestamp {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "timestamp", why)?;
        Some(Timestamp {
            epoch: f.req("epoch", why)?,
            unix: f.req("unix", why)?,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Node

#[derive(Debug)]
pub(crate) struct NodeStatus {
    pub synced: bool,
    pub now: u64,
    pub blocks_count: i64,
    pub timestamp: i64,
}

impl FromJson for NodeStatus {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "status", why)?;
        Some(NodeStatus {
            synced: f.req("synced", why)?,
            now: f.req("now", why)?,
            blocks_count: f.or_default("blocksCount", why)?,
            timestamp: f.req("timestamp", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct NodeConfiguration {
    pub core: Option<CoreVersion>,
    pub nethash: String,
    pub slip44: u32,
    pub wif: u8,
    pub token: String,
    pub symbol: String,
    pub explorer: Option<String>,
    /// The address network byte (`pubKeyHash`).
    pub version: u8,
    pub constants: Value,
    pub pool: PoolConfiguration,
}

impl FromJson for NodeConfiguration {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "configuration", why)?;
        Some(NodeConfiguration {
            core: f.opt("core", why)?,
            nethash: f.req("nethash", why)?,
            slip44: f.req("slip44", why)?,
            wif: f.req("wif", why)?,
            token: f.req("token", why)?,
            symbol: f.req("symbol", why)?,
            explorer: f.opt("explorer", why)?,
            version: f.req("version", why)?,
            constants: f.req("constants", why)?,
            pool: f.req("pool", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct CoreVersion {
    pub version: Option<String>,
}

impl FromJson for CoreVersion {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "core", why)?;
        Some(CoreVersion {
            version: f.opt("version", why)?,
        })
    }
}

/// The fields of a milestone the client reads itself; the whole milestone stays as JSON.
#[derive(Debug)]
pub(crate) struct MilestoneFacts {
    pub active_delegates: u32,
    pub block_time: u32,
}

impl FromJson for MilestoneFacts {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "constants", why)?;
        Some(MilestoneFacts {
            active_delegates: f.req("activeDelegates", why)?,
            block_time: f.req("blockTime", why)?,
        })
    }
}

// The node drops `false` values from this document, so every boolean defaults to false.
#[derive(Debug)]
pub(crate) struct PoolConfiguration {
    pub dynamic_fees: DynamicFees,
    pub max_transactions_in_pool: u32,
    pub max_transactions_per_sender: u32,
    pub max_transactions_per_request: u32,
    pub max_transaction_age: u32,
    pub max_transaction_bytes: u32,
}

impl FromJson for PoolConfiguration {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "pool", why)?;
        Some(PoolConfiguration {
            dynamic_fees: f.or_default("dynamicFees", why)?,
            max_transactions_in_pool: f.req("maxTransactionsInPool", why)?,
            max_transactions_per_sender: f.req("maxTransactionsPerSender", why)?,
            max_transactions_per_request: f.req("maxTransactionsPerRequest", why)?,
            max_transaction_age: f.req("maxTransactionAge", why)?,
            max_transaction_bytes: f.req("maxTransactionBytes", why)?,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct DynamicFees {
    pub enabled: bool,
    pub min_fee_pool: Option<u64>,
    pub min_fee_broadcast: Option<u64>,
    pub addon_bytes: Ordered<u64>,
}

impl FromJson for DynamicFees {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "dynamicFees", why)?;
        Some(DynamicFees {
            enabled: f.or_default("enabled", why)?,
            min_fee_pool: f.opt("minFeePool", why)?,
            min_fee_broadcast: f.opt("minFeeBroadcast", why)?,
            addon_bytes: f.or_default("addonBytes", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct CryptoConfiguration {
    pub network: Value,
    pub milestones: Value,
    pub genesis_block: Value,
    pub exceptions: Option<Value>,
}

impl FromJson for CryptoConfiguration {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "crypto configuration", why)?;
        Some(CryptoConfiguration {
            network: f.req("network", why)?,
            milestones: f.req("milestones", why)?,
            genesis_block: f.req("genesisBlock", why)?,
            exceptions: f.opt("exceptions", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct NetworkFacts {
    pub nethash: String,
    pub pub_key_hash: u8,
}

impl FromJson for NetworkFacts {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "network", why)?;
        Some(NetworkFacts {
            nethash: f.req("nethash", why)?,
            pub_key_hash: f.req("pubKeyHash", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Blockchain {
    pub block: BlockPointer,
    pub burned: Burned,
    pub supply: Units,
}

impl FromJson for Blockchain {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "blockchain", why)?;
        Some(Blockchain {
            block: f.req("block", why)?,
            burned: f.req("burned", why)?,
            supply: f.req("supply", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct BlockPointer {
    pub height: u64,
    pub id: String,
}

impl FromJson for BlockPointer {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "block", why)?;
        Some(BlockPointer {
            height: f.req("height", why)?,
            id: f.req("id", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Burned {
    pub fees: Units,
    pub transactions: Units,
    pub total: Units,
}

impl FromJson for Burned {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "burned", why)?;
        Some(Burned {
            fees: f.req("fees", why)?,
            transactions: f.req("transactions", why)?,
            total: f.req("total", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FeeStatisticsBody {
    pub meta: Option<FeeMeta>,
    pub data: Ordered<Ordered<FeeFigures>>,
}

impl FromJson for FeeStatisticsBody {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "body", why)?;
        Some(FeeStatisticsBody {
            meta: f.opt("meta", why)?,
            data: f.req("data", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FeeMeta {
    pub days: Option<u32>,
}

impl FromJson for FeeMeta {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "meta", why)?;
        Some(FeeMeta {
            days: f.opt("days", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FeeFigures {
    pub avg: Units,
    pub burned: Units,
    pub max: Units,
    pub min: Units,
    pub sum: Units,
}

impl FromJson for FeeFigures {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "fees", why)?;
        Some(FeeFigures {
            avg: f.req("avg", why)?,
            burned: f.req("burned", why)?,
            max: f.req("max", why)?,
            min: f.req("min", why)?,
            sum: f.req("sum", why)?,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Wallets

#[derive(Debug)]
pub(crate) struct Wallet {
    pub address: String,
    pub public_key: Option<String>,
    pub balance: Units,
    pub nonce: Units,
    pub attributes: WalletAttributes,
    pub voting_for: Ordered<VotingFor>,
}

impl FromJson for Wallet {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "wallet", why)?;
        Some(Wallet {
            address: f.req("address", why)?,
            public_key: f.opt("publicKey", why)?,
            balance: f.req("balance", why)?,
            nonce: f.req("nonce", why)?,
            attributes: f.or_default("attributes", why)?,
            voting_for: f.or_default("votingFor", why)?,
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct WalletAttributes {
    pub second_public_key: Option<String>,
    pub delegate: Option<DelegateAttribute>,
}

impl FromJson for WalletAttributes {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "attributes", why)?;
        Some(WalletAttributes {
            second_public_key: f.opt("secondPublicKey", why)?,
            delegate: f.opt("delegate", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct DelegateAttribute {
    pub username: String,
}

impl FromJson for DelegateAttribute {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "delegate", why)?;
        Some(DelegateAttribute {
            username: f.req("username", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct VotingFor {
    pub percent: Number,
}

impl FromJson for VotingFor {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "votingFor", why)?;
        Some(VotingFor {
            percent: f.req("percent", why)?,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Transactions

#[derive(Debug)]
pub(crate) struct Transaction {
    pub id: String,
    pub block_height: Option<u64>,
    pub block_id: Option<String>,
    pub version: Option<u8>,
    pub type_id: u16,
    pub type_group: u32,
    pub amount: Option<Units>,
    pub fee: Units,
    pub burned_fee: Option<Units>,
    /// `sender` in the transformed resource; `senderId` in the raw one.
    pub sender: Option<String>,
    pub sender_public_key: String,
    pub sign_signature: Option<String>,
    pub second_signature: Option<String>,
    pub memo: Option<String>,
    pub asset: Option<Value>,
    pub confirmations: Option<u64>,
    pub timestamp: Option<Timestamp>,
    pub nonce: Option<Units>,
}

impl FromJson for Transaction {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "transaction", why)?;
        let sender = match f.opt("sender", why)? {
            Some(sender) => Some(sender),
            None => f.opt("senderId", why)?,
        };
        Some(Transaction {
            id: f.req("id", why)?,
            block_height: f.opt("blockHeight", why)?,
            block_id: f.opt("blockId", why)?,
            version: f.opt("version", why)?,
            type_id: f.req("type", why)?,
            type_group: f.req("typeGroup", why)?,
            amount: f.opt("amount", why)?,
            fee: f.req("fee", why)?,
            burned_fee: f.opt("burnedFee", why)?,
            sender,
            sender_public_key: f.req("senderPublicKey", why)?,
            sign_signature: f.opt("signSignature", why)?,
            second_signature: f.opt("secondSignature", why)?,
            memo: f.opt("memo", why)?,
            asset: f.opt("asset", why)?,
            confirmations: f.opt("confirmations", why)?,
            timestamp: f.opt("timestamp", why)?,
            nonce: f.opt("nonce", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct TransferAsset {
    pub transfers: Vec<TransferItem>,
}

impl FromJson for TransferAsset {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "asset", why)?;
        Some(TransferAsset {
            transfers: f.req("transfers", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct TransferItem {
    pub amount: Units,
    pub recipient_id: String,
}

impl FromJson for TransferItem {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "transfer", why)?;
        Some(TransferItem {
            amount: f.req("amount", why)?,
            recipient_id: f.req("recipientId", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct VoteAsset {
    pub votes: Ordered<Number>,
}

impl FromJson for VoteAsset {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "asset", why)?;
        Some(VoteAsset {
            votes: f.req("votes", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct SecondKeyAsset {
    pub public_key: String,
}

impl FromJson for SecondKeyAsset {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "asset", why)?;
        let signature: Value = f.req("signature", why)?;
        let s = Fields::of(&signature, "signature", why)?;
        Some(SecondKeyAsset {
            public_key: s.req("publicKey", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct RegistrationAsset {
    pub delegate: DelegateAttribute,
}

impl FromJson for RegistrationAsset {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "asset", why)?;
        Some(RegistrationAsset {
            delegate: f.req("delegate", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResignationAsset {
    pub resignation_type: Option<u8>,
}

impl FromJson for ResignationAsset {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "asset", why)?;
        Some(ResignationAsset {
            resignation_type: f.opt("resignationType", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct StoreResult {
    pub data: StoreLists,
    pub errors: Option<Ordered<StoreError>>,
}

impl FromJson for StoreResult {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "body", why)?;
        Some(StoreResult {
            data: f.req("data", why)?,
            errors: f.opt("errors", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct StoreLists {
    pub accept: Vec<String>,
    pub broadcast: Vec<String>,
    pub invalid: Vec<String>,
    pub excess: Vec<String>,
}

impl FromJson for StoreLists {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "data", why)?;
        Some(StoreLists {
            accept: f.or_default("accept", why)?,
            broadcast: f.or_default("broadcast", why)?,
            invalid: f.or_default("invalid", why)?,
            excess: f.or_default("excess", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct StoreError {
    pub code: String,
    pub message: String,
}

impl FromJson for StoreError {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "error", why)?;
        Some(StoreError {
            code: f.req("type", why)?,
            message: f.or_default("message", why)?,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Blocks

#[derive(Debug)]
pub(crate) struct Block {
    pub id: String,
    pub version: u32,
    pub height: u64,
    pub previous: Option<String>,
    pub forged: Forged,
    pub payload: Payload,
    pub generator: Generator,
    pub signature: String,
    pub confirmations: u64,
    pub transactions: u32,
    pub timestamp: Timestamp,
}

impl FromJson for Block {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "block", why)?;
        Some(Block {
            id: f.req("id", why)?,
            version: f.req("version", why)?,
            height: f.req("height", why)?,
            previous: f.opt("previous", why)?,
            forged: f.req("forged", why)?,
            payload: f.req("payload", why)?,
            generator: f.req("generator", why)?,
            signature: f.req("signature", why)?,
            confirmations: f.or_default("confirmations", why)?,
            transactions: f.req("transactions", why)?,
            timestamp: f.req("timestamp", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Forged {
    pub reward: Units,
    pub donations: Ordered<Units>,
    pub fee: Units,
    pub burned_fee: Units,
    pub amount: Units,
    pub total: Units,
}

impl FromJson for Forged {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "forged", why)?;
        Some(Forged {
            reward: f.req("reward", why)?,
            donations: f.or_default("donations", why)?,
            fee: f.req("fee", why)?,
            burned_fee: f.or_default("burnedFee", why)?,
            amount: f.req("amount", why)?,
            total: f.req("total", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Payload {
    pub hash: String,
    pub length: u32,
}

impl FromJson for Payload {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "payload", why)?;
        Some(Payload {
            hash: f.req("hash", why)?,
            length: f.req("length", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Generator {
    pub username: Option<String>,
    pub public_key: String,
}

impl FromJson for Generator {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "generator", why)?;
        Some(Generator {
            username: f.opt("username", why)?,
            public_key: f.req("publicKey", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct MissedBlock {
    pub height: u64,
    pub timestamp: Timestamp,
    pub username: String,
}

impl FromJson for MissedBlock {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "missed block", why)?;
        Some(MissedBlock {
            height: f.req("height", why)?,
            timestamp: f.req("timestamp", why)?,
            username: f.req("username", why)?,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Delegates (validators) and rounds

#[derive(Debug)]
pub(crate) struct Delegate {
    pub username: String,
    pub address: String,
    pub public_key: String,
    pub votes_received: VotesReceived,
    pub rank: Option<u32>,
    pub is_resigned: bool,
    pub resignation_type: Option<String>,
    pub blocks: DelegateBlocks,
    pub forged: DelegateForged,
    pub version: Option<String>,
}

impl FromJson for Delegate {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "delegate", why)?;
        Some(Delegate {
            username: f.req("username", why)?,
            address: f.req("address", why)?,
            public_key: f.req("publicKey", why)?,
            votes_received: f.req("votesReceived", why)?,
            rank: f.opt("rank", why)?,
            is_resigned: f.or_default("isResigned", why)?,
            resignation_type: f.opt("resignationType", why)?,
            blocks: f.req("blocks", why)?,
            forged: f.req("forged", why)?,
            version: f.opt("version", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct VotesReceived {
    pub percent: Number,
    pub votes: Units,
    pub voters: u64,
}

impl FromJson for VotesReceived {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "votesReceived", why)?;
        Some(VotesReceived {
            percent: f.req("percent", why)?,
            votes: f.req("votes", why)?,
            voters: f.req("voters", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct DelegateBlocks {
    pub produced: u64,
    pub missed: Option<u64>,
    pub productivity: Option<Number>,
    pub last: Option<LastBlockRef>,
}

impl FromJson for DelegateBlocks {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "blocks", why)?;
        Some(DelegateBlocks {
            produced: f.or_default("produced", why)?,
            missed: f.opt("missed", why)?,
            productivity: f.opt("productivity", why)?,
            last: f.opt("last", why)?,
        })
    }
}

/// The last block of a delegate: the node sends the block id, and some versions an object.
#[derive(Debug)]
pub(crate) enum LastBlockRef {
    Id(String),
    Full {
        id: String,
        height: Option<u64>,
        timestamp: Option<Timestamp>,
    },
}

impl FromJson for LastBlockRef {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        if let Value::String(id) = value {
            return Some(LastBlockRef::Id(id.clone()));
        }
        let f = Fields::of(value, "last", why)?;
        Some(LastBlockRef::Full {
            id: f.req("id", why)?,
            height: f.opt("height", why)?,
            timestamp: f.opt("timestamp", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct DelegateForged {
    pub fees: Units,
    pub burned_fees: Units,
    pub rewards: Units,
    pub donations: Units,
    pub total: Units,
}

impl FromJson for DelegateForged {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "forged", why)?;
        Some(DelegateForged {
            fees: f.req("fees", why)?,
            burned_fees: f.req("burnedFees", why)?,
            rewards: f.req("rewards", why)?,
            donations: f.req("donations", why)?,
            total: f.req("total", why)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct RoundDelegate {
    pub public_key: String,
    pub votes: Units,
}

impl FromJson for RoundDelegate {
    fn from_json(value: &Value, why: &mut Why) -> Option<Self> {
        let f = Fields::of(value, "round delegate", why)?;
        Some(RoundDelegate {
            public_key: f.req("publicKey", why)?,
            votes: f.req("votes", why)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read<T: FromJson>(text: &str) -> Result<T, String> {
        let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        super::read(&value)
    }

    #[test]
    fn units_forms() {
        let parse = |s: &str| read::<Units>(s).map(|u| u.0);
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
        let map: Ordered<u8> = read(r#"{"b":1,"a":2,"c":3}"#).unwrap();
        let keys: Vec<&str> = map.0.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["b", "a", "c"]);
        assert!(read::<Ordered<u8>>("[1]").is_err());
        assert!(read::<Ordered<u8>>(r#"{"a":256}"#).is_err());
    }

    #[test]
    fn fields_follow_serde_rules() {
        let status = read::<NodeStatus>(r#"{"synced":true,"now":5,"timestamp":-3}"#).unwrap();
        assert_eq!(
            (status.now, status.blocks_count, status.timestamp),
            (5, 0, -3)
        );
        let missing = read::<NodeStatus>(r#"{"synced":true,"timestamp":1}"#).unwrap_err();
        assert_eq!(missing, "status.now: missing field");
        let wrong = read::<NodeStatus>(r#"{"synced":1,"now":5,"timestamp":1}"#).unwrap_err();
        assert!(wrong.contains("status.synced"), "{wrong}");
        assert!(read::<NodeStatus>(r#"{"synced":true,"now":5.5,"timestamp":1}"#).is_err());
        assert!(read::<NodeStatus>(r#"{"synced":true,"now":null,"timestamp":1}"#).is_err());
        assert!(read::<Payload>(r#"{"hash":"a","length":4294967296}"#).is_err());

        let raw = read::<Transaction>(
            r#"{"id":"a","type":6,"typeGroup":1,"fee":"1","senderId":"d","senderPublicKey":"02",
                "memo":null}"#,
        )
        .unwrap();
        assert_eq!(raw.sender.as_deref(), Some("d"));
        assert_eq!(raw.memo, None);
        assert!(matches!(
            read::<LastBlockRef>(r#""ab""#).unwrap(),
            LastBlockRef::Id(id) if id == "ab"
        ));
        assert!(matches!(
            read::<LastBlockRef>(r#"{"id":"ab","height":3}"#).unwrap(),
            LastBlockRef::Full {
                height: Some(3),
                ..
            }
        ));
        assert!(read::<LastBlockRef>("3").is_err());
    }
}
