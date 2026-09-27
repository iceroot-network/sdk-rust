//! IceRoot-shaped values returned by the node API client.
//!
//! These types describe accounts, validators, transactions, blocks and node facts in IceRoot's
//! terms, whatever backend served them: a validator is never a "delegate", a validator's name is
//! never a "username", shares are whole basis points and amounts are integers in base units. The
//! module depends on nothing but the standard library, so the SDK's core crate can re-export it
//! unchanged.
//!
//! Addresses and public keys are carried as the text the node reported. They are checked against a
//! network profile by the SDK's core, not here, because this crate knows no address format.

use std::fmt;

/// An amount in base units of an asset.
///
/// Today's devnet counts ROOT in 8-decimal base units that fit in `u64`; IceRoot formats widen
/// amounts to `u128`, which this type already holds, so values never change type between backends.
pub type BaseUnits = u128;

/// Identifies an asset. Assets are always identified by id, never by symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetId([u8; 32]);

impl AssetId {
    /// The native asset, ROOT. A stable constant on every backend.
    pub const ROOT: AssetId = AssetId([0; 32]);

    /// An asset id from its 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        AssetId(bytes)
    }

    /// The 32 bytes of the id.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Whether this is [`AssetId::ROOT`].
    pub fn is_root(self) -> bool {
        self == AssetId::ROOT
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str("ROOT");
        }
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A balance of one asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    /// The asset.
    pub asset: AssetId,
    /// The amount in base units.
    pub amount: BaseUnits,
}

/// A point in chain time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Seconds since the chain's epoch, as recorded in the block header.
    pub chain: u64,
    /// Seconds since the Unix epoch.
    pub unix: i64,
}

/// One page of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The items of this page, in the node's order.
    pub items: Vec<T>,
    /// The page number, starting at 1.
    pub page: u32,
    /// The number of pages the listing had when this page was served.
    pub page_count: u32,
    /// The number of items in the whole listing.
    pub total: u64,
    /// Whether `total` is an estimate (the node may count large listings approximately).
    pub total_is_estimate: bool,
    /// Whether a next page exists.
    pub has_next: bool,
}

impl<T> Page<T> {
    /// Maps every item, keeping the page facts.
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            page: self.page,
            page_count: self.page_count,
            total: self.total,
            total_is_estimate: self.total_is_estimate,
            has_next: self.has_next,
        }
    }
}

/// The node's view of its own progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStatus {
    /// Height of the node's last block.
    pub height: u64,
    /// Whether the node considers itself in sync with its peers.
    pub synced: bool,
    /// How many blocks the node's peers are ahead of it (0 when synced or unknown).
    pub blocks_behind: u64,
    /// The node's current chain time: seconds since the chain's epoch by the node's clock.
    pub chain_time: i64,
}

/// The chain identity a node reports. A network profile pins it, so a node on another chain is
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkIdentity {
    /// The network hash (hex), which is the genesis payload hash on today's devnet.
    pub nethash: String,
    /// The address network byte (90 on devnets, which gives addresses starting with `d`).
    pub network_byte: u8,
    /// The SLIP-44 coin type the network declares.
    pub slip44: u32,
    /// The WIF prefix byte the network declares.
    pub wif: u8,
}

/// The labels a node shows for the native token. Display only: the asset is [`AssetId::ROOT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLabels {
    /// The token's name as configured (for example `dROOT` on devnets).
    pub name: String,
    /// The token's short symbol (for example `dRT` on devnets).
    pub symbol: String,
}

/// The transaction pool's limits, which bound what one submission may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    /// Transactions the pool holds at most.
    pub max_transactions_in_pool: u32,
    /// Transactions one sender may have in the pool at most.
    pub max_transactions_per_sender: u32,
    /// Transactions one submission request may carry at most.
    pub max_transactions_per_request: u32,
    /// Age in blocks after which a pooled transaction expires.
    pub max_transaction_age: u32,
    /// Serialized size in bytes above which the pool refuses a transaction.
    pub max_transaction_bytes: u32,
}

/// The pool's dynamic fee settings. The exact fee floor is computed by the SDK's core from the
/// milestone in force; these figures let it apply the node's own minimum on top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolFees {
    /// Whether dynamic fees are enabled.
    pub dynamic: bool,
    /// Fee per byte-unit the pool requires to admit a transaction (0 when dynamic fees are off).
    pub min_fee_pool: u64,
    /// Fee per byte-unit the node requires to broadcast a transaction (0 when dynamic fees are off).
    pub min_fee_broadcast: u64,
    /// Extra byte-units per transaction kind, in wire type order. Kinds the client does not know
    /// are left out.
    pub addon_bytes: Vec<(TxKind, u64)>,
}

/// A node's configuration: chain identity, token labels, the milestone in force and pool limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfiguration {
    /// Version of the node software.
    pub core_version: String,
    /// The chain identity.
    pub network: NetworkIdentity,
    /// The native token's labels.
    pub token: TokenLabels,
    /// The explorer URL the network declares, if any.
    pub explorer: Option<String>,
    /// Validator seats per round in the milestone at the node's tip.
    pub seats: u32,
    /// Block time in seconds in the milestone at the node's tip.
    pub block_time: u32,
    /// The milestone in force at the node's tip, as JSON text exactly as the node sent it.
    pub milestone_json: String,
    /// The pool's limits.
    pub pool: PoolLimits,
    /// The pool's fee settings.
    pub pool_fees: PoolFees,
}

/// The chain definition a node serves: network, milestones, genesis block and exceptions, each as
/// JSON text exactly as the node sent it, ready for the SDK core's configuration loaders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoConfiguration {
    /// The network hash, read from the network definition.
    pub nethash: String,
    /// The address network byte, read from the network definition.
    pub network_byte: u8,
    /// The network definition.
    pub network_json: String,
    /// The milestone list.
    pub milestones_json: String,
    /// The genesis block.
    pub genesis_block_json: String,
    /// The exceptions, when the node sends them.
    pub exceptions_json: Option<String>,
}

/// Burned amounts since genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Burned {
    /// Burned by the fee burn share.
    pub fees: BaseUnits,
    /// Burned by burn transactions.
    pub transactions: BaseUnits,
    /// The sum of both.
    pub total: BaseUnits,
}

/// The native token's supply at a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supply {
    /// Height of the block the figures belong to.
    pub height: u64,
    /// Id of that block.
    pub block_id: String,
    /// The circulating supply in base units.
    pub supply: BaseUnits,
    /// What has been burned.
    pub burned: Burned,
}

/// Fee figures of one transaction kind over the requested window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeStatistic {
    /// The transaction kind.
    pub kind: TxKind,
    /// Average fee, rounded by the node.
    pub avg: BaseUnits,
    /// Smallest fee.
    pub min: BaseUnits,
    /// Largest fee.
    pub max: BaseUnits,
    /// Sum of fees.
    pub sum: BaseUnits,
    /// Sum of burned fee shares.
    pub burned: BaseUnits,
}

/// The node's fee statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeStatistics {
    /// The window in days, when one was requested.
    pub days: Option<u32>,
    /// One entry per transaction kind the node reports, in the node's order.
    pub entries: Vec<FeeStatistic>,
}

/// One entry of a vote: a validator, named, and its share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteEntry {
    /// The validator's name, which is what a vote carries on the wire.
    pub validator: String,
    /// The share in whole basis points (10,000 is the whole vote).
    pub basis_points: u16,
}

/// An account as the node sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    /// The account's address.
    pub address: String,
    /// The account's public key, once the account has sent a transaction (or is in the genesis).
    pub public_key: Option<String>,
    /// The nonce of the account's last transaction (0 for a fresh account).
    pub nonce: u64,
    /// Balances per asset. On today's devnet there is exactly one entry, ROOT.
    pub balances: Vec<Balance>,
    /// The account's current vote, empty when it does not vote.
    pub vote: Vec<VoteEntry>,
    /// The registered second public key, if any.
    pub second_public_key: Option<String>,
    /// The account's validator name, when the account is a registered validator.
    pub validator_name: Option<String>,
}

impl AccountInfo {
    /// The balance of one asset (0 when the account holds none).
    pub fn balance(&self, asset: AssetId) -> BaseUnits {
        self.balances
            .iter()
            .find(|b| b.asset == asset)
            .map_or(0, |b| b.amount)
    }
}

/// The kind of a transaction, named after the SDK's builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TxKind {
    /// A transfer to one or more recipients.
    Transfer,
    /// A vote, or the withdrawal of a vote.
    Vote,
    /// A burn.
    Burn,
    /// Registration of a second key.
    RegisterSecondKey,
    /// Registration of a validator.
    RegisterValidator,
    /// A validator's resignation, or the revocation of one.
    ResignValidator,
    /// A type the SDK does not model (for example legacy types a node still lists).
    Other {
        /// Wire type group.
        type_group: u32,
        /// Wire type within the group.
        type_id: u16,
    },
}

impl TxKind {
    /// A stable lower-case name: `transfer`, `vote`, `burn`, `register-second-key`,
    /// `register-validator`, `resign-validator` or `other`.
    pub fn as_str(self) -> &'static str {
        match self {
            TxKind::Transfer => "transfer",
            TxKind::Vote => "vote",
            TxKind::Burn => "burn",
            TxKind::RegisterSecondKey => "register-second-key",
            TxKind::RegisterValidator => "register-validator",
            TxKind::ResignValidator => "resign-validator",
            TxKind::Other { .. } => "other",
        }
    }
}

impl fmt::Display for TxKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxKind::Other {
                type_group,
                type_id,
            } => write!(f, "other ({type_group}/{type_id})"),
            kind => f.write_str(kind.as_str()),
        }
    }
}

/// One recipient of a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// The recipient's address.
    pub address: String,
    /// The amount in base units.
    pub amount: BaseUnits,
}

/// What a validator resignation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resignation {
    /// Leaves the ranking until revoked.
    Temporary,
    /// Leaves for good.
    Permanent,
    /// Revokes a temporary resignation.
    Revoke,
}

impl Resignation {
    /// `temporary`, `permanent` or `revoke`.
    pub fn as_str(self) -> &'static str {
        match self {
            Resignation::Temporary => "temporary",
            Resignation::Permanent => "permanent",
            Resignation::Revoke => "revoke",
        }
    }
}

/// The kind-specific content of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxDetails {
    /// A transfer: its recipients in the order the node reported them.
    Transfer {
        /// The recipients.
        recipients: Vec<Payment>,
    },
    /// A vote: the complete new vote; empty withdraws the vote.
    Vote {
        /// The entries in the order the node reported them.
        entries: Vec<VoteEntry>,
    },
    /// A burn of ROOT.
    Burn {
        /// The burned amount.
        amount: BaseUnits,
    },
    /// Registration of a second public key.
    RegisterSecondKey {
        /// The second public key.
        public_key: String,
    },
    /// Registration of a validator under a name.
    RegisterValidator {
        /// The validator's name.
        name: String,
    },
    /// A resignation or its revocation.
    ResignValidator {
        /// What the transaction does.
        resignation: Resignation,
    },
    /// A type the SDK does not model; the content stays as the node's JSON text.
    Other {
        /// Wire type group.
        type_group: u32,
        /// Wire type within the group.
        type_id: u16,
        /// The transaction's `asset` object as JSON text, when present.
        asset_json: Option<String>,
    },
}

impl TxDetails {
    /// The kind these details belong to.
    pub fn kind(&self) -> TxKind {
        match self {
            TxDetails::Transfer { .. } => TxKind::Transfer,
            TxDetails::Vote { .. } => TxKind::Vote,
            TxDetails::Burn { .. } => TxKind::Burn,
            TxDetails::RegisterSecondKey { .. } => TxKind::RegisterSecondKey,
            TxDetails::RegisterValidator { .. } => TxKind::RegisterValidator,
            TxDetails::ResignValidator { .. } => TxKind::ResignValidator,
            TxDetails::Other {
                type_group,
                type_id,
                ..
            } => TxKind::Other {
                type_group: *type_group,
                type_id: *type_id,
            },
        }
    }
}

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TxStatus {
    /// In a node's pool, not yet in a block.
    Pending,
    /// In a block. Where finality exists, "final" is reported separately; today's devnet has none.
    Confirmed,
}

/// A transaction's direction relative to one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxDirection {
    /// The account sent it and is not among its recipients.
    Sent,
    /// The account is a recipient and did not send it.
    Received,
    /// The account sent it to itself.
    ToSelf,
    /// The account neither sent nor received it (for example a vote listed for a validator).
    Other,
}

/// The block that holds a confirmed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBlock {
    /// Block id.
    pub id: String,
    /// Block height.
    pub height: u64,
    /// Confirmations when the node answered (1 in the node's last block).
    pub confirmations: u64,
    /// The block's time, when the node reported it.
    pub time: Option<Timestamp>,
}

/// A transaction as the SDK reports it in histories, lookups and listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRecord {
    /// Transaction id (hex).
    pub id: String,
    /// Pending or confirmed.
    pub status: TxStatus,
    /// The block, when confirmed.
    pub block: Option<TxBlock>,
    /// Direction relative to the account a history was requested for; `None` elsewhere.
    pub direction: Option<TxDirection>,
    /// The sender's address.
    pub sender: String,
    /// The sender's public key.
    pub sender_public_key: String,
    /// The sender's nonce for this transaction.
    pub nonce: u64,
    /// The fee in base units.
    pub fee: BaseUnits,
    /// The burned share of the fee, when the node reported it.
    pub burned_fee: Option<BaseUnits>,
    /// The memo, if any.
    pub memo: Option<String>,
    /// Whether the transaction carries a second signature.
    pub second_signed: bool,
    /// Wire format version.
    pub version: u8,
    /// Kind-specific content.
    pub details: TxDetails,
}

impl TxRecord {
    /// The transaction kind.
    pub fn kind(&self) -> TxKind {
        self.details.kind()
    }

    /// The amount leaving the sender apart from the fee: the sum of a transfer's payments, a burn's
    /// amount, 0 otherwise.
    pub fn amount(&self) -> BaseUnits {
        match &self.details {
            TxDetails::Transfer { recipients } => recipients
                .iter()
                .fold(0u128, |sum, p| sum.saturating_add(p.amount)),
            TxDetails::Burn { amount } => *amount,
            _ => 0,
        }
    }

    /// The amount an account receives from this transaction (the sum of its payments).
    pub fn amount_to(&self, address: &str) -> BaseUnits {
        match &self.details {
            TxDetails::Transfer { recipients } => recipients
                .iter()
                .filter(|p| p.address == address)
                .fold(0u128, |sum, p| sum.saturating_add(p.amount)),
            _ => 0,
        }
    }

    /// The direction of this transaction relative to `address`.
    pub fn direction_for(&self, address: &str) -> TxDirection {
        let sent = self.sender == address;
        let received = match &self.details {
            TxDetails::Transfer { recipients } => recipients.iter().any(|p| p.address == address),
            _ => false,
        };
        match (sent, received) {
            (true, true) => TxDirection::ToSelf,
            (true, false) => TxDirection::Sent,
            (false, true) => TxDirection::Received,
            (false, false) => TxDirection::Other,
        }
    }
}

/// Which way to list an account's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HistoryDirection {
    /// Everything the account sent or received.
    #[default]
    All,
    /// Only what it sent.
    Sent,
    /// Only what it received.
    Received,
}

/// A validator's name resolved to its account. Always carries the address, never a bare name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    /// The name.
    pub name: String,
    /// The account the name points at.
    pub address: String,
    /// The account's public key.
    pub public_key: String,
}

/// A validator's standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorStatus {
    /// Holds a seat: ranked within the seat count.
    Active,
    /// Registered and ranked below the seats, or not ranked yet.
    Standby,
    /// Resigned until a revocation.
    ResignedTemporary,
    /// Resigned for good.
    ResignedPermanent,
}

impl ValidatorStatus {
    /// `active`, `standby`, `resigned-temporary` or `resigned-permanent`.
    pub fn as_str(self) -> &'static str {
        match self {
            ValidatorStatus::Active => "active",
            ValidatorStatus::Standby => "standby",
            ValidatorStatus::ResignedTemporary => "resigned-temporary",
            ValidatorStatus::ResignedPermanent => "resigned-permanent",
        }
    }
}

/// The last block a validator produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastBlock {
    /// Block id.
    pub id: String,
    /// Block height, when the node reported it.
    pub height: Option<u64>,
    /// Block time, when the node reported it.
    pub time: Option<Timestamp>,
}

/// A validator's lifetime production counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Production {
    /// Blocks produced.
    pub produced: u64,
    /// Slots missed (0 when the node reports none).
    pub missed: u64,
    /// Produced against assigned slots in basis points, when the node reports it.
    pub productivity_basis_points: Option<u16>,
    /// The last block produced, if any.
    pub last_block: Option<LastBlock>,
}

/// What a validator has earned since registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Earnings {
    /// Block rewards.
    pub rewards: BaseUnits,
    /// Fees collected.
    pub fees: BaseUnits,
    /// The burned share of those fees.
    pub burned_fees: BaseUnits,
    /// Donations paid out of rewards.
    pub donations: BaseUnits,
    /// Net: rewards plus fees, minus burned fees and donations.
    pub total: BaseUnits,
}

/// A registered validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// The validator's name.
    pub name: String,
    /// The validator's account address.
    pub address: String,
    /// The validator's account public key.
    pub public_key: String,
    /// Rank by vote weight (1 is first); `None` when not ranked (for example after resigning).
    pub rank: Option<u32>,
    /// Active, standby or resigned.
    pub status: ValidatorStatus,
    /// Total vote weight in base units.
    pub vote_weight: BaseUnits,
    /// Vote weight as a share of the supply, in basis points, rounded by the node.
    pub vote_share_basis_points: u32,
    /// Number of voting accounts.
    pub voters: u64,
    /// Production counters.
    pub production: Production,
    /// Earnings since registration.
    pub earnings: Earnings,
    /// The node software version the validator last announced, if any.
    pub version: Option<String>,
}

/// One donation paid out of a block reward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Donation {
    /// The receiving address.
    pub address: String,
    /// The amount in base units.
    pub amount: BaseUnits,
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    /// Block id (hex).
    pub id: String,
    /// Height.
    pub height: u64,
    /// Block format version.
    pub version: u32,
    /// Id of the previous block (`None` for the genesis block).
    pub previous: Option<String>,
    /// The producing validator's name, when it has one.
    pub producer_name: Option<String>,
    /// The producer's public key.
    pub producer_public_key: String,
    /// Block reward.
    pub reward: BaseUnits,
    /// Donations paid out of the reward, sorted by address.
    pub donations: Vec<Donation>,
    /// Sum of fees.
    pub total_fee: BaseUnits,
    /// Burned share of the fees.
    pub burned_fee: BaseUnits,
    /// Sum of amounts moved by the block's transactions.
    pub total_amount: BaseUnits,
    /// What the producer keeps: reward minus donations, plus fees minus the burned share.
    pub producer_earned: BaseUnits,
    /// Number of transactions.
    pub transaction_count: u32,
    /// Payload hash (hex).
    pub payload_hash: String,
    /// Payload length in bytes.
    pub payload_length: u32,
    /// The block signature (hex).
    pub signature: String,
    /// Blocks on top of this one when the node answered.
    pub confirmations: u64,
    /// The block's time.
    pub time: Timestamp,
}

/// Where to find a block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockRef {
    /// By height.
    Height(u64),
    /// By id (hex).
    Id(String),
}

/// A slot a validator missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissedSlot {
    /// The height the block would have had.
    pub height: u64,
    /// The slot's time.
    pub time: Timestamp,
    /// The validator that missed it.
    pub validator: String,
}

/// One seat of a round's validator set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundValidator {
    /// The validator's public key.
    pub public_key: String,
    /// Its vote weight when the round was built.
    pub vote_weight: BaseUnits,
}

/// Why the node, or the client on its behalf, refused a submitted transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectReason {
    /// The fee is below the floor.
    LowFee,
    /// The nonce is not the sender's next one.
    Nonce,
    /// The sender cannot pay.
    Balance,
    /// The transaction is already in the pool, or was just tried.
    Duplicate,
    /// The transaction is malformed, badly signed or breaks a rule.
    Invalid,
    /// The pool, or the sender's share of it, is full.
    PoolFull,
    /// The transaction belongs to another network.
    WrongNetwork,
    /// The transaction exceeds the pool's size limit.
    TooLarge,
    /// Anything else; the node's code says more.
    Other,
}

impl RejectReason {
    /// `low-fee`, `nonce`, `balance`, `duplicate`, `invalid`, `pool-full`, `wrong-network`,
    /// `too-large` or `other`.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::LowFee => "low-fee",
            RejectReason::Nonce => "nonce",
            RejectReason::Balance => "balance",
            RejectReason::Duplicate => "duplicate",
            RejectReason::Invalid => "invalid",
            RejectReason::PoolFull => "pool-full",
            RejectReason::WrongNetwork => "wrong-network",
            RejectReason::TooLarge => "too-large",
            RejectReason::Other => "other",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of submitting one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitStatus {
    /// The pool accepted the transaction.
    Accepted {
        /// Whether the node also relays it to its peers.
        broadcast: bool,
    },
    /// The transaction was refused.
    Rejected {
        /// The normalized reason.
        reason: RejectReason,
        /// The node's own code (for example `ERR_LOW_FEE`), kept for diagnostics.
        node_code: String,
        /// The node's message.
        message: String,
    },
}

/// One transaction's outcome within a submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitOutcome {
    /// The transaction id the outcome belongs to.
    pub id: String,
    /// Accepted or rejected.
    pub status: SubmitStatus,
}

impl SubmitOutcome {
    /// Whether the pool accepted the transaction.
    pub fn is_accepted(&self) -> bool {
        matches!(self.status, SubmitStatus::Accepted { .. })
    }
}

/// The outcomes of a submission, one per transaction, in submission order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubmitReport {
    /// The outcomes.
    pub outcomes: Vec<SubmitOutcome>,
}

impl SubmitReport {
    /// The outcome of one transaction.
    pub fn get(&self, id: &str) -> Option<&SubmitOutcome> {
        self.outcomes.iter().find(|o| o.id == id)
    }

    /// Whether every transaction was accepted.
    pub fn all_accepted(&self) -> bool {
        self.outcomes.iter().all(SubmitOutcome::is_accepted)
    }

    /// Appends the outcomes of another report.
    pub fn extend(&mut self, other: SubmitReport) {
        self.outcomes.extend(other.outcomes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(sender: &str, to: &[(&str, u128)]) -> TxRecord {
        TxRecord {
            id: "00".into(),
            status: TxStatus::Confirmed,
            block: None,
            direction: None,
            sender: sender.into(),
            sender_public_key: "02".into(),
            nonce: 1,
            fee: 10,
            burned_fee: None,
            memo: None,
            second_signed: false,
            version: 3,
            details: TxDetails::Transfer {
                recipients: to
                    .iter()
                    .map(|(a, v)| Payment {
                        address: (*a).into(),
                        amount: *v,
                    })
                    .collect(),
            },
        }
    }

    #[test]
    fn directions_and_amounts() {
        let tx = transfer("A", &[("B", 5), ("A", 7), ("B", 1)]);
        assert_eq!(tx.direction_for("A"), TxDirection::ToSelf);
        assert_eq!(tx.direction_for("B"), TxDirection::Received);
        assert_eq!(tx.direction_for("C"), TxDirection::Other);
        assert_eq!(
            transfer("A", &[("B", 1)]).direction_for("A"),
            TxDirection::Sent
        );
        assert_eq!(tx.amount(), 13);
        assert_eq!(tx.amount_to("B"), 6);
        assert_eq!(tx.kind(), TxKind::Transfer);
    }

    #[test]
    fn names() {
        assert_eq!(AssetId::ROOT.to_string(), "ROOT");
        assert_eq!(AssetId::from_bytes([1; 32]).to_string(), "01".repeat(32));
        assert_eq!(
            TxKind::Other {
                type_group: 1,
                type_id: 5
            }
            .to_string(),
            "other (1/5)"
        );
        assert_eq!(RejectReason::PoolFull.to_string(), "pool-full");
        assert_eq!(
            ValidatorStatus::ResignedTemporary.as_str(),
            "resigned-temporary"
        );
        assert_eq!(Resignation::Revoke.as_str(), "revoke");
    }
}
