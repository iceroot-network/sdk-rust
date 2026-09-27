//! Transactions: operations, drafts, signing and signed transactions.
//!
//! Building and signing are separate steps. [`Draft::build`] takes an [`Operation`] and the facts
//! only the node knows ([`OnlineFacts`]: the nonce, the height, the sender's second key), resolves
//! the fee, applies every rule and returns a draft whose summary is exactly what will be signed.
//! [`Draft::sign`] then signs it with the sender's account (and its second key, when it has one)
//! and returns a [`SignedTransaction`] with its id, bytes and JSON.
//!
//! A draft can be built where the network is and signed where the key is, such as a sandboxed
//! page or another device: [`Draft::serialize`] writes it with the network's configuration, and
//! [`Draft::deserialize`] reads it back against a profile, refuses another network and recomputes
//! the summary from the transaction's own fields. A signed transaction travels back the same way.
//!
//! The six operations of today's formats are built and signed by `heartwood-crypto`'s
//! transaction builder, so the bytes and ids are the node's own.

mod draft;
mod envelope;
mod signed;

use std::fmt;

use heartwood_crypto::errors::SchemaError;
use heartwood_crypto::identities::{PublicKey, PublicKeyBytes};
use heartwood_crypto::transactions::TransactionType;
use heartwood_crypto::transactions::types::{Asset, ResignationType};
use heartwood_crypto::validation::votes_from_json;
use serde_json::{Map, Value};

pub use self::draft::{Draft, DraftSummary};
pub use self::signed::SignedTransaction;
use crate::address::Address;
use crate::amount::Amount;
use crate::error::{Error, VoteProblem};
use crate::fee::FeeChoice;
use crate::profile::Capability;

/// The kind of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperationKind {
    /// A transfer to one or more recipients.
    Transfer,
    /// A vote for validators, or its withdrawal.
    Vote,
    /// A burn.
    Burn,
    /// The registration of a second key.
    RegisterSecondKey,
    /// A validator registration.
    RegisterValidator,
    /// A validator resignation, or its revoke.
    ResignValidator,
}

impl OperationKind {
    /// Every kind.
    pub const ALL: [OperationKind; 6] = [
        OperationKind::Transfer,
        OperationKind::Vote,
        OperationKind::Burn,
        OperationKind::RegisterSecondKey,
        OperationKind::RegisterValidator,
        OperationKind::ResignValidator,
    ];

    /// The stable string form: `transfer`, `vote`, `burn`, `register-second-key`,
    /// `register-validator` or `resign-validator`.
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationKind::Transfer => "transfer",
            OperationKind::Vote => "vote",
            OperationKind::Burn => "burn",
            OperationKind::RegisterSecondKey => "register-second-key",
            OperationKind::RegisterValidator => "register-validator",
            OperationKind::ResignValidator => "resign-validator",
        }
    }

    /// The capability a network needs for the operation.
    pub const fn capability(self) -> Capability {
        match self {
            OperationKind::Transfer => Capability::Transfer,
            OperationKind::Vote => Capability::Vote,
            OperationKind::Burn => Capability::Burn,
            OperationKind::RegisterSecondKey => Capability::SecondKey,
            OperationKind::RegisterValidator => Capability::ValidatorRegistration,
            OperationKind::ResignValidator => Capability::ValidatorResignation,
        }
    }

    /// The wire type group and type of today's formats.
    pub const fn wire_numbers(self) -> (u32, u16) {
        let kind = self.wire_type();
        (kind.type_group(), kind.type_id())
    }

    /// The operation of the wire type `kind`.
    pub(crate) const fn from_wire_type(kind: TransactionType) -> OperationKind {
        match kind {
            TransactionType::Transfer => OperationKind::Transfer,
            TransactionType::Vote => OperationKind::Vote,
            TransactionType::Burn => OperationKind::Burn,
            TransactionType::SecondSignature => OperationKind::RegisterSecondKey,
            TransactionType::DelegateRegistration => OperationKind::RegisterValidator,
            TransactionType::DelegateResignation => OperationKind::ResignValidator,
        }
    }

    /// The wire type of today's formats.
    pub(crate) const fn wire_type(self) -> TransactionType {
        match self {
            OperationKind::Transfer => TransactionType::Transfer,
            OperationKind::Vote => TransactionType::Vote,
            OperationKind::Burn => TransactionType::Burn,
            OperationKind::RegisterSecondKey => TransactionType::SecondSignature,
            OperationKind::RegisterValidator => TransactionType::DelegateRegistration,
            OperationKind::ResignValidator => TransactionType::DelegateResignation,
        }
    }
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One recipient of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Recipient {
    /// The recipient's address.
    pub address: Address,
    /// The amount, in base units.
    pub amount: Amount,
}

/// One entry of a vote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteEntry {
    /// The validator's name, which is what a vote names.
    pub validator: String,
    /// The share of the vote, in basis points (10,000 is all of it).
    pub basis_points: u16,
}

impl VoteEntry {
    /// The entries of a vote in the relay API's form, a JSON object of validator names and
    /// percentages, read as a node reads a vote: keys that are not validator names are dropped,
    /// every share must be a multiple of 0.01 from 0.01 to 100 (it becomes whole basis points),
    /// and the shares must add up to 100 unless there are none. The entries keep the object's
    /// order.
    pub fn from_percentages(votes: &Map<String, Value>) -> Result<Vec<VoteEntry>, Error> {
        let kept = votes_from_json(votes).map_err(|error| Error::InvalidVote {
            problem: match error {
                SchemaError::VoteSum { basis_points } => VoteProblem::Sum { basis_points },
                SchemaError::Invalid { field, .. } | SchemaError::Missing { field } => {
                    VoteProblem::Percentage {
                        validator: field
                            .strip_prefix("asset.votes['")
                            .and_then(|rest| rest.strip_suffix("']"))
                            .unwrap_or(&field)
                            .to_owned(),
                    }
                }
            },
        })?;
        Ok(kept
            .into_iter()
            .map(|(validator, basis_points)| VoteEntry {
                validator,
                basis_points,
            })
            .collect())
    }
}

/// The kind of a validator resignation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resignation {
    /// A temporary resignation, which can be revoked.
    Temporary,
    /// A permanent resignation.
    Permanent,
    /// The revoke of a temporary resignation.
    Revoke,
}

impl Resignation {
    /// The stable string form: `temporary`, `permanent` or `revoke`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Resignation::Temporary => "temporary",
            Resignation::Permanent => "permanent",
            Resignation::Revoke => "revoke",
        }
    }
}

/// An operation to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// A transfer to one or more recipients.
    Transfer {
        /// The recipients, in order.
        recipients: Vec<Recipient>,
    },
    /// A vote. No entries withdraws the account's vote.
    Vote {
        /// The entries; the SDK puts them in the network's canonical order.
        entries: Vec<VoteEntry>,
    },
    /// A burn of the network's own asset.
    Burn {
        /// The amount to burn.
        amount: Amount,
    },
    /// The registration of a second key, which must then co-sign every transaction.
    RegisterSecondKey {
        /// The second key's compressed public key (33 bytes). A draft refuses bytes that are not a
        /// valid key; a received transaction shows the bytes it carries.
        public_key: PublicKeyBytes,
    },
    /// A validator registration under a name.
    RegisterValidator {
        /// The validator name.
        name: String,
    },
    /// A validator resignation, or its revoke.
    ResignValidator {
        /// The kind of resignation.
        kind: Resignation,
    },
}

impl Operation {
    /// The kind of the operation.
    pub fn kind(&self) -> OperationKind {
        match self {
            Operation::Transfer { .. } => OperationKind::Transfer,
            Operation::Vote { .. } => OperationKind::Vote,
            Operation::Burn { .. } => OperationKind::Burn,
            Operation::RegisterSecondKey { .. } => OperationKind::RegisterSecondKey,
            Operation::RegisterValidator { .. } => OperationKind::RegisterValidator,
            Operation::ResignValidator { .. } => OperationKind::ResignValidator,
        }
    }

    /// The amount the operation moves: the sum of a transfer's amounts, a burn's amount, or zero.
    pub fn total_amount(&self) -> Amount {
        match self {
            Operation::Transfer { recipients } => recipients
                .iter()
                .try_fold(Amount::ZERO, |sum, recipient| {
                    sum.checked_add(recipient.amount)
                })
                .unwrap_or(Amount::from_base_units(u128::MAX)),
            Operation::Burn { amount } => *amount,
            Operation::Vote { .. }
            | Operation::RegisterSecondKey { .. }
            | Operation::RegisterValidator { .. }
            | Operation::ResignValidator { .. } => Amount::ZERO,
        }
    }

    /// The operation that a transaction's fields carry.
    pub(crate) fn from_asset(asset: &Asset) -> Operation {
        match asset {
            Asset::Transfer { transfers } => Operation::Transfer {
                recipients: transfers
                    .iter()
                    .map(|item| Recipient {
                        address: Address::from_inner(item.recipient),
                        amount: Amount::from(item.amount),
                    })
                    .collect(),
            },
            Asset::Vote { votes } => Operation::Vote {
                entries: votes
                    .iter()
                    .map(|(validator, &basis_points)| VoteEntry {
                        validator: validator.clone(),
                        basis_points,
                    })
                    .collect(),
            },
            Asset::Burn { amount } => Operation::Burn {
                amount: Amount::from(*amount),
            },
            Asset::SecondSignature { public_key } => Operation::RegisterSecondKey {
                public_key: *public_key,
            },
            Asset::DelegateRegistration { username } => Operation::RegisterValidator {
                name: username.clone(),
            },
            Asset::DelegateResignation { resignation_type } => Operation::ResignValidator {
                kind: match resignation_type {
                    None | Some(ResignationType::TemporaryResign) => Resignation::Temporary,
                    Some(ResignationType::PermanentResign) => Resignation::Permanent,
                    Some(ResignationType::NotResigned) => Resignation::Revoke,
                },
            },
        }
    }
}

/// A draft to build: the operation, an optional memo and the fee choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftRequest {
    /// The operation.
    pub operation: Operation,
    /// A memo of at most 255 bytes of UTF-8; empty is the same as none.
    pub memo: Option<String>,
    /// How the fee is chosen.
    pub fee: FeeChoice,
}

impl DraftRequest {
    /// A request for `operation` with no memo and the minimum fee.
    pub fn new(operation: Operation) -> DraftRequest {
        DraftRequest {
            operation,
            memo: None,
            fee: FeeChoice::Minimum,
        }
    }
}

/// The facts a draft needs from the node, read when it is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineFacts {
    /// The sender's public key.
    pub sender: PublicKey,
    /// The nonce the transaction carries: the account's current nonce plus one.
    pub nonce: u64,
    /// The height the draft is built for: the next block's.
    pub height: u32,
    /// The sender's registered second key, if it has one; the draft then needs its signature too.
    pub second_key: Option<PublicKey>,
}
