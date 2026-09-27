//! Drafts: transactions built and checked, ready to sign.

use heartwood_crypto::Aux;
use heartwood_crypto::errors::{BuildError, EncodeError, MemoError, SchemaError, SigError};
use heartwood_crypto::identities::PublicKey;
use heartwood_crypto::managers::Params;
use heartwood_crypto::transactions::codec::{SIGNATURE_SIZE, VERSION};
use heartwood_crypto::transactions::serialiser::{SerialiseOptions, serialise, size_limit};
use heartwood_crypto::transactions::types::group2::MAX_VOTE_ASSET_BYTES;
use heartwood_crypto::transactions::types::{
    Asset, Memo, ResignationType, TransactionData, TransferItem, Votes,
};
use heartwood_crypto::transactions::{TransactionBuilder, deserialiser};
use heartwood_crypto::utils::sort_votes::sort_votes;
use heartwood_crypto::validation::{MAX_AMOUNT, Mode, is_delegate_name, validate_transaction};

use super::envelope::{self, Envelope, EnvelopeKind};
use super::signed::SignedTransaction;
use super::{DraftRequest, OnlineFacts, Operation, OperationKind, Resignation};
use crate::address::Address;
use crate::amount::Amount;
use crate::chain::Chain;
use crate::error::{AddressProblem, AmountProblem, Error, TransactionProblem, VoteProblem};
use crate::fee::{self, FeeStatistics, ResolvedFee};
use crate::keys::Account;
use crate::profile::Profile;
use crate::rules::Rules;

/// A transaction built and checked against the rules in force at its height, ready to sign.
#[derive(Debug, Clone)]
pub struct Draft {
    chain: Chain,
    height: u32,
    data: TransactionData,
    unsigned: Vec<u8>,
    fee: ResolvedFee,
    second_key: Option<PublicKey>,
}

/// Everything a review screen shows about a draft. It is computed from the transaction's own
/// fields, so it is what will be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSummary {
    /// The profile id.
    pub profile: String,
    /// The network byte.
    pub network_byte: u8,
    /// The network hash.
    pub nethash: String,
    /// The height the draft is built for.
    pub height: u32,
    /// The operation.
    pub operation: Operation,
    /// The sender.
    pub sender: Address,
    /// The sender's public key.
    pub sender_public_key: PublicKey,
    /// The nonce.
    pub nonce: u64,
    /// The fee and where it comes from.
    pub fee: ResolvedFee,
    /// The memo, if any.
    pub memo: Option<String>,
    /// The amount the operation moves, without the fee.
    pub total_amount: Amount,
    /// The size of the signed transaction in bytes.
    pub size: usize,
    /// Whether the sender's second key must sign too.
    pub second_signature: bool,
}

impl Draft {
    /// Build the draft of `request` on `chain`, with the facts the node reported, and the node's
    /// fee `statistics` when the fee is resolved from them.
    ///
    /// Every rule is applied before anything is signed: recipients, amounts, the memo, the vote,
    /// the name, the size and the fee. A refusal names the rule it breaks.
    pub fn build(
        chain: &Chain,
        request: &DraftRequest,
        facts: &OnlineFacts,
        statistics: Option<&FeeStatistics>,
    ) -> Result<Draft, Error> {
        let kind = request.operation.kind();
        chain.profile().require(kind.capability())?;
        if facts.sender.as_bytes().len() != 33 {
            return Err(Error::InvalidKey);
        }
        let params = chain.params(facts.height);
        let rules = chain.rules(facts.height);
        let asset = asset_of(&request.operation, &rules, chain.network_byte())?;
        let memo = memo_of(request.memo.as_deref())?;
        let mut data = TransactionData {
            version: VERSION,
            network: params.network(),
            kind: kind.wire_type(),
            nonce: facts.nonce,
            sender_public_key: facts.sender.clone(),
            fee: 0,
            memo,
            asset,
            signature: None,
            second_signature: None,
        };
        let unsigned =
            serialise(&data, SerialiseOptions::UNSIGNED, params).map_err(encode_error)?;
        let size = signed_size(unsigned.len(), facts.second_key.is_some(), params)?;
        let fee = fee::resolve(request.fee, kind, size, params, statistics)?;
        data.fee = fee.amount.to_u64().ok_or(Error::InvalidFee {
            reason: "above the largest fee",
        })?;
        Draft::from_data(
            chain.clone(),
            facts.height,
            data,
            fee,
            facts.second_key.clone(),
        )
    }

    /// The draft of the unsigned fields `data`, checked against the rules at `height`.
    fn from_data(
        chain: Chain,
        height: u32,
        data: TransactionData,
        fee: ResolvedFee,
        second_key: Option<PublicKey>,
    ) -> Result<Draft, Error> {
        let params = chain.params(height);
        if data.signature.is_some() || data.second_signature.is_some() {
            return Err(Error::InvalidTransaction {
                problem: TransactionProblem::Signatures,
            });
        }
        let mut checked = data.clone();
        validate_transaction(&mut checked, params, Mode::NonStrict).map_err(schema_error)?;
        if checked != data {
            return Err(Error::InvalidTransaction {
                problem: TransactionProblem::Rules(
                    "the rules would change the transaction".to_owned(),
                ),
            });
        }
        let unsigned =
            serialise(&data, SerialiseOptions::UNSIGNED, params).map_err(encode_error)?;
        signed_size(unsigned.len(), second_key.is_some(), params)?;
        Ok(Draft {
            chain,
            height,
            data,
            unsigned,
            fee,
            second_key,
        })
    }

    /// Everything a review screen shows.
    pub fn summary(&self) -> DraftSummary {
        let operation = self.operation();
        DraftSummary {
            profile: self.chain.profile().id().to_owned(),
            network_byte: self.chain.network_byte(),
            nethash: self.chain.nethash().to_owned(),
            height: self.height,
            total_amount: operation.total_amount(),
            operation,
            sender: self.sender(),
            sender_public_key: self.data.sender_public_key.clone(),
            nonce: self.data.nonce,
            fee: self.fee,
            memo: self.memo().map(str::to_owned),
            size: self.size(),
            second_signature: self.second_key.is_some(),
        }
    }

    /// The operation.
    pub fn operation(&self) -> Operation {
        Operation::from_asset(&self.data.asset)
    }

    /// The operation's kind.
    pub fn kind(&self) -> OperationKind {
        OperationKind::from_wire_type(self.data.kind)
    }

    /// The sender's address.
    pub fn sender(&self) -> Address {
        Address::from_public_key_for_network_byte(
            &self.data.sender_public_key,
            self.chain.network_byte(),
        )
    }

    /// The nonce.
    pub fn nonce(&self) -> u64 {
        self.data.nonce
    }

    /// The fee and where it comes from.
    pub fn fee(&self) -> ResolvedFee {
        self.fee
    }

    /// The memo, if any.
    pub fn memo(&self) -> Option<&str> {
        self.data.memo.as_ref().map(Memo::as_str)
    }

    /// The height the draft is built for.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The size of the signed transaction in bytes: the unsigned bytes and one 64-byte signature
    /// per key that signs.
    pub fn size(&self) -> usize {
        self.unsigned.len() + SIGNATURE_SIZE * (1 + usize::from(self.second_key.is_some()))
    }

    /// The unsigned bytes: what the sender's key signs (after SHA-256).
    pub fn unsigned_bytes(&self) -> &[u8] {
        &self.unsigned
    }

    /// The chain the draft is for.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Sign with the sender's `account`, and with `second` when the sender has a second key.
    /// Each signature takes fresh randomness.
    pub fn sign(
        &self,
        account: &Account,
        second: Option<&Account>,
    ) -> Result<SignedTransaction, Error> {
        self.sign_with(account, second, Aux::random())
    }

    /// [`Draft::sign`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`]
    /// exists, so this is the same as [`Draft::sign`].
    pub fn sign_with(
        &self,
        account: &Account,
        second: Option<&Account>,
        aux: Aux,
    ) -> Result<SignedTransaction, Error> {
        if account.public_key() != &self.data.sender_public_key {
            return Err(Error::WrongKey {
                reason: "the account is not the draft's sender",
            });
        }
        match (&self.second_key, second) {
            (Some(expected), Some(second))
                if second.public_key().to_compressed() == expected.to_compressed() => {}
            (Some(_), Some(_)) => {
                return Err(Error::WrongKey {
                    reason: "the second account is not the sender's second key",
                });
            }
            (Some(_), None) => {
                return Err(Error::WrongKey {
                    reason: "the sender has a second key, which must sign too",
                });
            }
            (None, Some(_)) => {
                return Err(Error::WrongKey {
                    reason: "the sender has no second key",
                });
            }
            (None, None) => {}
        }
        let params = self.chain.params(self.height);
        let builder = builder_of(&self.data);
        let built = match second {
            Some(second) => {
                builder.build_second_signed(account.keys(), aux, second.keys(), aux, params)
            }
            None => builder.build(account.keys(), aux, params),
        };
        let transaction = built.map_err(build_error)?;
        if !transaction.is_verified() {
            return Err(Error::SigningFailed {
                reason: "the signed transaction does not verify".to_owned(),
            });
        }
        let unsigned = serialise(transaction.data(), SerialiseOptions::UNSIGNED, params)
            .map_err(encode_error)?;
        if unsigned != self.unsigned {
            return Err(Error::SigningFailed {
                reason: "the signed transaction differs from the draft".to_owned(),
            });
        }
        Ok(SignedTransaction::new(
            self.chain.clone(),
            self.height,
            transaction,
        ))
    }

    /// The draft as bytes, for signing in another context: versioned, with the profile id, the
    /// network's identity and configuration, the height and the unsigned transaction.
    pub fn serialize(&self) -> Vec<u8> {
        Envelope {
            kind: EnvelopeKind::Draft,
            height: self.height,
            transaction: self.unsigned.clone(),
            fee: Some(self.fee),
            second_key: self.second_key.clone(),
        }
        .encode(&self.chain)
    }

    /// The draft in `bytes`, for `profile`, whose network hash must be pinned. Data made for
    /// another profile or network is refused with [`Error::NetworkMismatch`], and the summary is
    /// computed again from the transaction's own fields.
    pub fn deserialize(bytes: &[u8], profile: &Profile) -> Result<Draft, Error> {
        let (chain, envelope) = envelope::decode(bytes, profile, EnvelopeKind::Draft)?;
        let data = deserialiser::deserialise(&envelope.transaction).map_err(|error| {
            Error::InvalidTransaction {
                problem: super::signed::decode_problem(&error),
            }
        })?;
        // The fee is the transaction's own; only its source is taken from the serialized form.
        // The floor is computed again, as everything else the summary shows.
        let source = envelope
            .fee
            .ok_or_else(|| envelope::invalid("no fee"))?
            .source;
        let fee = ResolvedFee {
            amount: Amount::from(data.fee),
            source,
            floor: None,
        };
        let mut draft = Draft::from_data(chain, envelope.height, data, fee, envelope.second_key)?;
        if draft.unsigned != envelope.transaction {
            return Err(Error::InvalidTransaction {
                problem: TransactionProblem::NotCanonical,
            });
        }
        draft.fee.floor = draft
            .chain
            .fee_floor(draft.kind(), draft.size(), draft.height);
        Ok(draft)
    }
}

/// The size of a signed transaction whose unsigned bytes are `unsigned` long, checked against the
/// size limit.
fn signed_size(unsigned: usize, second: bool, params: &Params) -> Result<usize, Error> {
    let size = unsigned + SIGNATURE_SIZE * (1 + usize::from(second));
    if size > size_limit(params) {
        return Err(Error::InvalidTransaction {
            problem: TransactionProblem::TooLarge,
        });
    }
    Ok(size)
}

/// A 64-bit amount field, checked against the largest amount.
fn amount_field(amount: Amount) -> Result<u64, Error> {
    amount
        .to_u64()
        .filter(|amount| *amount <= MAX_AMOUNT)
        .ok_or(Error::InvalidAmount {
            problem: AmountProblem::TooLarge,
        })
}

/// The asset of `operation`, checked against `rules`.
fn asset_of(operation: &Operation, rules: &Rules, network_byte: u8) -> Result<Asset, Error> {
    match operation {
        Operation::Transfer { recipients } => {
            let count = recipients.len();
            if count < rules.transfer.min_recipients || count == 0 {
                return Err(Error::NoRecipients {
                    minimum: rules.transfer.min_recipients.max(1),
                });
            }
            if count > rules.transfer.max_recipients {
                return Err(Error::TooManyRecipients {
                    count,
                    maximum: rules.transfer.max_recipients,
                });
            }
            let transfers = recipients
                .iter()
                .map(|recipient| {
                    if recipient.address.network_byte() != network_byte {
                        return Err(Error::InvalidAddress {
                            problem: AddressProblem::WrongNetwork {
                                expected: network_byte,
                                actual: recipient.address.network_byte(),
                            },
                        });
                    }
                    if recipient.amount.is_zero() {
                        return Err(Error::InvalidAmount {
                            problem: AmountProblem::Zero,
                        });
                    }
                    Ok(TransferItem {
                        amount: amount_field(recipient.amount)?,
                        recipient: recipient.address.inner(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Asset::Transfer { transfers })
        }
        Operation::Vote { entries } => {
            if entries.len() > rules.vote.max_entries {
                return Err(Error::InvalidVote {
                    problem: VoteProblem::TooManyEntries {
                        count: entries.len(),
                        maximum: rules.vote.max_entries,
                    },
                });
            }
            let mut votes = Votes::with_capacity(entries.len());
            let mut total: u32 = 0;
            for entry in entries {
                let invalid = |problem| Error::InvalidVote { problem };
                if !is_delegate_name(&entry.validator) {
                    return Err(invalid(VoteProblem::Name {
                        validator: entry.validator.clone(),
                    }));
                }
                if entry.basis_points == 0
                    || u32::from(entry.basis_points) > rules.vote.max_basis_points_per_entry
                {
                    return Err(invalid(VoteProblem::Share {
                        validator: entry.validator.clone(),
                        basis_points: entry.basis_points,
                    }));
                }
                if votes
                    .insert(entry.validator.clone(), entry.basis_points)
                    .is_some()
                {
                    return Err(invalid(VoteProblem::Duplicate {
                        validator: entry.validator.clone(),
                    }));
                }
                total += u32::from(entry.basis_points);
            }
            if !votes.is_empty() && total != rules.vote.total_basis_points {
                return Err(Error::InvalidVote {
                    problem: VoteProblem::Sum {
                        basis_points: total,
                    },
                });
            }
            Ok(Asset::Vote {
                votes: sort_votes(&votes),
            })
        }
        Operation::Burn { amount } => {
            if *amount < rules.burn.min_amount {
                return Err(Error::InvalidAmount {
                    problem: AmountProblem::BelowMinimum {
                        minimum: rules.burn.min_amount.base_units(),
                    },
                });
            }
            Ok(Asset::Burn {
                amount: amount_field(*amount)?,
            })
        }
        Operation::RegisterSecondKey { public_key } => {
            public_key.parse().map_err(|_| Error::InvalidKey)?;
            Ok(Asset::SecondSignature {
                public_key: *public_key,
            })
        }
        Operation::RegisterValidator { name } => {
            if !rules.name.is_valid(name) {
                return Err(Error::InvalidName {
                    name: name.clone(),
                    reason: "1 to 20 of a-z, 0-9 and !@$&_., not starting with _ nor only digits",
                });
            }
            Ok(Asset::DelegateRegistration {
                username: name.clone(),
            })
        }
        Operation::ResignValidator { kind } => Ok(Asset::DelegateResignation {
            resignation_type: match kind {
                Resignation::Temporary => None,
                Resignation::Permanent => Some(ResignationType::PermanentResign),
                Resignation::Revoke => Some(ResignationType::NotResigned),
            },
        }),
    }
}

/// The memo of `text`: none when absent or empty.
fn memo_of(text: Option<&str>) -> Result<Option<Memo>, Error> {
    match text {
        None | Some("") => Ok(None),
        Some(text) => Memo::new(text).map(Some).map_err(|error| match error {
            MemoError::TooLong { length } => Error::MemoTooLong {
                bytes: length,
                maximum: Memo::MAX_BYTES,
            },
            MemoError::Empty => Error::MemoTooLong {
                bytes: 0,
                maximum: Memo::MAX_BYTES,
            },
        }),
    }
}

/// The builder that signs `data` exactly: its asset, nonce, fee and memo.
fn builder_of(data: &TransactionData) -> TransactionBuilder {
    let builder = match &data.asset {
        Asset::Transfer { transfers } => TransactionBuilder::transfer(transfers.clone()),
        Asset::SecondSignature { public_key } => TransactionBuilder::second_signature(*public_key),
        Asset::DelegateRegistration { username } => {
            TransactionBuilder::delegate_registration(username)
        }
        Asset::DelegateResignation { resignation_type } => {
            TransactionBuilder::delegate_resignation(*resignation_type)
        }
        Asset::Burn { amount } => TransactionBuilder::burn(*amount),
        Asset::Vote { votes } => TransactionBuilder::vote(votes.clone()),
    };
    let builder = builder.nonce(data.nonce).fee(data.fee);
    match &data.memo {
        Some(memo) => builder.memo(memo.clone()),
        None => builder,
    }
}

/// The SDK error of a refusal by the transaction rules.
pub(crate) fn schema_error(error: SchemaError) -> Error {
    match error {
        SchemaError::VoteSum { basis_points } => Error::InvalidVote {
            problem: VoteProblem::Sum { basis_points },
        },
        SchemaError::Invalid { ref field, .. } if field == "fee" => Error::InvalidFee {
            reason: "below the operation's minimum",
        },
        other => Error::InvalidTransaction {
            problem: TransactionProblem::Rules(other.to_string()),
        },
    }
}

/// The SDK error of a transaction that does not serialise.
pub(crate) fn encode_error(error: EncodeError) -> Error {
    match error {
        EncodeError::TooLarge { .. } => Error::InvalidTransaction {
            problem: TransactionProblem::TooLarge,
        },
        EncodeError::VoteAssetTooLarge { size } => Error::InvalidVote {
            problem: VoteProblem::TooLarge {
                bytes: size,
                maximum: MAX_VOTE_ASSET_BYTES,
            },
        },
        EncodeError::AddressNetwork(error) => Error::InvalidTransaction {
            problem: TransactionProblem::OutOfRange(error.to_string()),
        },
        EncodeError::OutOfRange { field } => Error::InvalidTransaction {
            problem: TransactionProblem::OutOfRange(format!("{field} does not fit its field")),
        },
    }
}

/// The SDK error of a refusal while signing.
fn build_error(error: BuildError) -> Error {
    match error {
        BuildError::Sign(SigError::Randomness) => Error::RandomnessUnavailable,
        BuildError::Schema(error) => schema_error(error),
        BuildError::Encode(error) => encode_error(error),
        other => Error::SigningFailed {
            reason: other.to_string(),
        },
    }
}
