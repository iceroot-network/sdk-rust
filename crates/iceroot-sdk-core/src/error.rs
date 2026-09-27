//! Errors: one type for the whole SDK, with a stable code and structured details.
//!
//! Every fallible SDK function returns [`Error`]. Its [`Error::code`] is a stable string that is
//! part of the API (the TypeScript and Go SDKs raise the same codes), [`Error::details`] carries
//! the structured facts as JSON, and the `Display` text is a human message that may change.
//!
//! Error values never contain secrets: a phrase problem names the position of a word, never the
//! word, and no key material appears anywhere.

use std::fmt;

use serde_json::{Value, json};

use crate::profile::Capability;
use crate::transaction::OperationKind;

/// A stable error code. The string form ([`ErrorCode::as_str`]) is part of the SDK's API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// A recovery phrase is not a valid BIP39 English phrase.
    InvalidPhrase,
    /// A recovery phrase has fewer than 18 words.
    PhraseTooShort,
    /// An account or address index is out of range.
    InvalidPath,
    /// An address does not parse, or belongs to another network.
    InvalidAddress,
    /// An amount does not parse or is out of range.
    InvalidAmount,
    /// A public key is not valid.
    InvalidKey,
    /// A memo is longer than the network allows.
    MemoTooLong,
    /// A transfer has no recipient.
    NoRecipients,
    /// A transfer has more recipients than the network allows.
    TooManyRecipients,
    /// A vote breaks the network's vote rules.
    InvalidVote,
    /// A validator name breaks the network's name rules.
    InvalidName,
    /// A fee choice is not valid.
    InvalidFee,
    /// No fee can be resolved for the operation.
    FeeUnavailable,
    /// A serialized draft or signed transaction is malformed.
    InvalidDraft,
    /// A transaction's bytes or JSON are refused.
    InvalidTransaction,
    /// A sign-in message fails a check.
    InvalidSignIn,
    /// A request to a node could not be built from its arguments.
    InvalidRequest,
    /// A network profile is incomplete or malformed.
    InvalidProfile,
    /// No node could be reached.
    NodeUnavailable,
    /// The node refused the request for its rate limit.
    RateLimited,
    /// A request timed out.
    Timeout,
    /// The node's response cannot be used.
    BadResponse,
    /// The node has no such resource.
    NotFound,
    /// The node refused the request.
    Refused,
    /// The node or the data belongs to another network than the profile.
    NetworkMismatch,
    /// The node refused a submitted transaction.
    TxRejected,
    /// The nonce, fee or milestone changed since the draft was built.
    StaleDraft,
    /// The network does not support the operation.
    UnsupportedOnNetwork,
    /// The WebAssembly module was used before it was initialized.
    SdkNotInitialized,
    /// No randomness is available for a key or signature.
    RandomnessUnavailable,
    /// A signature could not be made.
    SigningFailed,
    /// A draft was signed with a key it does not name.
    WrongKey,
    /// A key was used after it was released.
    KeyReleased,
}

impl ErrorCode {
    /// The stable string form of the code, as the TypeScript and Go SDKs report it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidPhrase => "InvalidPhrase",
            ErrorCode::PhraseTooShort => "PhraseTooShort",
            ErrorCode::InvalidPath => "InvalidPath",
            ErrorCode::InvalidAddress => "InvalidAddress",
            ErrorCode::InvalidAmount => "InvalidAmount",
            ErrorCode::InvalidKey => "InvalidKey",
            ErrorCode::MemoTooLong => "MemoTooLong",
            ErrorCode::NoRecipients => "NoRecipients",
            ErrorCode::TooManyRecipients => "TooManyRecipients",
            ErrorCode::InvalidVote => "InvalidVote",
            ErrorCode::InvalidName => "InvalidName",
            ErrorCode::InvalidFee => "InvalidFee",
            ErrorCode::FeeUnavailable => "FeeUnavailable",
            ErrorCode::InvalidDraft => "InvalidDraft",
            ErrorCode::InvalidTransaction => "InvalidTransaction",
            ErrorCode::InvalidSignIn => "InvalidSignIn",
            ErrorCode::InvalidRequest => "InvalidRequest",
            ErrorCode::InvalidProfile => "InvalidProfile",
            ErrorCode::NodeUnavailable => "NodeUnavailable",
            ErrorCode::RateLimited => "RateLimited",
            ErrorCode::Timeout => "Timeout",
            ErrorCode::BadResponse => "BadResponse",
            ErrorCode::NotFound => "NotFound",
            ErrorCode::Refused => "Refused",
            ErrorCode::NetworkMismatch => "NetworkMismatch",
            ErrorCode::TxRejected => "TxRejected",
            ErrorCode::StaleDraft => "StaleDraft",
            ErrorCode::UnsupportedOnNetwork => "UnsupportedOnNetwork",
            ErrorCode::SdkNotInitialized => "SdkNotInitialized",
            ErrorCode::RandomnessUnavailable => "RandomnessUnavailable",
            ErrorCode::SigningFailed => "SigningFailed",
            ErrorCode::WrongKey => "WrongKey",
            ErrorCode::KeyReleased => "KeyReleased",
        }
    }

    /// The group the code belongs to.
    pub const fn group(self) -> ErrorGroup {
        match self {
            ErrorCode::InvalidPhrase
            | ErrorCode::PhraseTooShort
            | ErrorCode::InvalidPath
            | ErrorCode::InvalidAddress
            | ErrorCode::InvalidAmount
            | ErrorCode::InvalidKey
            | ErrorCode::MemoTooLong
            | ErrorCode::NoRecipients
            | ErrorCode::TooManyRecipients
            | ErrorCode::InvalidVote
            | ErrorCode::InvalidName
            | ErrorCode::InvalidFee
            | ErrorCode::InvalidDraft
            | ErrorCode::InvalidTransaction
            | ErrorCode::InvalidSignIn
            | ErrorCode::InvalidRequest
            | ErrorCode::InvalidProfile => ErrorGroup::Input,
            ErrorCode::NodeUnavailable
            | ErrorCode::RateLimited
            | ErrorCode::Timeout
            | ErrorCode::BadResponse
            | ErrorCode::NotFound
            | ErrorCode::Refused
            | ErrorCode::NetworkMismatch => ErrorGroup::Network,
            ErrorCode::TxRejected | ErrorCode::StaleDraft | ErrorCode::FeeUnavailable => {
                ErrorGroup::Submission
            }
            ErrorCode::UnsupportedOnNetwork | ErrorCode::SdkNotInitialized => ErrorGroup::Support,
            ErrorCode::RandomnessUnavailable
            | ErrorCode::SigningFailed
            | ErrorCode::WrongKey
            | ErrorCode::KeyReleased => ErrorGroup::Crypto,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The group of an [`ErrorCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorGroup {
    /// The caller's input is refused.
    Input,
    /// The node or the network is not usable.
    Network,
    /// A transaction could not be prepared or submitted.
    Submission,
    /// The network or the runtime does not support the call.
    Support,
    /// A key or signature operation failed.
    Crypto,
}

/// An SDK error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A recovery phrase is not a valid BIP39 English phrase.
    #[error("the recovery phrase is not valid: {problem}")]
    InvalidPhrase {
        /// What is wrong with it.
        problem: PhraseProblem,
    },
    /// A recovery phrase has fewer words than new keys require.
    #[error("the recovery phrase has {words} words; keys need at least {minimum}")]
    PhraseTooShort {
        /// Words in the phrase.
        words: usize,
        /// The fewest words accepted.
        minimum: usize,
    },
    /// An account or address index is not below 2^31, the range of hardened derivation.
    #[error("account {account} and index {index} must both be below 2^31")]
    InvalidPath {
        /// The account number given.
        account: u32,
        /// The address index given.
        index: u32,
    },
    /// An address does not parse, or belongs to another network.
    #[error("invalid address: {problem}")]
    InvalidAddress {
        /// What is wrong with it.
        problem: AddressProblem,
    },
    /// An amount does not parse or is out of range.
    #[error("invalid amount: {problem}")]
    InvalidAmount {
        /// What is wrong with it.
        problem: AmountProblem,
    },
    /// A public key is not a valid key.
    #[error("invalid public key")]
    InvalidKey,
    /// A memo is longer than the network allows.
    #[error("the memo is {bytes} bytes of UTF-8; at most {maximum} are allowed")]
    MemoTooLong {
        /// Length of the memo in UTF-8 bytes.
        bytes: usize,
        /// The most bytes allowed.
        maximum: usize,
    },
    /// A transfer has no recipient.
    #[error("a transfer needs at least {minimum} recipient")]
    NoRecipients {
        /// The fewest recipients allowed.
        minimum: usize,
    },
    /// A transfer has more recipients than the network allows.
    #[error("{count} recipients; at most {maximum} are allowed")]
    TooManyRecipients {
        /// Recipients given.
        count: usize,
        /// The most recipients allowed.
        maximum: usize,
    },
    /// A vote breaks the network's vote rules.
    #[error("invalid vote: {problem}")]
    InvalidVote {
        /// What is wrong with it.
        problem: VoteProblem,
    },
    /// A validator name breaks the network's name rules.
    #[error("invalid validator name {name:?}: {reason}")]
    InvalidName {
        /// The name given.
        name: String,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// A fee choice is not valid.
    #[error("invalid fee: {reason}")]
    InvalidFee {
        /// The rule it breaks.
        reason: &'static str,
    },
    /// No minimum fee can be resolved for the operation: the milestone in force has no enabled
    /// dynamic fee table, so no floor is in force and the node's pool applies settings of its
    /// own, or the exact fee floor is above the largest fee a transaction can carry. An explicit
    /// fee still works.
    #[error("no fee can be resolved for {operation}; pass an explicit fee")]
    FeeUnavailable {
        /// The operation.
        operation: OperationKind,
    },
    /// A serialized draft or signed transaction is malformed.
    #[error("invalid serialized transaction: {reason}")]
    InvalidDraft {
        /// What is wrong with it.
        reason: String,
    },
    /// A transaction's bytes or JSON are refused.
    #[error("invalid transaction: {problem}")]
    InvalidTransaction {
        /// Why it is refused.
        problem: TransactionProblem,
    },
    /// A sign-in message fails a check.
    #[error("invalid sign-in message: {problem}")]
    InvalidSignIn {
        /// The check it fails.
        problem: SignInProblem,
    },
    /// A request to a node could not be built from its arguments, such as a relay URL without
    /// a scheme or a page out of range.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// What is wrong.
        reason: String,
    },
    /// A network profile is incomplete or malformed, such as a network hash to pin that is not 64
    /// hex digits.
    #[error("invalid profile: {reason}")]
    InvalidProfile {
        /// What is wrong.
        reason: &'static str,
    },
    /// No node could be reached.
    #[error("no node is available: {reason}")]
    NodeUnavailable {
        /// What happened.
        reason: String,
    },
    /// The node refused the request for its rate limit.
    #[error("rate limited by the node")]
    RateLimited {
        /// Seconds the node asked to wait, if it said.
        retry_after_seconds: Option<u64>,
    },
    /// A request timed out.
    #[error("the request timed out")]
    Timeout,
    /// The node's response cannot be used.
    #[error("the node's response cannot be used: {reason}")]
    BadResponse {
        /// What is wrong with it.
        reason: String,
    },
    /// The node has no such resource, where the request needs one (a lookup that may find nothing
    /// returns `None` instead).
    #[error("not found: {message}")]
    NotFound {
        /// The node's message.
        message: String,
    },
    /// The node refused the request with an error status, such as 422 for an argument it does not
    /// accept.
    #[error("the node refused the request with HTTP {status}: {message}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The node's message.
        message: String,
    },
    /// The node or the data belongs to another network than the profile.
    #[error("another network: {problem}")]
    NetworkMismatch {
        /// What differs.
        problem: MismatchProblem,
    },
    /// The node refused a submitted transaction.
    #[error("the node refused the transaction ({reason}, {node_code}): {message}")]
    TxRejected {
        /// The normalized reason.
        reason: RejectReason,
        /// The node's own error code.
        node_code: String,
        /// The node's message.
        message: String,
    },
    /// The nonce, fee or milestone changed since the draft was built.
    #[error("the draft is stale: {reason}")]
    StaleDraft {
        /// What changed.
        reason: String,
    },
    /// The network does not support the operation.
    #[error("{capability} is not supported on the network {profile}")]
    UnsupportedOnNetwork {
        /// The capability the operation needs.
        capability: Capability,
        /// The profile id.
        profile: String,
    },
    /// The WebAssembly module was used before it was initialized.
    #[error("the SDK is not initialized")]
    SdkNotInitialized,
    /// No randomness is available for a key or signature.
    #[error("no randomness is available")]
    RandomnessUnavailable,
    /// A signature could not be made.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// What happened.
        reason: String,
    },
    /// A draft was signed with a key it does not name, or without a key it needs.
    #[error("wrong key: {reason}")]
    WrongKey {
        /// What is wrong.
        reason: &'static str,
    },
    /// A key was used after it was released.
    #[error("the key was released")]
    KeyReleased,
}

impl Error {
    /// The stable code of the error.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Error::InvalidPhrase { .. } => ErrorCode::InvalidPhrase,
            Error::PhraseTooShort { .. } => ErrorCode::PhraseTooShort,
            Error::InvalidPath { .. } => ErrorCode::InvalidPath,
            Error::InvalidAddress { .. } => ErrorCode::InvalidAddress,
            Error::InvalidAmount { .. } => ErrorCode::InvalidAmount,
            Error::InvalidKey => ErrorCode::InvalidKey,
            Error::MemoTooLong { .. } => ErrorCode::MemoTooLong,
            Error::NoRecipients { .. } => ErrorCode::NoRecipients,
            Error::TooManyRecipients { .. } => ErrorCode::TooManyRecipients,
            Error::InvalidVote { .. } => ErrorCode::InvalidVote,
            Error::InvalidName { .. } => ErrorCode::InvalidName,
            Error::InvalidFee { .. } => ErrorCode::InvalidFee,
            Error::FeeUnavailable { .. } => ErrorCode::FeeUnavailable,
            Error::InvalidDraft { .. } => ErrorCode::InvalidDraft,
            Error::InvalidTransaction { .. } => ErrorCode::InvalidTransaction,
            Error::InvalidSignIn { .. } => ErrorCode::InvalidSignIn,
            Error::InvalidRequest { .. } => ErrorCode::InvalidRequest,
            Error::InvalidProfile { .. } => ErrorCode::InvalidProfile,
            Error::NodeUnavailable { .. } => ErrorCode::NodeUnavailable,
            Error::RateLimited { .. } => ErrorCode::RateLimited,
            Error::Timeout => ErrorCode::Timeout,
            Error::BadResponse { .. } => ErrorCode::BadResponse,
            Error::NotFound { .. } => ErrorCode::NotFound,
            Error::Refused { .. } => ErrorCode::Refused,
            Error::NetworkMismatch { .. } => ErrorCode::NetworkMismatch,
            Error::TxRejected { .. } => ErrorCode::TxRejected,
            Error::StaleDraft { .. } => ErrorCode::StaleDraft,
            Error::UnsupportedOnNetwork { .. } => ErrorCode::UnsupportedOnNetwork,
            Error::SdkNotInitialized => ErrorCode::SdkNotInitialized,
            Error::RandomnessUnavailable => ErrorCode::RandomnessUnavailable,
            Error::SigningFailed { .. } => ErrorCode::SigningFailed,
            Error::WrongKey { .. } => ErrorCode::WrongKey,
            Error::KeyReleased => ErrorCode::KeyReleased,
        }
    }

    /// The structured details of the error, as a JSON object. The keys of each code are part of
    /// the API.
    pub fn details(&self) -> Value {
        match self {
            Error::InvalidPhrase { problem } => problem.details(),
            Error::PhraseTooShort { words, minimum } => {
                json!({ "words": words, "minimum": minimum })
            }
            Error::InvalidPath { account, index } => json!({ "account": account, "index": index }),
            Error::InvalidAddress { problem } => problem.details(),
            Error::InvalidAmount { problem } => problem.details(),
            Error::InvalidKey
            | Error::Timeout
            | Error::SdkNotInitialized
            | Error::RandomnessUnavailable
            | Error::KeyReleased => json!({}),
            Error::MemoTooLong { bytes, maximum } => json!({ "bytes": bytes, "maximum": maximum }),
            Error::NoRecipients { minimum } => json!({ "minimum": minimum }),
            Error::TooManyRecipients { count, maximum } => {
                json!({ "count": count, "maximum": maximum })
            }
            Error::InvalidVote { problem } => problem.details(),
            Error::InvalidName { name, reason } => json!({ "name": name, "reason": reason }),
            Error::InvalidFee { reason } | Error::InvalidProfile { reason } => {
                json!({ "reason": reason })
            }
            Error::FeeUnavailable { operation } => json!({ "operation": operation.as_str() }),
            Error::InvalidDraft { reason }
            | Error::InvalidRequest { reason }
            | Error::NodeUnavailable { reason }
            | Error::BadResponse { reason }
            | Error::StaleDraft { reason }
            | Error::SigningFailed { reason } => json!({ "reason": reason }),
            Error::InvalidTransaction { problem } => {
                json!({ "reason": problem.as_str(), "message": problem.to_string() })
            }
            Error::InvalidSignIn { problem } => json!({ "reason": problem.as_str() }),
            Error::RateLimited {
                retry_after_seconds,
            } => json!({ "retryAfterSeconds": retry_after_seconds }),
            Error::NetworkMismatch { problem } => problem.details(),
            Error::NotFound { message } => json!({ "message": message }),
            Error::Refused { status, message } => json!({ "status": status, "message": message }),
            Error::TxRejected {
                reason,
                node_code,
                message,
            } => json!({ "reason": reason.as_str(), "nodeCode": node_code, "message": message }),
            Error::UnsupportedOnNetwork {
                capability,
                profile,
            } => json!({ "capability": capability.as_str(), "profile": profile }),
            Error::WrongKey { reason } => json!({ "reason": reason }),
        }
    }
}

/// What is wrong with a recovery phrase. Never names a word: a phrase is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PhraseProblem {
    /// The phrase has no words.
    Empty,
    /// The phrase is not UTF-8 text.
    NotText,
    /// The word at `position` (1-based) is not in the BIP39 English list.
    UnknownWord {
        /// 1-based position of the word.
        position: usize,
    },
    /// The number of words is not one BIP39 defines (12, 15, 18, 21 or 24).
    WordCount {
        /// Words in the phrase.
        words: usize,
    },
    /// A valid BIP39 phrase of 12 or 15 words, which is too short for keys.
    TooShort {
        /// Words in the phrase.
        words: usize,
    },
    /// The checksum does not match: a word is wrong or two words are swapped.
    Checksum,
}

impl PhraseProblem {
    /// A stable string for the problem: `empty`, `not-text`, `unknown-word`, `word-count`,
    /// `too-short` or `checksum`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PhraseProblem::Empty => "empty",
            PhraseProblem::NotText => "not-text",
            PhraseProblem::UnknownWord { .. } => "unknown-word",
            PhraseProblem::WordCount { .. } => "word-count",
            PhraseProblem::TooShort { .. } => "too-short",
            PhraseProblem::Checksum => "checksum",
        }
    }

    fn details(self) -> Value {
        match self {
            PhraseProblem::UnknownWord { position } => {
                json!({ "reason": self.as_str(), "position": position })
            }
            PhraseProblem::WordCount { words } | PhraseProblem::TooShort { words } => {
                json!({ "reason": self.as_str(), "words": words })
            }
            PhraseProblem::Empty | PhraseProblem::NotText | PhraseProblem::Checksum => {
                json!({ "reason": self.as_str() })
            }
        }
    }
}

impl fmt::Display for PhraseProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhraseProblem::Empty => f.write_str("it has no words"),
            PhraseProblem::NotText => f.write_str("it is not UTF-8 text"),
            PhraseProblem::UnknownWord { position } => {
                write!(f, "word {position} is not in the BIP39 English list")
            }
            PhraseProblem::WordCount { words } => {
                write!(f, "{words} words; a phrase has 12, 15, 18, 21 or 24")
            }
            PhraseProblem::TooShort { words } => {
                write!(f, "{words} words; keys need 18, 21 or 24")
            }
            PhraseProblem::Checksum => f.write_str("the checksum does not match"),
        }
    }
}

/// What is wrong with an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressProblem {
    /// The text is not in the address format (for example, a character outside Base58).
    Format {
        /// 0-based index of the first bad character, when one is to blame.
        position: Option<usize>,
    },
    /// The checksum does not match: a character is mistyped.
    Checksum,
    /// The address has the wrong length.
    Length {
        /// Length of the payload in bytes.
        bytes: usize,
    },
    /// The address belongs to another network.
    WrongNetwork {
        /// The network byte of the profile.
        expected: u8,
        /// The network byte of the address.
        actual: u8,
    },
}

impl AddressProblem {
    /// A stable string for the problem: `format`, `checksum`, `length` or `wrong-network`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AddressProblem::Format { .. } => "format",
            AddressProblem::Checksum => "checksum",
            AddressProblem::Length { .. } => "length",
            AddressProblem::WrongNetwork { .. } => "wrong-network",
        }
    }

    fn details(self) -> Value {
        match self {
            AddressProblem::Format { position } => {
                json!({ "reason": self.as_str(), "position": position })
            }
            AddressProblem::Checksum => json!({ "reason": self.as_str() }),
            AddressProblem::Length { bytes } => json!({ "reason": self.as_str(), "bytes": bytes }),
            AddressProblem::WrongNetwork { expected, actual } => {
                json!({ "reason": self.as_str(), "expected": expected, "actual": actual })
            }
        }
    }
}

impl fmt::Display for AddressProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressProblem::Format {
                position: Some(position),
            } => write!(f, "character {position} is not allowed in an address"),
            AddressProblem::Format { position: None } => f.write_str("not an address"),
            AddressProblem::Checksum => f.write_str("the checksum does not match"),
            AddressProblem::Length { bytes } => {
                write!(f, "the address holds {bytes} bytes, not 21")
            }
            AddressProblem::WrongNetwork { expected, actual } => write!(
                f,
                "the address is for network byte {actual}, not this network's {expected}"
            ),
        }
    }
}

/// What is wrong with an amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmountProblem {
    /// The text is empty.
    Empty,
    /// The text is not a plain decimal number (digits with at most one point).
    Format,
    /// The text has more digits after the point than the asset has decimals.
    TooManyDecimals {
        /// The asset's decimals.
        decimals: u8,
    },
    /// The asset's decimals are more than the SDK represents (38).
    Decimals {
        /// The decimals given.
        decimals: u8,
    },
    /// The amount is larger than the field that carries it.
    TooLarge,
    /// The amount is zero where a positive amount is required.
    Zero,
    /// The amount is below the network's minimum for the operation.
    BelowMinimum {
        /// The minimum, in base units.
        minimum: u128,
    },
}

impl AmountProblem {
    /// A stable string for the problem: `empty`, `format`, `too-many-decimals`, `decimals`,
    /// `too-large`, `zero` or `below-minimum`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AmountProblem::Empty => "empty",
            AmountProblem::Format => "format",
            AmountProblem::TooManyDecimals { .. } => "too-many-decimals",
            AmountProblem::Decimals { .. } => "decimals",
            AmountProblem::TooLarge => "too-large",
            AmountProblem::Zero => "zero",
            AmountProblem::BelowMinimum { .. } => "below-minimum",
        }
    }

    fn details(self) -> Value {
        match self {
            AmountProblem::TooManyDecimals { decimals } | AmountProblem::Decimals { decimals } => {
                json!({ "reason": self.as_str(), "decimals": decimals })
            }
            AmountProblem::BelowMinimum { minimum } => {
                json!({ "reason": self.as_str(), "minimum": minimum.to_string() })
            }
            AmountProblem::Empty
            | AmountProblem::Format
            | AmountProblem::TooLarge
            | AmountProblem::Zero => json!({ "reason": self.as_str() }),
        }
    }
}

impl fmt::Display for AmountProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmountProblem::Empty => f.write_str("no amount given"),
            AmountProblem::Format => f.write_str("not a plain decimal number"),
            AmountProblem::TooManyDecimals { decimals } => {
                write!(f, "more than {decimals} digits after the point")
            }
            AmountProblem::Decimals { decimals } => {
                write!(f, "{decimals} decimals is more than 38")
            }
            AmountProblem::TooLarge => f.write_str("too large"),
            AmountProblem::Zero => f.write_str("the amount must be above zero"),
            AmountProblem::BelowMinimum { minimum } => {
                write!(f, "below the minimum of {minimum} base units")
            }
        }
    }
}

/// What is wrong with a vote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VoteProblem {
    /// More entries than the network allows.
    TooManyEntries {
        /// Entries given.
        count: usize,
        /// The most entries allowed.
        maximum: usize,
    },
    /// The shares do not add up to 10,000 basis points.
    Sum {
        /// The sum of the shares.
        basis_points: u32,
    },
    /// An entry has a share of 0 or above 10,000 basis points.
    Share {
        /// The validator of the entry.
        validator: String,
        /// Its share.
        basis_points: u16,
    },
    /// An entry names a text that is not a validator name.
    Name {
        /// The text given.
        validator: String,
    },
    /// A share in the relay API's percentage form is not a multiple of 0.01 from 0.01 to 100.
    Percentage {
        /// The validator of the entry.
        validator: String,
    },
    /// Two entries name the same validator.
    Duplicate {
        /// The validator named twice.
        validator: String,
    },
    /// The vote does not fit the vote field's size limit.
    TooLarge {
        /// Size of the encoded vote in bytes.
        bytes: usize,
        /// The limit.
        maximum: usize,
    },
}

impl VoteProblem {
    /// A stable string for the problem: `too-many-entries`, `sum`, `share`, `name`,
    /// `percentage`, `duplicate` or `too-large`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            VoteProblem::TooManyEntries { .. } => "too-many-entries",
            VoteProblem::Sum { .. } => "sum",
            VoteProblem::Share { .. } => "share",
            VoteProblem::Name { .. } => "name",
            VoteProblem::Percentage { .. } => "percentage",
            VoteProblem::Duplicate { .. } => "duplicate",
            VoteProblem::TooLarge { .. } => "too-large",
        }
    }

    fn details(&self) -> Value {
        let reason = self.as_str();
        match self {
            VoteProblem::TooManyEntries { count, maximum } => {
                json!({ "reason": reason, "count": count, "maximum": maximum })
            }
            VoteProblem::Sum { basis_points } => {
                json!({ "reason": reason, "basisPoints": basis_points })
            }
            VoteProblem::Share {
                validator,
                basis_points,
            } => json!({ "reason": reason, "validator": validator, "basisPoints": basis_points }),
            VoteProblem::Name { validator }
            | VoteProblem::Percentage { validator }
            | VoteProblem::Duplicate { validator } => {
                json!({ "reason": reason, "validator": validator })
            }
            VoteProblem::TooLarge { bytes, maximum } => {
                json!({ "reason": reason, "bytes": bytes, "maximum": maximum })
            }
        }
    }
}

impl fmt::Display for VoteProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoteProblem::TooManyEntries { count, maximum } => {
                write!(f, "{count} entries; at most {maximum} are allowed")
            }
            VoteProblem::Sum { basis_points } => {
                write!(
                    f,
                    "the shares add up to {basis_points} basis points, not 10000"
                )
            }
            VoteProblem::Share {
                validator,
                basis_points,
            } => write!(
                f,
                "the share of {validator:?} is {basis_points} basis points; it must be 1 to 10000"
            ),
            VoteProblem::Name { validator } => write!(f, "{validator:?} is not a validator name"),
            VoteProblem::Percentage { validator } => write!(
                f,
                "the share of {validator:?} is not a multiple of 0.01 from 0.01 to 100"
            ),
            VoteProblem::Duplicate { validator } => write!(f, "{validator:?} is named twice"),
            VoteProblem::TooLarge { bytes, maximum } => {
                write!(f, "the vote is {bytes} bytes; at most {maximum} fit")
            }
        }
    }
}

/// Why a transaction's bytes or JSON are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransactionProblem {
    /// The bytes end inside a field.
    Truncated,
    /// A version other than 3.
    UnsupportedVersion(u8),
    /// A header type other than the standard header.
    UnsupportedHeader(u8),
    /// A type the network no longer carries.
    RemovedType {
        /// Wire type group.
        type_group: u32,
        /// Wire type.
        type_id: u16,
    },
    /// A type no network defines.
    UnknownType {
        /// Wire type group.
        type_group: u32,
        /// Wire type.
        type_id: u16,
    },
    /// The sender key is not a valid public key.
    SenderKey,
    /// The memo is not valid UTF-8.
    InvalidMemo,
    /// The memo is too long.
    MemoTooLong,
    /// The vote field is over its size limit.
    VoteTooLarge,
    /// A transfer has more items than the network allows.
    TooManyTransfers,
    /// Bytes are left after the signatures.
    TrailingBytes,
    /// Multi-signature entries, which no account can use.
    MultiSignature,
    /// The transaction is larger than the size limit.
    TooLarge,
    /// A value does not fit its field, or the id cannot be computed.
    OutOfRange(String),
    /// A transaction rule refuses it.
    Rules(String),
    /// The JSON form is malformed.
    Json(String),
    /// The transaction carries no signature where one is required, or signatures where none may
    /// be.
    Signatures,
    /// The transaction is not in canonical form.
    NotCanonical,
}

impl TransactionProblem {
    /// A stable string for the problem.
    pub const fn as_str(&self) -> &'static str {
        match self {
            TransactionProblem::Truncated => "truncated",
            TransactionProblem::UnsupportedVersion(_) => "version",
            TransactionProblem::UnsupportedHeader(_) => "header",
            TransactionProblem::RemovedType { .. } => "removed-type",
            TransactionProblem::UnknownType { .. } => "unknown-type",
            TransactionProblem::SenderKey => "sender-key",
            TransactionProblem::InvalidMemo => "memo",
            TransactionProblem::MemoTooLong => "memo-too-long",
            TransactionProblem::VoteTooLarge => "vote-too-large",
            TransactionProblem::TooManyTransfers => "too-many-transfers",
            TransactionProblem::TrailingBytes => "trailing-bytes",
            TransactionProblem::MultiSignature => "multi-signature",
            TransactionProblem::TooLarge => "too-large",
            TransactionProblem::OutOfRange(_) => "out-of-range",
            TransactionProblem::Rules(_) => "rules",
            TransactionProblem::Json(_) => "json",
            TransactionProblem::Signatures => "signatures",
            TransactionProblem::NotCanonical => "not-canonical",
        }
    }
}

impl fmt::Display for TransactionProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionProblem::Truncated => f.write_str("the bytes end inside a field"),
            TransactionProblem::UnsupportedVersion(version) => {
                write!(f, "version {version} is not supported")
            }
            TransactionProblem::UnsupportedHeader(header) => {
                write!(f, "header type {header} is not supported")
            }
            TransactionProblem::RemovedType {
                type_group,
                type_id,
            } => write!(f, "type {type_group}/{type_id} is no longer carried"),
            TransactionProblem::UnknownType {
                type_group,
                type_id,
            } => write!(f, "type {type_group}/{type_id} is unknown"),
            TransactionProblem::SenderKey => f.write_str("the sender key is not valid"),
            TransactionProblem::InvalidMemo => f.write_str("the memo is not UTF-8"),
            TransactionProblem::MemoTooLong => f.write_str("the memo is too long"),
            TransactionProblem::VoteTooLarge => f.write_str("the vote is too large"),
            TransactionProblem::TooManyTransfers => f.write_str("too many transfer items"),
            TransactionProblem::TrailingBytes => f.write_str("bytes after the signatures"),
            TransactionProblem::MultiSignature => {
                f.write_str("multi-signature entries are not accepted")
            }
            TransactionProblem::TooLarge => f.write_str("the transaction is too large"),
            TransactionProblem::OutOfRange(what)
            | TransactionProblem::Rules(what)
            | TransactionProblem::Json(what) => f.write_str(what),
            TransactionProblem::Signatures => f.write_str("wrong signatures for this form"),
            TransactionProblem::NotCanonical => f.write_str("not in canonical form"),
        }
    }
}

/// What differs between a profile and the network it meets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MismatchProblem {
    /// Another network byte.
    NetworkByte {
        /// The profile's network byte.
        expected: u8,
        /// The one found.
        actual: u8,
    },
    /// Another network hash: a different chain, or a devnet that was generated again.
    Nethash {
        /// The pinned network hash.
        expected: String,
        /// The one found.
        actual: String,
    },
    /// Data made for another profile.
    Profile {
        /// The profile id.
        expected: String,
        /// The profile id the data names.
        actual: String,
    },
    /// The profile has no pinned chain identity, so data made for a network cannot be matched to
    /// it.
    NotPinned,
}

impl MismatchProblem {
    /// A stable string for the problem: `network-byte`, `nethash`, `profile` or `not-pinned`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            MismatchProblem::NetworkByte { .. } => "network-byte",
            MismatchProblem::Nethash { .. } => "nethash",
            MismatchProblem::Profile { .. } => "profile",
            MismatchProblem::NotPinned => "not-pinned",
        }
    }

    fn details(&self) -> Value {
        let reason = self.as_str();
        match self {
            MismatchProblem::NetworkByte { expected, actual } => {
                json!({ "reason": reason, "expected": expected, "actual": actual })
            }
            MismatchProblem::Nethash { expected, actual }
            | MismatchProblem::Profile { expected, actual } => {
                json!({ "reason": reason, "expected": expected, "actual": actual })
            }
            MismatchProblem::NotPinned => json!({ "reason": reason }),
        }
    }
}

impl fmt::Display for MismatchProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MismatchProblem::NetworkByte { expected, actual } => {
                write!(f, "network byte {actual}, expected {expected}")
            }
            MismatchProblem::Nethash { expected, actual } => {
                write!(f, "network hash {actual}, expected {expected}")
            }
            MismatchProblem::Profile { expected, actual } => {
                write!(f, "made for profile {actual:?}, expected {expected:?}")
            }
            MismatchProblem::NotPinned => f.write_str("the profile has no pinned chain identity"),
        }
    }
}

/// The check a sign-in message fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignInProblem {
    /// Not a sign-in message of the supported format (lines, fixed text, length).
    Format,
    /// A field line is missing or malformed.
    Field,
    /// The origin is not a secure origin, or the URI is not the origin's `/login`.
    Origin,
    /// The message is for another network.
    Network,
    /// The public key, address or nonce has the wrong form, or the address is not the key's.
    Identity,
    /// The origin, public key or address differs from the one expected.
    Mismatch,
    /// The times are malformed, out of order, too far apart or expired.
    Expired,
}

impl SignInProblem {
    /// A stable string for the problem: `format`, `field`, `origin`, `network`, `identity`,
    /// `mismatch` or `expired`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SignInProblem::Format => "format",
            SignInProblem::Field => "field",
            SignInProblem::Origin => "origin",
            SignInProblem::Network => "network",
            SignInProblem::Identity => "identity",
            SignInProblem::Mismatch => "mismatch",
            SignInProblem::Expired => "expired",
        }
    }
}

impl fmt::Display for SignInProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignInProblem::Format => "not a supported sign-in message",
            SignInProblem::Field => "a field is missing or malformed",
            SignInProblem::Origin => "the website is not a secure origin",
            SignInProblem::Network => "the message is for another network",
            SignInProblem::Identity => "the identity or nonce is malformed",
            SignInProblem::Mismatch => "the origin or identity does not match this request",
            SignInProblem::Expired => "the message has expired or has invalid times",
        })
    }
}

/// The normalized reason of a node's refusal of a submitted transaction. The node API client
/// and the core share this type.
pub use iceroot_sdk_api::RejectReason;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_details() {
        let error = Error::PhraseTooShort {
            words: 12,
            minimum: 18,
        };
        assert_eq!(error.code().as_str(), "PhraseTooShort");
        assert_eq!(error.code().group(), ErrorGroup::Input);
        assert_eq!(error.details(), json!({ "words": 12, "minimum": 18 }));
        let error = Error::InvalidPhrase {
            problem: PhraseProblem::UnknownWord { position: 3 },
        };
        assert_eq!(
            error.details(),
            json!({ "reason": "unknown-word", "position": 3 })
        );
        assert_eq!(
            error.to_string(),
            "the recovery phrase is not valid: word 3 is not in the BIP39 English list"
        );
        let error = Error::InvalidAddress {
            problem: AddressProblem::WrongNetwork {
                expected: 90,
                actual: 63,
            },
        };
        assert_eq!(error.code(), ErrorCode::InvalidAddress);
        assert_eq!(
            error.details(),
            json!({ "reason": "wrong-network", "expected": 90, "actual": 63 })
        );
        assert_eq!(
            Error::TxRejected {
                reason: RejectReason::LowFee,
                node_code: "ERR_LOW_FEE".into(),
                message: "fee too low".into()
            }
            .details(),
            json!({ "reason": "low-fee", "nodeCode": "ERR_LOW_FEE", "message": "fee too low" })
        );
    }
}
