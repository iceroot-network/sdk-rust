//! Signed transactions: made by signing a draft, or read from bytes or JSON.

use heartwood_crypto::Transaction;
use heartwood_crypto::errors::{BuildError, DecodeError, EncodeError, MemoError};
use heartwood_crypto::identities::PublicKey;
use heartwood_crypto::transactions::deserialiser;
use heartwood_crypto::transactions::types::Memo;
use serde_json::Value;

use super::envelope::{self, Envelope, EnvelopeKind};
use super::{Operation, OperationKind};
use crate::address::Address;
use crate::amount::Amount;
use crate::chain::Chain;
use crate::error::{Error, TransactionProblem};
use crate::profile::Profile;

/// A signed transaction, with its id, bytes and JSON.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    chain: Chain,
    height: u32,
    transaction: Transaction,
}

impl SignedTransaction {
    pub(crate) fn new(chain: Chain, height: u32, transaction: Transaction) -> SignedTransaction {
        SignedTransaction {
            chain,
            height,
            transaction,
        }
    }

    /// The transaction in `bytes`, received from a node or another party, decoded and checked
    /// under the rules of `chain` at `height`, as a node does. A bad signature does not refuse
    /// it: [`SignedTransaction::is_verified`] is then false.
    pub fn decode(chain: &Chain, bytes: &[u8], height: u32) -> Result<SignedTransaction, Error> {
        let transaction = Transaction::decode(bytes, chain.params(height)).map_err(|error| {
            Error::InvalidTransaction {
                problem: decode_problem(&error),
            }
        })?;
        Ok(SignedTransaction::new(chain.clone(), height, transaction))
    }

    /// The transaction in the reference implementation's JSON form, read and checked under the
    /// rules of `chain` at `height`.
    pub fn from_json(chain: &Chain, json: &Value, height: u32) -> Result<SignedTransaction, Error> {
        let transaction = Transaction::from_json(json, chain.params(height)).map_err(|error| {
            Error::InvalidTransaction {
                problem: build_problem(&error),
            }
        })?;
        Ok(SignedTransaction::new(chain.clone(), height, transaction))
    }

    /// The id: the SHA-256 of the signed bytes, as 64 lowercase hex digits.
    pub fn id(&self) -> String {
        self.transaction.id().to_hex()
    }

    /// The id's 32 bytes.
    pub fn id_bytes(&self) -> &[u8; 32] {
        self.transaction.id().as_bytes()
    }

    /// The signed bytes, as sent to a node.
    pub fn bytes(&self) -> &[u8] {
        self.transaction.bytes()
    }

    /// The transaction in the JSON form a node accepts and returns.
    pub fn json(&self) -> Value {
        self.transaction.to_json(self.chain.params(self.height))
    }

    /// Whether the sender's signature verifies.
    pub fn is_verified(&self) -> bool {
        self.transaction.is_verified()
    }

    /// Whether the second signature verifies for `public_key`.
    pub fn verify_second_signature(&self, public_key: &PublicKey) -> bool {
        self.transaction
            .verify_second_signature(public_key.as_bytes(), self.chain.params(self.height))
    }

    /// The operation's kind.
    pub fn kind(&self) -> OperationKind {
        OperationKind::from_wire_type(self.transaction.kind())
    }

    /// The operation.
    pub fn operation(&self) -> Operation {
        Operation::from_asset(&self.transaction.data().asset)
    }

    /// The sender's address.
    pub fn sender(&self) -> Address {
        Address::from_public_key_for_network_byte(
            &self.transaction.data().sender_public_key,
            self.chain.network_byte(),
        )
    }

    /// The sender's public key.
    pub fn sender_public_key(&self) -> &PublicKey {
        &self.transaction.data().sender_public_key
    }

    /// The nonce.
    pub fn nonce(&self) -> u64 {
        self.transaction.data().nonce
    }

    /// The fee.
    pub fn fee(&self) -> Amount {
        Amount::from(self.transaction.fee())
    }

    /// The memo, if any.
    pub fn memo(&self) -> Option<&str> {
        self.transaction.data().memo.as_ref().map(Memo::as_str)
    }

    /// Whether the transaction carries a second signature.
    pub fn has_second_signature(&self) -> bool {
        self.transaction.data().second_signature.is_some()
    }

    /// The height the transaction was built or read for.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The transaction as bytes, for the trip back from the context that signed it (see
    /// [`super::Draft::serialize`]).
    pub fn serialize(&self) -> Vec<u8> {
        Envelope {
            kind: EnvelopeKind::Signed,
            height: self.height,
            transaction: self.transaction.bytes().to_vec(),
            fee: None,
            second_key: None,
        }
        .encode(&self.chain)
    }

    /// The signed transaction in `bytes`, for `profile`, whose network hash must be pinned. The
    /// sender's signature must verify. A second signature is not checked here, since that needs
    /// the account's second public key: check it with
    /// [`SignedTransaction::verify_second_signature`] (a node refuses a transaction whose second
    /// signature does not verify). Data made for another profile or network is refused with
    /// [`Error::NetworkMismatch`].
    pub fn deserialize(bytes: &[u8], profile: &Profile) -> Result<SignedTransaction, Error> {
        let (chain, envelope) = envelope::decode(bytes, profile, EnvelopeKind::Signed)?;
        let data = deserialiser::deserialise(&envelope.transaction).map_err(|error| {
            Error::InvalidTransaction {
                problem: decode_problem(&error),
            }
        })?;
        envelope::check_network(data.network, &chain)?;
        let signed = SignedTransaction::decode(&chain, &envelope.transaction, envelope.height)?;
        if !signed.is_verified() {
            return Err(Error::InvalidTransaction {
                problem: TransactionProblem::Signatures,
            });
        }
        Ok(signed)
    }
}

/// The SDK problem of a decode refusal.
pub(crate) fn decode_problem(error: &DecodeError) -> TransactionProblem {
    match error {
        DecodeError::Truncated(_) => TransactionProblem::Truncated,
        DecodeError::UnsupportedVersion(version) => {
            TransactionProblem::UnsupportedVersion(*version)
        }
        DecodeError::UnsupportedHeaderType(header) => {
            TransactionProblem::UnsupportedHeader(*header)
        }
        DecodeError::RemovedType {
            type_group,
            type_id,
        } => TransactionProblem::RemovedType {
            type_group: *type_group,
            type_id: *type_id,
        },
        DecodeError::UnknownType {
            type_group,
            type_id,
        } => TransactionProblem::UnknownType {
            type_group: *type_group,
            type_id: *type_id,
        },
        DecodeError::SenderKey(_) => TransactionProblem::SenderKey,
        DecodeError::InvalidMemo => TransactionProblem::InvalidMemo,
        DecodeError::VoteAssetTooLarge { .. } => TransactionProblem::VoteTooLarge,
        DecodeError::SignatureBytes => TransactionProblem::TrailingBytes,
        DecodeError::MultiSignature => TransactionProblem::MultiSignature,
        DecodeError::Id(error) => encode_problem(error),
        DecodeError::Schema(error) => TransactionProblem::Rules(error.to_string()),
    }
}

/// The SDK problem of a serialisation refusal.
fn encode_problem(error: &EncodeError) -> TransactionProblem {
    match error {
        EncodeError::TooLarge { .. } => TransactionProblem::TooLarge,
        EncodeError::VoteAssetTooLarge { .. } => TransactionProblem::VoteTooLarge,
        other => TransactionProblem::OutOfRange(other.to_string()),
    }
}

/// The SDK problem of a refusal of the JSON form.
fn build_problem(error: &BuildError) -> TransactionProblem {
    match error {
        BuildError::Schema(error) => TransactionProblem::Rules(error.to_string()),
        BuildError::Encode(error) => encode_problem(error),
        BuildError::Decode(error) => decode_problem(error),
        BuildError::Memo(MemoError::TooLong { .. }) => TransactionProblem::MemoTooLong,
        BuildError::TooManyTransfers { .. } => TransactionProblem::TooManyTransfers,
        other => TransactionProblem::Json(other.to_string()),
    }
}
