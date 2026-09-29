//! What a node reports, read into what the core takes.
//!
//! The node API client (`iceroot-sdk-api`) decodes a node's answers into IceRoot-shaped values.
//! This module turns them into the core's inputs, and checks them on the way rather than trusting
//! them:
//!
//! - [`Chain::from_node`] loads the chain from the node's crypto configuration,
//!   [`Chain::check_node`] refuses a node whose configuration names another chain, and
//!   [`Chain::relay_identity`] gives the chain's identity for the HTTP client to check relays against.
//! - [`OnlineFacts::from_node`] reads a draft's nonce, height and second key from the sender's
//!   account and the node's status, and refuses an account that is not the sender's.
//! - [`OperationKind`] converts from and to the client's transaction kinds.
//! - [`SignedTransaction::to_submit`] prepares a signed transaction for submission, and
//!   [`submit_result`] turns a refusal into [`Error::TxRejected`].
//! - Every error of the client becomes an [`Error`] with the same stable code.
//!
//! The types both crates use ([`crate::amount::AssetId`], [`crate::transaction::VoteEntry`],
//! [`crate::economics::Supply`], [`crate::error::RejectReason`]) are the client's own.

use heartwood_crypto::PublicKey;
use iceroot_sdk_api::{
    AccountInfo, ApiError, CryptoConfiguration, NodeConfiguration, NodeStatus, RelayIdentity,
    SubmitOutcome, SubmitStatus, SubmitTx, TxKind,
};
use serde_json::Value;

use crate::address::Address;
use crate::chain::Chain;
use crate::error::{Error, MismatchProblem};
use crate::profile::Profile;
use crate::transaction::{OnlineFacts, OperationKind, SignedTransaction};

impl Chain {
    /// The chain of the crypto configuration a node reports, for `profile`: the network
    /// description and milestones are loaded and checked as [`Chain::load`] does, the genesis
    /// block's payload hash must be the network hash, and the network hash and byte the client
    /// read must be the loaded network's.
    pub fn from_node(
        profile: &Profile,
        configuration: &CryptoConfiguration,
    ) -> Result<Chain, Error> {
        let chain = Chain::from_parts(
            profile,
            &configuration.network_json,
            &configuration.milestones_json,
        )?;
        if !configuration.nethash.eq_ignore_ascii_case(chain.nethash())
            || configuration.network_byte != chain.network_byte()
        {
            return Err(Error::BadResponse {
                reason: "the crypto configuration contradicts its network description".to_owned(),
            });
        }
        let genesis: Value =
            serde_json::from_str(&configuration.genesis_block_json).map_err(|error| {
                Error::BadResponse {
                    reason: format!("the genesis block is not JSON: {error}"),
                }
            })?;
        let payload_hash = genesis.get("payloadHash").and_then(Value::as_str);
        if payload_hash.is_none_or(|hash| !hash.eq_ignore_ascii_case(chain.nethash())) {
            return Err(Error::BadResponse {
                reason: "the genesis block's payload hash is not the network hash".to_owned(),
            });
        }
        Ok(chain)
    }

    /// The identity a node of this chain reports: the network hash and address network byte.
    /// With `HttpOptions::identity` (the node API client's feature `http`), the HTTP client uses a
    /// relay only once its node configuration names this chain.
    pub fn relay_identity(&self) -> RelayIdentity {
        RelayIdentity {
            nethash: self.nethash().to_owned(),
            network_byte: self.network_byte(),
        }
    }

    /// `Ok` when the node's configuration names this chain: the same network hash and address
    /// network byte. A node on another chain is refused with [`Error::NetworkMismatch`].
    pub fn check_node(&self, configuration: &NodeConfiguration) -> Result<(), Error> {
        let identity = &configuration.network;
        if !identity.nethash.eq_ignore_ascii_case(self.nethash()) {
            return Err(Error::NetworkMismatch {
                problem: MismatchProblem::Nethash {
                    expected: self.nethash().to_owned(),
                    actual: identity.nethash.to_ascii_lowercase(),
                },
            });
        }
        if identity.network_byte != self.network_byte() {
            return Err(Error::NetworkMismatch {
                problem: MismatchProblem::NetworkByte {
                    expected: self.network_byte(),
                    actual: identity.network_byte,
                },
            });
        }
        Ok(())
    }
}

impl OnlineFacts {
    /// The facts of a draft by `sender` on `chain`, from what the node reports: the sender's
    /// account (`None` when the node does not know the address yet, as for a new account) and
    /// the node's status. The nonce is the account's plus one, the height the next block's, and
    /// the second key the one the account registered.
    ///
    /// The account must be the sender's: its address is the sender's address on the chain, and a
    /// public key the node knows for it is the sender's key. Otherwise the draft would be built
    /// for another account's nonce, so it is refused with [`Error::WrongKey`].
    pub fn from_node(
        chain: &Chain,
        sender: &PublicKey,
        account: Option<&AccountInfo>,
        status: &NodeStatus,
    ) -> Result<OnlineFacts, Error> {
        let address = Address::from_public_key(sender, chain.profile())?;
        let mut second_key = None;
        let mut nonce = 0;
        if let Some(account) = account {
            if account.address != address.to_string() {
                return Err(Error::WrongKey {
                    reason: "the account is not the sender's",
                });
            }
            if let Some(known) = &account.public_key
                && !known.eq_ignore_ascii_case(&sender.to_hex())
            {
                return Err(Error::WrongKey {
                    reason: "the node knows another public key for the sender",
                });
            }
            if let Some(second) = &account.second_public_key {
                second_key = Some(PublicKey::from_hex(second).map_err(|_| Error::BadResponse {
                    reason: "the account's second public key is not a valid key".to_owned(),
                })?);
            }
            nonce = account.nonce;
        }
        let nonce = nonce.checked_add(1).ok_or_else(|| Error::BadResponse {
            reason: "the account's nonce is out of range".to_owned(),
        })?;
        let height = status
            .height
            .checked_add(1)
            .and_then(|next| u32::try_from(next).ok())
            .ok_or_else(|| Error::BadResponse {
                reason: "the node's height is out of range".to_owned(),
            })?;
        Ok(OnlineFacts {
            sender: sender.clone(),
            nonce,
            height,
            second_key,
        })
    }
}

impl OperationKind {
    /// The operation of the client's transaction kind; `None` for a kind the SDK does not build.
    pub fn from_tx_kind(kind: TxKind) -> Option<OperationKind> {
        match kind {
            TxKind::Transfer => Some(OperationKind::Transfer),
            TxKind::Vote => Some(OperationKind::Vote),
            TxKind::Burn => Some(OperationKind::Burn),
            TxKind::RegisterSecondKey => Some(OperationKind::RegisterSecondKey),
            TxKind::RegisterValidator => Some(OperationKind::RegisterValidator),
            TxKind::ResignValidator => Some(OperationKind::ResignValidator),
            _ => None,
        }
    }

    /// The client's transaction kind of the operation.
    pub const fn tx_kind(self) -> TxKind {
        match self {
            OperationKind::Transfer => TxKind::Transfer,
            OperationKind::Vote => TxKind::Vote,
            OperationKind::Burn => TxKind::Burn,
            OperationKind::RegisterSecondKey => TxKind::RegisterSecondKey,
            OperationKind::RegisterValidator => TxKind::RegisterValidator,
            OperationKind::ResignValidator => TxKind::ResignValidator,
        }
    }
}

impl SignedTransaction {
    /// The transaction as the client submits it: its id, its JSON and its size.
    pub fn to_submit(&self) -> Result<SubmitTx, Error> {
        SubmitTx::new(self.id(), &self.json().to_string(), self.bytes().len()).map_err(Error::from)
    }
}

/// `Ok` when the node accepted the transaction of `outcome`, else [`Error::TxRejected`] with the
/// normalized reason and the node's own code and message.
pub fn submit_result(outcome: &SubmitOutcome) -> Result<(), Error> {
    match &outcome.status {
        SubmitStatus::Accepted { .. } => Ok(()),
        SubmitStatus::Rejected {
            reason,
            node_code,
            message,
        } => Err(Error::TxRejected {
            reason: *reason,
            node_code: node_code.clone(),
            message: message.clone(),
        }),
    }
}

impl From<ApiError> for Error {
    /// The error with the client's code: `InvalidRequest`, `RateLimited`, `NotFound`, `Refused`,
    /// `BadResponse`, `NodeUnavailable` or `Timeout`.
    fn from(error: ApiError) -> Error {
        match error {
            ApiError::InvalidRequest { reason } => Error::InvalidRequest { reason },
            ApiError::RateLimited { retry_after } => Error::RateLimited {
                retry_after_seconds: retry_after.map(|wait| {
                    wait.as_secs()
                        .saturating_add(u64::from(wait.subsec_nanos() > 0))
                }),
            },
            ApiError::NotFound { message } => Error::NotFound { message },
            ApiError::Refused {
                status, message, ..
            } => Error::Refused { status, message },
            ApiError::BadResponse { status, detail } => Error::BadResponse {
                reason: format!("HTTP {status}: {detail}"),
            },
            ApiError::NodeUnavailable { detail } => Error::NodeUnavailable { reason: detail },
            ApiError::Timeout => Error::Timeout,
            other => Error::BadResponse {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iceroot_sdk_api::RejectReason;

    use super::*;
    use crate::chain::tests::devnet_chain;
    use crate::error::ErrorCode;

    #[test]
    fn api_errors_keep_their_codes() {
        let cases = [
            (
                ApiError::InvalidRequest {
                    reason: "no scheme".into(),
                },
                ErrorCode::InvalidRequest,
            ),
            (
                ApiError::RateLimited { retry_after: None },
                ErrorCode::RateLimited,
            ),
            (
                ApiError::NotFound {
                    message: "Block not found".into(),
                },
                ErrorCode::NotFound,
            ),
            (
                ApiError::Refused {
                    status: 422,
                    error: "Unprocessable Entity".into(),
                    message: "Wallet not valid".into(),
                },
                ErrorCode::Refused,
            ),
            (
                ApiError::BadResponse {
                    status: 200,
                    detail: "no data".into(),
                },
                ErrorCode::BadResponse,
            ),
            (
                ApiError::NodeUnavailable {
                    detail: "connection refused".into(),
                },
                ErrorCode::NodeUnavailable,
            ),
            (ApiError::Timeout, ErrorCode::Timeout),
        ];
        for (api, code) in cases {
            assert_eq!(api.code(), code.as_str());
            assert_eq!(Error::from(api).code(), code);
        }
        let limited = Error::from(ApiError::RateLimited {
            retry_after: Some(Duration::from_millis(1500)),
        });
        assert_eq!(
            limited.details(),
            serde_json::json!({ "retryAfterSeconds": 2 })
        );
    }

    #[test]
    fn a_node_s_own_text_is_in_the_details_only() {
        const TEXT: &str = "Restore your wallet at https://recovery.example";
        let refused = Error::from(ApiError::Refused {
            status: 422,
            error: "Unprocessable Entity".into(),
            message: TEXT.into(),
        });
        assert_eq!(
            refused.to_string(),
            "the node refused the request with HTTP 422"
        );
        assert_eq!(
            refused.details(),
            serde_json::json!({ "status": 422, "message": TEXT })
        );
        let missing = Error::from(ApiError::NotFound {
            message: TEXT.into(),
        });
        assert_eq!(missing.to_string(), "not found");
        assert_eq!(missing.details(), serde_json::json!({ "message": TEXT }));
        let rejected = Error::TxRejected {
            reason: RejectReason::LowFee,
            node_code: "ERR_LOW_FEE".into(),
            message: TEXT.into(),
        };
        assert!(!rejected.to_string().contains("Restore"));
        assert_eq!(rejected.details()["message"], TEXT);
    }

    #[test]
    fn operation_kinds() {
        for kind in OperationKind::ALL {
            assert_eq!(OperationKind::from_tx_kind(kind.tx_kind()), Some(kind));
        }
        assert_eq!(
            OperationKind::from_tx_kind(TxKind::Other {
                type_group: 1,
                type_id: 4,
            }),
            None
        );
    }

    #[test]
    fn rejections_become_errors() {
        let accepted = SubmitOutcome {
            id: "a".into(),
            status: SubmitStatus::Accepted { broadcast: true },
        };
        assert!(submit_result(&accepted).is_ok());
        let rejected = SubmitOutcome {
            id: "b".into(),
            status: SubmitStatus::Rejected {
                reason: RejectReason::LowFee,
                node_code: "ERR_LOW_FEE".into(),
                message: "fee too low".into(),
            },
        };
        let error = submit_result(&rejected).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TxRejected);
        assert_eq!(
            error.details(),
            serde_json::json!({ "reason": "low-fee", "nodeCode": "ERR_LOW_FEE", "message": "fee too low" })
        );
    }

    #[test]
    fn facts_from_the_node() {
        let chain = devnet_chain();
        let sender = PublicKey::from_hex(
            "03f83f83227e28add5598d2c75c20f72b4bfb0328957ef27e2da2ff73779fa4bd2",
        )
        .unwrap();
        let address = Address::from_public_key(&sender, chain.profile())
            .unwrap()
            .to_string();
        let status = NodeStatus {
            height: 41,
            synced: true,
            blocks_behind: 0,
            chain_time: 0,
        };
        let fresh = OnlineFacts::from_node(&chain, &sender, None, &status).unwrap();
        assert_eq!((fresh.nonce, fresh.height, fresh.second_key), (1, 42, None));

        let mut account = AccountInfo {
            address: address.clone(),
            public_key: Some(sender.to_hex()),
            nonce: 7,
            balances: Vec::new(),
            vote: Vec::new(),
            second_public_key: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            ),
            validator_name: None,
        };
        let facts = OnlineFacts::from_node(&chain, &sender, Some(&account), &status).unwrap();
        assert_eq!(facts.nonce, 8);
        assert!(facts.second_key.is_some());

        account.public_key =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        assert!(matches!(
            OnlineFacts::from_node(&chain, &sender, Some(&account), &status),
            Err(Error::WrongKey { .. })
        ));
        account.public_key = None;
        account.address = "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNX".into();
        assert!(matches!(
            OnlineFacts::from_node(&chain, &sender, Some(&account), &status),
            Err(Error::WrongKey { .. })
        ));
        account.address = address;
        account.second_public_key = Some("02zz".into());
        assert!(matches!(
            OnlineFacts::from_node(&chain, &sender, Some(&account), &status),
            Err(Error::BadResponse { .. })
        ));
        let far = NodeStatus {
            height: u64::from(u32::MAX),
            ..status
        };
        assert!(matches!(
            OnlineFacts::from_node(&chain, &sender, None, &far),
            Err(Error::BadResponse { .. })
        ));
    }
}
