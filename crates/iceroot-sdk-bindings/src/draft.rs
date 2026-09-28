//! Drafts and signed transactions.
//!
//! A draft is built from an operation and the facts a node reported, checked against every rule
//! of the milestone in force, and signed as a separate step. Drafts and signed transactions
//! serialize to bytes, so a draft can be built where the network is and signed where the key is.

use iceroot_sdk::api::{AccountInfo, NodeStatus, SubmitTx};
use iceroot_sdk::fee::{FeeChoice, ResolvedFee};
use iceroot_sdk::transaction::{DraftRequest, Operation, Recipient, Resignation, VoteEntry};
use iceroot_sdk::{
    Address, Aux, Chain, Draft, OnlineFacts, Profile, PublicKey, PublicKeyBytes, SignedTransaction,
};
use serde_json::{Map, Value, json};

use crate::error::{BindingError, Result};
use crate::json::{self, amount_value};
use crate::keys::Key;

/// The draft of `request` on `chain`, with the `facts` the node reported.
///
/// - `request`: `{ operation, memo?, fee? }`. The operation is one of
///   `{ kind: "transfer", to: [{ address, amount }] }`, `{ kind: "vote", entries: [{ validator,
///   basisPoints }] }`, `{ kind: "burn", amount }`, `{ kind: "register-second-key", publicKey }`,
///   `{ kind: "register-validator", name }` and `{ kind: "resign-validator", resignation }` (
///   `temporary`, `permanent` or `revoke`). The fee is `{ kind: "minimum" }` (the default),
///   `{ kind: "exact", amount }` or `{ kind: "multiplier", basisPoints }`; the minimum and its
///   multiples fail with `FeeUnavailable` where no fee floor is in force.
/// - `facts`: `{ sender, nonce, height, secondKey? }`, keys as hex.
///
/// Amounts and the nonce are decimal strings.
pub fn build(chain: &Chain, request: &str, facts: &str) -> Result<Draft> {
    let request = read_request(&json::parse_object(request, "the request")?)?;
    let facts = read_facts(&json::parse_object(facts, "the facts")?)?;
    Ok(Draft::build(chain, &request, &facts)?)
}

/// The draft in `bytes` (from [`Draft::serialize`]), for `profile`, whose network hash must be
/// pinned. A draft for another profile or network is refused, and the summary is computed again
/// from the transaction's own fields.
pub fn deserialize(bytes: &[u8], profile: &Profile) -> Result<Draft> {
    Ok(Draft::deserialize(bytes, profile)?)
}

/// Everything a review screen shows, in JSON: `{ profile, networkByte, nethash, height, kind,
/// operation, from, publicKey, nonce, fee: { amount, source, floor }, memo, amount, size,
/// secondSignature }`.
pub fn summary(draft: &Draft) -> String {
    let summary = draft.summary();
    json!({
        "profile": summary.profile,
        "networkByte": summary.network_byte,
        "nethash": summary.nethash,
        "height": summary.height,
        "kind": summary.operation.kind().as_str(),
        "operation": operation_json(&summary.operation),
        "from": summary.sender.to_string(),
        "publicKey": summary.sender_public_key.to_hex(),
        "nonce": summary.nonce.to_string(),
        "fee": fee_json(&summary.fee),
        "memo": summary.memo,
        "amount": amount_value(summary.total_amount),
        "size": summary.size,
        "secondSignature": summary.second_signature,
    })
    .to_string()
}

/// Signs `draft` with the sender's `key`, and with `second`, the sender's registered second key,
/// when it has one, with the auxiliary randomness `aux` for every signature ([`Aux::random`]
/// outside the test seam of the feature `fixed-aux`).
pub fn sign(draft: &Draft, key: &Key, second: Option<&Key>, aux: Aux) -> Result<SignedTransaction> {
    let second = second.map(Key::account).transpose()?;
    Ok(draft.sign_with(key.account()?, second, aux)?)
}

/// The auxiliary randomness of a test signature: exactly 32 bytes.
#[cfg(feature = "fixed-aux")]
pub fn fixed_aux(aux: &[u8]) -> Result<Aux> {
    <[u8; 32]>::try_from(aux)
        .map(Aux::fixed)
        .map_err(|_| BindingError::argument("the auxiliary bytes must be 32 bytes"))
}

/// The signed transaction in `bytes` (from [`SignedTransaction::serialize`]), for `profile`,
/// whose network hash must be pinned. The sender's signature must verify; a second signature is
/// not checked (see [`SignedTransaction::deserialize`]).
pub fn signed_deserialize(bytes: &[u8], profile: &Profile) -> Result<SignedTransaction> {
    Ok(SignedTransaction::deserialize(bytes, profile)?)
}

/// The transaction in the node's JSON form, read and checked under the rules of `chain` at
/// `height`. A bad signature does not refuse it: [`SignedTransaction::is_verified`] is then false.
pub fn signed_from_json(chain: &Chain, json: &str, height: u32) -> Result<SignedTransaction> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| BindingError::argument(format!("the transaction is not JSON: {error}")))?;
    Ok(SignedTransaction::from_json(chain, &value, height)?)
}

/// The transaction in `bytes`, as a node sends them, read and checked under the rules of `chain`
/// at `height`. A bad signature does not refuse it: [`SignedTransaction::is_verified`] is then
/// false.
pub fn signed_decode(chain: &Chain, bytes: &[u8], height: u32) -> Result<SignedTransaction> {
    Ok(SignedTransaction::decode(chain, bytes, height)?)
}

/// Whether the second signature of `signed` verifies for `public_key` (hex).
pub fn verify_second_signature(signed: &SignedTransaction, public_key: &str) -> bool {
    PublicKey::from_hex(public_key).is_ok_and(|key| signed.verify_second_signature(&key))
}

/// What the transaction does, in JSON: `{ id, kind, operation, from, publicKey, nonce, fee,
/// memo, amount, size, height, secondSignature }`.
pub fn signed_summary(signed: &SignedTransaction) -> String {
    let operation = signed.operation();
    json!({
        "id": signed.id(),
        "kind": operation.kind().as_str(),
        "amount": amount_value(operation.total_amount()),
        "operation": operation_json(&operation),
        "from": signed.sender().to_string(),
        "publicKey": signed.sender_public_key().to_hex(),
        "nonce": signed.nonce().to_string(),
        "fee": amount_value(signed.fee()),
        "memo": signed.memo(),
        "size": signed.bytes().len(),
        "height": signed.height(),
        "secondSignature": signed.has_second_signature(),
    })
    .to_string()
}

/// The transaction as a submission takes it.
pub fn to_submit(signed: &SignedTransaction) -> Result<SubmitTx> {
    Ok(signed.to_submit()?)
}

/// The facts of a draft by `sender` (a public key as hex) on `chain`, from what the node reported:
/// the sender's account (as [`crate::api::PreparedCall::decode`] writes it; `undefined` when the node
/// does not know the address yet) and the node's status (likewise). Returns the facts
/// [`build`] takes, in JSON: `{ sender, nonce, height, secondKey }`, the nonce being
/// the account's plus one and the height the next block's.
///
/// The account must be the sender's (the same address, and the same public key when the node
/// knows one), else the draft would take another account's nonce: that is refused with
/// `WrongKey`.
pub fn online_facts(
    chain: &Chain,
    sender: &str,
    account: Option<&str>,
    status: &str,
) -> Result<String> {
    let sender = PublicKey::from_hex(sender)
        .map_err(|_| BindingError::new("InvalidKey", "the sender is not a public key"))?;
    let account = account.map(read_account).transpose()?;
    let status = json::parse_object(status, "the node status")?;
    let status = NodeStatus {
        height: json::decimal_u64(&status, "height")?,
        synced: status
            .get("synced")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        blocks_behind: 0,
        chain_time: 0,
    };
    let facts = OnlineFacts::from_node(chain, &sender, account.as_ref(), &status)?;
    Ok(json!({
        "sender": facts.sender.to_hex(),
        "nonce": facts.nonce.to_string(),
        "height": facts.height,
        "secondKey": facts.second_key.as_ref().map(PublicKey::to_hex),
    })
    .to_string())
}

/// The parts of an account (in the client's JSON form) that a draft's facts depend on.
fn read_account(text: &str) -> Result<AccountInfo> {
    let account = json::parse_object(text, "the account")?;
    let text = |key: &str| -> Result<Option<String>> {
        Ok(json::optional_string(&account, key)?.map(str::to_owned))
    };
    Ok(AccountInfo {
        address: json::string(&account, "address")?.to_owned(),
        public_key: text("publicKey")?,
        nonce: json::decimal_u64(&account, "nonce")?,
        balances: Vec::new(),
        vote: Vec::new(),
        second_public_key: text("secondPublicKey")?,
        validator_name: None,
    })
}

fn read_request(object: &Map<String, Value>) -> Result<DraftRequest> {
    let operation = read_operation(json::object(
        json::member(object, "operation")?,
        "operation",
    )?)?;
    let memo = json::optional_string(object, "memo")?.map(str::to_owned);
    let fee = match json::optional(object, "fee") {
        None => FeeChoice::Minimum,
        Some(fee) => {
            let fee = json::object(fee, "fee")?;
            match json::string(fee, "kind")? {
                "minimum" => FeeChoice::Minimum,
                "exact" => FeeChoice::Exact(json::amount(fee, "amount")?),
                "multiplier" => FeeChoice::Multiplier {
                    basis_points: u32::try_from(json::unsigned(
                        fee,
                        "basisPoints",
                        u64::from(u32::MAX),
                    )?)
                    .map_err(|_| BindingError::argument("basisPoints is out of range"))?,
                },
                other => {
                    return Err(BindingError::argument(format!(
                        "no fee choice is {other:?}"
                    )));
                }
            }
        }
    };
    Ok(DraftRequest {
        operation,
        memo,
        fee,
    })
}

fn read_operation(object: &Map<String, Value>) -> Result<Operation> {
    let kind = json::string(object, "kind")?;
    Ok(match kind {
        "transfer" => Operation::Transfer {
            recipients: json::array(object, "to")?
                .iter()
                .map(|recipient| {
                    let recipient = json::object(recipient, "a recipient")?;
                    Ok(Recipient {
                        address: Address::parse_any_network(json::string(recipient, "address")?)?,
                        amount: json::amount(recipient, "amount")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        },
        "vote" => Operation::Vote {
            entries: json::array(object, "entries")?
                .iter()
                .map(|entry| {
                    let entry = json::object(entry, "a vote entry")?;
                    Ok(VoteEntry {
                        validator: json::string(entry, "validator")?.to_owned(),
                        basis_points: u16::try_from(json::unsigned(
                            entry,
                            "basisPoints",
                            u64::from(u16::MAX),
                        )?)
                        .map_err(|_| BindingError::argument("basisPoints is out of range"))?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        },
        "burn" => Operation::Burn {
            amount: json::amount(object, "amount")?,
        },
        "register-second-key" => Operation::RegisterSecondKey {
            public_key: PublicKeyBytes::from_hex(json::string(object, "publicKey")?).map_err(
                |_| BindingError::new("InvalidKey", "the second key is not 33 bytes of hex"),
            )?,
        },
        "register-validator" => Operation::RegisterValidator {
            name: json::string(object, "name")?.to_owned(),
        },
        "resign-validator" => Operation::ResignValidator {
            kind: match json::string(object, "resignation")? {
                "temporary" => Resignation::Temporary,
                "permanent" => Resignation::Permanent,
                "revoke" => Resignation::Revoke,
                other => {
                    return Err(BindingError::argument(format!(
                        "no resignation is {other:?}: use temporary, permanent or revoke"
                    )));
                }
            },
        },
        other => {
            return Err(BindingError::argument(format!("no operation is {other:?}")));
        }
    })
}

fn read_key(text: &str) -> Result<PublicKey> {
    PublicKey::from_hex(text)
        .map_err(|_| BindingError::new("InvalidKey", "the public key is not a valid key"))
}

fn read_facts(object: &Map<String, Value>) -> Result<OnlineFacts> {
    Ok(OnlineFacts {
        sender: read_key(json::string(object, "sender")?)?,
        nonce: json::decimal_u64(object, "nonce")?,
        height: u32::try_from(json::unsigned(object, "height", u64::from(u32::MAX))?)
            .map_err(|_| BindingError::argument("height is out of range"))?,
        second_key: json::optional_string(object, "secondKey")?
            .map(read_key)
            .transpose()?,
    })
}

fn fee_json(fee: &ResolvedFee) -> Value {
    json!({
        "amount": amount_value(fee.amount),
        "source": fee.source.as_str(),
        "floor": fee.floor.map(amount_value),
    })
}

fn operation_json(operation: &Operation) -> Value {
    match operation {
        Operation::Transfer { recipients } => json!({
            "kind": "transfer",
            "to": recipients
                .iter()
                .map(|recipient| json!({
                    "address": recipient.address.to_string(),
                    "amount": amount_value(recipient.amount),
                }))
                .collect::<Vec<_>>(),
        }),
        Operation::Vote { entries } => json!({
            "kind": "vote",
            "entries": entries
                .iter()
                .map(|entry| json!({ "validator": entry.validator, "basisPoints": entry.basis_points }))
                .collect::<Vec<_>>(),
        }),
        Operation::Burn { amount } => json!({ "kind": "burn", "amount": amount_value(*amount) }),
        Operation::RegisterSecondKey { public_key } => {
            json!({ "kind": "register-second-key", "publicKey": public_key.to_hex() })
        }
        Operation::RegisterValidator { name } => {
            json!({ "kind": "register-validator", "name": name })
        }
        Operation::ResignValidator { kind } => {
            json!({ "kind": "resign-validator", "resignation": kind.as_str() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::{devnet, devnet_profile as profile};

    const RECIPIENT: &str = "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF";

    fn facts(key: &Key) -> String {
        json!({
            "sender": hex::encode(key.public_key().unwrap()),
            "nonce": "1",
            "height": 2,
        })
        .to_string()
    }

    #[test]
    fn facts_from_what_the_node_reported() {
        let chain = devnet();
        let key = Key::from_legacy_passphrase(&profile(), "sender".to_owned()).unwrap();
        let sender = hex::encode(key.public_key().unwrap());
        let address = key.address().unwrap();
        let status = r#"{"height":"80","synced":true,"blocksBehind":"0","chainTime":"656"}"#;
        let second = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let account = json!({
            "address": address, "publicKey": sender, "nonce": "4",
            "balances": [{ "asset": "ROOT", "amount": "1" }], "vote": [], "secondPublicKey": second,
        })
        .to_string();
        let facts: Value =
            serde_json::from_str(&online_facts(&chain, &sender, Some(&account), status).unwrap())
                .unwrap();
        assert_eq!(
            facts,
            json!({ "sender": sender, "nonce": "5", "height": 81, "secondKey": second })
        );
        let fresh: Value =
            serde_json::from_str(&online_facts(&chain, &sender, None, status).unwrap()).unwrap();
        assert_eq!(
            (fresh["nonce"].as_str(), fresh["secondKey"].is_null()),
            (Some("1"), true)
        );

        let stranger =
            json!({ "address": RECIPIENT, "nonce": "1", "balances": [], "vote": [] }).to_string();
        assert_eq!(
            online_facts(&chain, &sender, Some(&stranger), status)
                .unwrap_err()
                .code(),
            "WrongKey"
        );
        assert_eq!(
            online_facts(&chain, "02zz", None, status)
                .unwrap_err()
                .code(),
            "InvalidKey"
        );
        for bad in ["{}", r#"{"height":80}"#, "["] {
            assert_eq!(
                online_facts(&chain, &sender, None, bad).unwrap_err().code(),
                "InvalidArgument",
                "{bad}"
            );
        }
    }

    #[test]
    fn build_sign_and_travel() {
        let chain = devnet();
        let key = Key::from_legacy_passphrase(&profile(), "sender".to_owned()).unwrap();
        let request = json!({
            "operation": { "kind": "transfer", "to": [{ "address": RECIPIENT, "amount": "150000000" }] },
            "memo": "invoice 42",
            "fee": { "kind": "exact", "amount": "1000000" },
        })
        .to_string();
        let draft = build(&chain, &request, &facts(&key)).unwrap();
        let described: Value = serde_json::from_str(&summary(&draft)).unwrap();
        assert_eq!(described["kind"], "transfer");
        assert_eq!(described["amount"], "150000000");
        assert_eq!(described["fee"]["amount"], "1000000");
        assert_eq!(described["fee"]["source"], "explicit");
        assert_eq!(described["operation"]["to"][0]["address"], RECIPIENT);

        let signed = sign(&draft, &key, None, Aux::random()).unwrap();
        assert!(signed.is_verified());
        assert_eq!(signed.id().len(), 64);
        let json: Value = serde_json::from_str(&signed.json().to_string()).unwrap();
        assert_eq!(json["id"], signed.id());

        // Built here, signed elsewhere, and back.
        let pinned = chain.profile().clone();
        let again = deserialize(&draft.serialize(), &pinned).unwrap();
        assert_eq!(summary(&again), summary(&draft));
        let back = signed_deserialize(
            &sign(&again, &key, None, Aux::random()).unwrap().serialize(),
            &pinned,
        )
        .unwrap();
        assert!(back.is_verified());
        assert_eq!(
            deserialize(&draft.serialize(), &profile())
                .unwrap_err()
                .code(),
            "NetworkMismatch"
        );
        let read = signed_from_json(&chain, &signed.json().to_string(), 2).unwrap();
        assert_eq!(read.id(), signed.id());
        let decoded = signed_decode(&chain, signed.bytes(), 2).unwrap();
        assert_eq!(signed_summary(&decoded), signed_summary(&signed));
        assert!(to_submit(&signed).is_ok());

        let other = Key::from_legacy_passphrase(&profile(), "other".to_owned()).unwrap();
        assert_eq!(
            sign(&draft, &other, None, Aux::random())
                .unwrap_err()
                .code(),
            "WrongKey"
        );
    }

    #[test]
    fn requests_are_checked() {
        let chain = devnet();
        let key = Key::from_legacy_passphrase(&profile(), "sender".to_owned()).unwrap();
        let attempt =
            |request: Value| build(&chain, &request.to_string(), &facts(&key)).map(|_| ());
        let code = |request: Value| attempt(request).unwrap_err().code();
        assert_eq!(
            code(
                json!({ "operation": { "kind": "transfer", "to": [] }, "fee": { "kind": "exact", "amount": "1" } })
            ),
            "NoRecipients"
        );
        assert_eq!(
            code(
                json!({ "operation": { "kind": "transfer", "to": [{ "address": RECIPIENT, "amount": "1" }] }, "fee": { "kind": "multiplier", "basisPoints": 9999 } })
            ),
            "InvalidFee"
        );
        assert_eq!(
            code(json!({ "operation": { "kind": "swap" } })),
            "InvalidArgument"
        );
        assert_eq!(
            code(
                json!({ "operation": { "kind": "transfer", "to": [{ "address": "x", "amount": "1" }] } })
            ),
            "InvalidAddress"
        );
        assert_eq!(
            code(
                json!({ "operation": { "kind": "vote", "entries": [{ "validator": "a", "basisPoints": 5000 }] }, "fee": { "kind": "exact", "amount": "1" } })
            ),
            "InvalidVote"
        );
        // The minimum is the exact floor.
        let vote = json!({ "operation": { "kind": "vote", "entries": [{ "validator": "b", "basisPoints": 4000 }, { "validator": "a", "basisPoints": 6000 }] } }).to_string();
        let draft = build(&chain, &vote, &facts(&key)).unwrap();
        let described: Value = serde_json::from_str(&summary(&draft)).unwrap();
        assert_eq!(described["fee"]["source"], "floor");
        let size = described["size"].as_u64().unwrap();
        let floor = (98 + size.div_ceil(2)) * 6173;
        assert_eq!(described["fee"]["amount"], floor.to_string());
        assert_eq!(described["fee"]["floor"], floor.to_string());
        assert_eq!(described["operation"]["entries"][0]["validator"], "a");
        let burn = json!({ "operation": { "kind": "burn", "amount": "2000000" } }).to_string();
        let draft = build(&chain, &burn, &facts(&key)).unwrap();
        let described: Value = serde_json::from_str(&summary(&draft)).unwrap();
        assert_eq!(
            (&described["fee"]["amount"], &described["fee"]["source"]),
            (&json!("0"), &json!("floor"))
        );
    }
}
