//! Heartwood's golden vectors (`vectors/heartwood/`, generated from the reference implementation)
//! run through the SDK's public API.
//!
//! Each record either gives the reference's outcome through the SDK, or is a documented
//! difference whose outcome is checked, or is skipped by an explicit rule because the SDK has no
//! such operation (blocks, peer status, the legacy Schnorr scheme). Every class ends by asserting
//! how many records took each path, so a new record is never skipped without a change here.

// Tests may panic on a broken vector or fixture: that is how they fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::HashMap;

use common::{
    DEVNET, Outcome, Record, Tally, VectorFile, check_devnet, check_manifest, compare,
    devnet_profile, json_text, run_class, vectors_dir,
};
use heartwood_crypto::crypto::hash::sha256;
use heartwood_crypto::transactions::TransactionType;
use heartwood_crypto::transactions::codec::HEADER_SIZE;
use heartwood_crypto::utils::{hex, js};
use heartwood_crypto::{Aux, Signature};
use iceroot_sdk_core::address::Address;
use iceroot_sdk_core::amount::Amount;
use iceroot_sdk_core::error::{AddressProblem, TransactionProblem, VoteProblem};
use iceroot_sdk_core::fee::FeeChoice;
use iceroot_sdk_core::keys::Account;
use iceroot_sdk_core::message;
use iceroot_sdk_core::phrase::bip39;
use iceroot_sdk_core::transaction::{
    Draft, DraftRequest, OnlineFacts, Operation, Recipient, Resignation, SignedTransaction,
    VoteEntry, vote_from_percentages,
};
use iceroot_sdk_core::{Chain, Error, OperationKind, PublicKey, PublicKeyBytes};
use serde_json::{Map, Value, json};

/// The fixed aux the oracle signs with (0x42 × 32).
const AUX: Aux = Aux::fixed([0x42; 32]);

fn load(class: &str) -> VectorFile {
    VectorFile::load("heartwood", class)
}

fn chain() -> &'static Chain {
    &DEVNET.chain
}

fn account(passphrase: &str) -> Account {
    Account::from_legacy_passphrase(chain().profile(), passphrase).expect("a legacy key")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("a string")
}

#[test]
fn manifest() {
    check_manifest(&vectors_dir().join("heartwood"));
}

// ------------------------------------------------------------------------------------------------
// V01: keys and addresses.

#[test]
fn v01_keys_addresses() {
    let file = load("V01-keys-addresses");
    check_devnet(&file);
    let tally = run_class(&file, |record| {
        let input = &record.input;
        match record.op.as_str() {
            // The public key determines the secret key (one scalar per point), so an equal public
            // key is an equal key; the SDK never hands the secret key out.
            "keys.fromPassphrase" => {
                let account = account(text(&input["passphrase"]));
                let expected = record.expected.as_ref().expect("an output");
                compare(
                    &expected["publicKey"],
                    &json!(account.public_key().to_hex()),
                )
            }
            "address.fromPublicKey" => {
                let byte =
                    u8::try_from(input["networkByte"].as_u64().expect("a byte")).expect("u8");
                match (
                    &record.expected,
                    PublicKey::from_hex(text(&input["publicKey"])),
                ) {
                    (Ok(expected), Ok(key)) => {
                        let address = Address::from_public_key_for_network_byte(&key, byte);
                        compare(expected, &json!({ "address": address.to_string() }))
                    }
                    (Err(error), Err(_)) => compare(&error["class"], &json!("PublicKeyError")),
                    (expected, actual) => {
                        Outcome::Failed(format!("expected {expected:?}, got {actual:?}"))
                    }
                }
            }
            "address.validate" => {
                let byte = input["networkByte"].as_u64().map_or(90, |byte| byte as u8);
                let result = Address::parse_for_network_byte(text(&input["address"]), byte);
                let expected = record.expected.as_ref().expect("an output");
                match (&result, expected["valid"].as_bool()) {
                    (
                        Err(Error::InvalidAddress {
                            problem: AddressProblem::Length { .. },
                        }),
                        Some(true),
                    ) => Outcome::Divergent(
                        "the reference validates only the Base58Check form and the first byte; \
                         the SDK also refuses a payload that is not 21 bytes",
                    ),
                    _ => compare(expected, &json!({ "valid": result.is_ok() })),
                }
            }
            "address.toBuffer" => {
                let text = text(&input["address"]);
                let parsed = Address::parse_any_network(text);
                match (&record.expected, parsed) {
                    (Ok(expected), Ok(address)) => {
                        let error = match Address::parse(text, chain().profile()) {
                            Err(Error::InvalidAddress {
                                problem: AddressProblem::WrongNetwork { expected, actual },
                            }) => json!(format!(
                                "Expected address network byte {expected}, but got {actual}."
                            )),
                            _ => Value::Null,
                        };
                        compare(
                            expected,
                            &json!({
                                "addressBuffer": hex::encode(address.as_bytes()),
                                "addressError": error,
                            }),
                        )
                    }
                    (
                        Ok(_),
                        Err(Error::InvalidAddress {
                            problem: AddressProblem::Length { .. },
                        }),
                    ) => Outcome::Divergent(
                        "the reference reads a Base58Check payload of any length; the SDK \
                         refuses one that is not 21 bytes",
                    ),
                    (
                        Err(error),
                        Err(Error::InvalidAddress {
                            problem: AddressProblem::Checksum,
                        }),
                    ) if error["message"] == "Invalid checksum" => Outcome::Matched,
                    (expected, actual) => {
                        Outcome::Failed(format!("expected {expected:?}, got {actual:?}"))
                    }
                }
            }
            "publicKey.verify" => {
                let valid = hex::decode(text(&input["publicKey"]))
                    .is_ok_and(|bytes| PublicKey::from_bytes(&bytes).is_ok());
                compare(
                    record.expected.as_ref().expect("an output"),
                    &json!({ "valid": valid }),
                )
            }
            other => Outcome::Failed(format!("unknown operation {other}")),
        }
    });
    assert_eq!(
        tally,
        Tally {
            matched: 81,
            divergent: 4,
            skipped: 0
        }
    );
}

// ------------------------------------------------------------------------------------------------
// Transactions: V02, V03 and the transaction records of V07 and V12.

/// The reference's error class for a refusal of received bytes.
fn bytes_class(problem: &TransactionProblem) -> &'static str {
    match problem {
        TransactionProblem::Rules(_) => "TransactionSchemaError",
        TransactionProblem::UnsupportedVersion(_) => "TransactionVersionError",
        _ => "InvalidTransactionBytesError",
    }
}

/// The reference's error class for a refusal of the JSON form.
fn json_class(problem: &TransactionProblem) -> String {
    match problem {
        TransactionProblem::Rules(_) => "TransactionSchemaError".into(),
        TransactionProblem::UnsupportedVersion(_) => "TransactionVersionError".into(),
        TransactionProblem::MemoTooLong => "MemoLengthExceededError".into(),
        TransactionProblem::TooManyTransfers => "MaximumTransferCountExceededError".into(),
        TransactionProblem::VoteTooLarge => "VoteAssetTooLargeError".into(),
        TransactionProblem::Json(message) => format!("unexpected: {message}"),
        _ => "InvalidTransactionBytesError".into(),
    }
}

/// The reference's error class for a refusal while building.
fn build_class(error: &Error) -> String {
    match error {
        Error::MemoTooLong { .. } => "MemoLengthExceededError".into(),
        Error::TooManyRecipients { .. } => "MaximumTransferCountExceededError".into(),
        Error::InvalidVote {
            problem: VoteProblem::TooLarge { .. },
        } => "VoteAssetTooLargeError".into(),
        Error::NoRecipients { .. }
        | Error::InvalidVote { .. }
        | Error::InvalidName { .. }
        | Error::InvalidAmount { .. }
        | Error::InvalidFee { .. } => "TransactionSchemaError".into(),
        Error::InvalidTransaction { problem } => bytes_class(problem).into(),
        other => format!("unexpected: {other}"),
    }
}

/// `{id, hex, json, isVerified}` of a transaction, as the oracle writes it.
fn tx_output(tx: &SignedTransaction) -> Value {
    json!({
        "id": tx.id(),
        "hex": hex::encode(tx.bytes()),
        "json": tx.json(),
        "isVerified": tx.is_verified(),
    })
}

/// The documented differences of the transaction classes, keyed by operation and record name.
/// Whether a refusal is the one a documented difference names.
type Recognise = fn(&TransactionProblem) -> bool;

fn divergence(op: &str, name: &str) -> Option<(&'static str, Recognise)> {
    const REMOVED: &str = "a removed type: the reference decodes it and refuses it when it is \
        applied; heartwood-crypto refuses it at decode";
    const EXTENDED: &str = "the extended header: the reference decodes it and refuses it when it \
        is applied; heartwood-crypto refuses it at decode";
    const MEMO: &str = "a memo that is not UTF-8: the reference replaces the bad bytes; \
        heartwood-crypto refuses it at decode";
    const MULTI: &str = "multi-signature entries: no account can use them, so the reference \
        refuses the transaction when it is applied; heartwood-crypto refuses it at decode";
    const VOTE_JSON: &str = "an asset.votes that is not an object: heartwood-crypto refuses the \
        JSON";
    let removed = |p: &TransactionProblem| matches!(p, TransactionProblem::RemovedType { .. });
    let extended = |p: &TransactionProblem| matches!(p, TransactionProblem::UnsupportedHeader(1));
    let memo = |p: &TransactionProblem| matches!(p, TransactionProblem::InvalidMemo);
    let multi = |p: &TransactionProblem| matches!(p, TransactionProblem::MultiSignature);
    let votes = |p: &TransactionProblem| matches!(p, TransactionProblem::Json(m) if m.contains("asset.votes"));
    match (op, name) {
        (
            "tx.fromBytes",
            "ipfs-1-5"
            | "htlc-lock-1-8"
            | "htlc-claim-1-9"
            | "htlc-refund-1-10"
            | "multisignature-1-4"
            | "legacy-transfer-1-0"
            | "legacy-vote-1-3",
        ) => Some((REMOVED, removed)),
        (
            "tx.fromBytes",
            "extended-header-other-sender"
            | "extended-header-byte-63-sender"
            | "extended-header-own-sender",
        ) => Some((EXTENDED, extended)),
        (
            "tx.fromBytes",
            "memo-invalid-utf8-wire-signed"
            | "memo-overlong-nul-wire-signed"
            | "memo-surrogate-wire-signed"
            | "memo-truncated-wire-signed"
            | "memo-invalid-utf8-canonical-signed",
        ) => Some((MEMO, memo)),
        (
            "tx.fromBytes",
            "trailing-1" | "trailing-65" | "trailing-66" | "trailing-130" | "resignation-0f",
        ) => Some((MULTI, multi)),
        (
            "tx.fromJson",
            r#"unvote, votes "ab""#
            | "unvote, votes [50,50]"
            | r#"unvote, votes """#
            | "unvote, votes null"
            | "unvote, votes false"
            | "unvote, votes 0",
        ) => Some((VOTE_JSON, votes)),
        _ => None,
    }
}

/// The chain a record runs under: the devnet, or the devnet with the record's own milestones.
fn record_chain(record: &Record) -> Chain {
    match record.input.get("milestones") {
        None => chain().clone(),
        Some(milestones) => {
            let network = serde_json::to_string(&chain().network().to_json()).expect("JSON");
            Chain::from_parts(chain().profile(), &network, text(milestones))
                .expect("the record's milestones load")
        }
    }
}

/// `tx.fromBytes`, through [`SignedTransaction::decode`].
fn from_bytes(record: &Record) -> Outcome {
    if record.input["strict"] == json!(false) {
        return Outcome::Skipped("the SDK decodes received transactions strictly");
    }
    let bytes = hex::decode(text(&record.input["hex"])).expect("hex");
    let name = record.name.as_deref().unwrap_or_default();
    match (
        SignedTransaction::decode(&record_chain(record), &bytes, record.height),
        &record.expected,
        divergence(&record.op, name),
    ) {
        (Err(Error::InvalidTransaction { problem }), _, Some((reason, recognise))) => {
            if recognise(&problem) {
                Outcome::Divergent(reason)
            } else {
                Outcome::Failed(format!("refused with another problem: {problem:?}"))
            }
        }
        (_, _, Some(_)) => Outcome::Failed("a documented difference, not refused".into()),
        (Ok(tx), Ok(expected), None) => compare(expected, &tx_output(&tx)),
        (Err(Error::InvalidTransaction { problem }), Err(error), None) => {
            compare(&error["class"], &json!(bytes_class(&problem)))
        }
        (actual, expected, None) => Outcome::Failed(format!(
            "expected {expected:?}, got {:?}",
            actual.map(|tx| tx.id())
        )),
    }
}

/// `tx.fromJson`, through [`SignedTransaction::from_json`].
fn from_json(record: &Record) -> Outcome {
    let name = record.name.as_deref().unwrap_or_default();
    match (
        SignedTransaction::from_json(chain(), &record.input["json"], record.height),
        &record.expected,
        divergence(&record.op, name),
    ) {
        (Err(Error::InvalidTransaction { problem }), _, Some((reason, recognise))) => {
            if recognise(&problem) {
                Outcome::Divergent(reason)
            } else {
                Outcome::Failed(format!("refused with another problem: {problem:?}"))
            }
        }
        (_, _, Some(_)) => Outcome::Failed("a documented difference, not refused".into()),
        (Ok(tx), Ok(expected), None) => compare(expected, &tx_output(&tx)),
        (Err(Error::InvalidTransaction { problem }), Err(error), None) => {
            compare(&error["class"], &json!(json_class(&problem)))
        }
        (actual, expected, None) => Outcome::Failed(format!(
            "expected {expected:?}, got {:?}",
            actual.map(|tx| tx.id())
        )),
    }
}

/// The votes the reference's `votesAsset` makes of its argument: an object of percentages, or a
/// list of names sharing 100 % (`floor(10000 / n)` basis points each, one more for each of the
/// first `10000 mod n`).
fn builder_votes(argument: &Value) -> Vec<VoteEntry> {
    match argument {
        Value::Object(object) => object
            .iter()
            .map(|(name, percent)| VoteEntry {
                validator: name.clone(),
                basis_points: (percent.as_f64().expect("a percentage") * 100.0).round() as u16,
            })
            .collect(),
        Value::Array(names) => {
            let count = u16::try_from(names.len()).expect("a few names");
            let remainder = usize::from(10_000 % count);
            names
                .iter()
                .enumerate()
                .map(|(index, name)| VoteEntry {
                    validator: text(name).to_owned(),
                    basis_points: 10_000 / count + u16::from(index < remainder),
                })
                .collect()
        }
        other => panic!("votesAsset of {other}"),
    }
}

/// The static fee of `builder` at `height`, which the reference's builders use when no fee is set.
/// The SDK always sets a fee, so the vectors' default is passed explicitly.
fn static_fee(builder: &str, height: u32) -> u64 {
    let kind = match builder {
        "transfer" => TransactionType::Transfer,
        "secondSignature" => TransactionType::SecondSignature,
        "delegateRegistration" => TransactionType::DelegateRegistration,
        "delegateResignation" => TransactionType::DelegateResignation,
        "burn" => TransactionType::Burn,
        "vote" => TransactionType::Vote,
        other => panic!("builder {other}"),
    };
    chain().params(height).as_json()["fees"]["staticFees"]
        .get(kind.key())
        .and_then(Value::as_u64)
        .unwrap_or(kind.default_static_fee())
}

/// `tx.build`: the reference's builder calls, translated to an SDK draft signed with the fixed aux.
fn build(record: &Record) -> Outcome {
    let input = &record.input;
    let builder = text(&input["builder"]);
    if !matches!(
        builder,
        "transfer"
            | "secondSignature"
            | "delegateRegistration"
            | "delegateResignation"
            | "burn"
            | "vote"
    ) {
        return Outcome::Skipped("no builder for a removed type");
    }
    let amount = |value: &Value| text(value).parse::<u64>().expect("a decimal amount");
    let address = |value: &Value| Address::parse_any_network(text(value)).expect("an address");
    let mut recipients: Vec<Recipient> = Vec::new();
    let (mut nonce, mut fee, mut memo) = (0, None, None);
    let mut operation = None;
    for call in input["calls"].as_array().expect("calls") {
        let argument = &call[1];
        match text(&call[0]) {
            "nonce" => nonce = amount(argument),
            "fee" => fee = Some(amount(argument)),
            "memo" => memo = Some(text(argument).to_owned()),
            "recipientId" => {
                let amount = recipients.first().map_or(Amount::ZERO, |r| r.amount);
                recipients = vec![Recipient {
                    address: address(argument),
                    amount,
                }];
            }
            "amount" if builder == "burn" => {
                operation = Some(Operation::Burn {
                    amount: Amount::from(amount(argument)),
                });
            }
            "amount" => {
                let first = recipients.first().expect("recipientId before amount");
                recipients = vec![Recipient {
                    address: first.address,
                    amount: Amount::from(amount(argument)),
                }];
            }
            "addTransfer" => recipients.push(Recipient {
                address: address(argument),
                amount: Amount::from(amount(&call[2])),
            }),
            "signatureAsset" => {
                let key = account(text(argument)).public_key().to_compressed();
                operation = Some(Operation::RegisterSecondKey {
                    public_key: PublicKeyBytes::from_array(*key.as_bytes()),
                });
            }
            "usernameAsset" => {
                operation = Some(Operation::RegisterValidator {
                    name: text(argument).to_owned(),
                });
            }
            "resignationTypeAsset" => {
                let kind = match argument.as_u64() {
                    Some(0) => Resignation::Temporary,
                    Some(1) => Resignation::Permanent,
                    Some(2) => Resignation::Revoke,
                    other => panic!("resignation type {other:?}"),
                };
                operation = Some(Operation::ResignValidator { kind });
            }
            "votesAsset" => {
                operation = Some(Operation::Vote {
                    entries: builder_votes(argument),
                });
            }
            "senderId" => return Outcome::Skipped("a sender address other than the key's"),
            other => panic!("builder method {other} is not translated"),
        }
    }
    let operation = match builder {
        "transfer" => Operation::Transfer { recipients },
        _ => operation.expect("an asset call"),
    };
    let sender = account(text(&input["sign"]));
    let second = input.get("secondSign").map(|value| account(text(value)));
    let request = DraftRequest {
        operation,
        memo,
        fee: FeeChoice::Exact(Amount::from(
            fee.unwrap_or_else(|| static_fee(builder, record.height)),
        )),
    };
    let facts = OnlineFacts {
        sender: sender.public_key().clone(),
        nonce,
        height: record.height,
        second_key: second.as_ref().map(|second| second.public_key().clone()),
    };
    let signed = Draft::build(chain(), &request, &facts)
        .and_then(|draft| draft.sign_with(&sender, second.as_ref(), AUX));
    match (&record.expected, signed) {
        (Ok(expected), Ok(tx)) => {
            let mut output = tx_output(&tx);
            output["strict"] = match SignedTransaction::decode(chain(), tx.bytes(), record.height) {
                Ok(decoded) => {
                    json!({ "ok": true, "id": decoded.id(), "isVerified": decoded.is_verified() })
                }
                Err(Error::InvalidTransaction { problem }) => {
                    json!({ "ok": false, "error": { "class": bytes_class(&problem) } })
                }
                Err(other) => json!({ "ok": false, "error": other.to_string() }),
            };
            compare(expected, &output)
        }
        (Err(error), Err(ours)) => compare(&error["class"], &json!(build_class(&ours))),
        (expected, actual) => Outcome::Failed(format!(
            "expected {expected:?}, got {:?}",
            actual.map(|tx| tx.id())
        )),
    }
}

fn transaction_record(record: &Record) -> Option<Outcome> {
    match record.op.as_str() {
        "tx.build" => Some(build(record)),
        "tx.fromBytes" => Some(from_bytes(record)),
        "tx.fromJson" => Some(from_json(record)),
        _ => None,
    }
}

#[test]
fn v02_transactions() {
    let file = load("V02-transactions");
    check_devnet(&file);
    let tally = run_class(&file, |record| {
        transaction_record(record).unwrap_or(Outcome::Failed("unknown operation".into()))
    });
    assert_eq!(
        tally,
        Tally {
            matched: 273,
            divergent: 6,
            skipped: 2
        }
    );
}

#[test]
fn v03_noncanonical_and_removed() {
    let file = load("V03-noncanonical-removed");
    check_devnet(&file);
    let tally = run_class(&file, |record| match record.op.as_str() {
        "handler.activation" => Outcome::Skipped(
            "the SDK has no handler registry: a removed type is refused when it is decoded",
        ),
        _ => transaction_record(record).unwrap_or(Outcome::Failed("unknown operation".into())),
    });
    assert_eq!(
        tally,
        Tally {
            matched: 36,
            divergent: 20,
            skipped: 21
        }
    );
}

// ------------------------------------------------------------------------------------------------
// V04 and V11: signatures and the published external vectors.

/// The secret keys of the passphrases whose keys the V01 class records, by secret key hex.
fn known_passphrases() -> HashMap<String, String> {
    load("V01-keys-addresses")
        .records
        .iter()
        .filter(|record| record.op == "keys.fromPassphrase")
        .map(|record| {
            let expected = record.expected.as_ref().expect("an output");
            (
                text(&expected["privateKey"]).to_owned(),
                text(&record.input["passphrase"]).to_owned(),
            )
        })
        .collect()
}

/// The 32 bytes BIP340 signs for `message`: the message itself when it is 32 bytes long, else its
/// SHA-256, as the reference passes messages.
fn signed_digest(message: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(message).unwrap_or_else(|_| sha256(message))
}

fn bip340_sign(record: &Record, passphrases: &HashMap<String, String>) -> Outcome {
    let input = &record.input;
    let Some(passphrase) = passphrases.get(text(&input["privateKey"])) else {
        return Outcome::Skipped("a raw secret key: the SDK signs only with accounts");
    };
    let account = account(passphrase);
    let message = hex::decode(text(&input["message"])).expect("hex");
    let aux = Aux::fixed(hex::decode_array(text(&input["aux"])).expect("32 bytes of aux"));
    // The reference signs the raw 32 bytes, which no public SDK function does (message signing
    // always hashes first), so the digest goes through the test seam.
    match message::test_seam::sign_digest(&account, &signed_digest(&message), aux) {
        Ok(signature) => compare(
            record.expected.as_ref().expect("an output"),
            &json!({ "signature": signature.to_hex() }),
        ),
        Err(error) => Outcome::Failed(error.to_string()),
    }
}

fn bip340_verify(record: &Record) -> Outcome {
    let input = &record.input;
    let message = hex::decode(text(&input["message"])).expect("hex");
    let public_key = hex::decode(text(&input["publicKey"])).expect("hex");
    let valid = Signature::from_hex(text(&input["signature"])).is_ok_and(|signature| {
        message::verify_digest(&signed_digest(&message), &signature, &public_key)
    });
    compare(
        record.expected.as_ref().expect("an output"),
        &json!({ "valid": valid }),
    )
}

#[test]
fn v04_signatures() {
    let file = load("V04-signatures");
    check_devnet(&file);
    let passphrases = known_passphrases();
    let tally = run_class(&file, |record| match record.op.as_str() {
        "sig.bip340.sign" => bip340_sign(record, &passphrases),
        "sig.bip340.verify" => bip340_verify(record),
        "sig.legacy.sign" | "sig.legacy.verify" | "status.preimage" => Outcome::Skipped(
            "the legacy Schnorr scheme signs peer status attestations only; the SDK never uses it",
        ),
        "tx.preimages" => Outcome::Skipped(
            "signing preimages of received transactions are internal to heartwood-crypto",
        ),
        other => Outcome::Failed(format!("unknown operation {other}")),
    });
    assert_eq!(
        tally,
        Tally {
            matched: 334,
            divergent: 0,
            skipped: 371
        }
    );
}

#[test]
fn v11_external() {
    let file = load("V11-external");
    let passphrases = known_passphrases();
    let tally = run_class(&file, |record| {
        let input = &record.input;
        match record.op.as_str() {
            "external.file" => {
                let path = vectors_dir().join("heartwood").join(text(&input["file"]));
                let bytes = std::fs::read(path).expect("the external file");
                compare(
                    record.expected.as_ref().expect("an output"),
                    &json!({ "sha256": hex::encode(&sha256(&bytes)), "length": bytes.len() }),
                )
            }
            "bip39.entropyToMnemonic" => {
                let entropy = hex::decode(text(&input["entropy"])).expect("hex");
                let mnemonic = bip39::entropy_to_mnemonic(&entropy).expect("a mnemonic");
                compare(
                    record.expected.as_ref().expect("an output"),
                    &json!({ "mnemonic": mnemonic.as_str() }),
                )
            }
            "sig.bip340.sign" => bip340_sign(record, &passphrases),
            "sig.bip340.verify" => bip340_verify(record),
            "sig.legacy.sign" | "sig.legacy.verify" => {
                Outcome::Skipped("the legacy Schnorr scheme signs peer status attestations only")
            }
            other => Outcome::Failed(format!("unknown operation {other}")),
        }
    });
    assert_eq!(
        tally,
        Tally {
            matched: 46,
            divergent: 0,
            skipped: 27
        }
    );
}

// ------------------------------------------------------------------------------------------------
// V05, V06, V07, V10, V12 and V19.

#[test]
fn v05_blocks() {
    let file = load("V05-blocks");
    check_devnet(&file);
    let tally = run_class(&file, |_| {
        Outcome::Skipped("blocks: the SDK builds and decodes no blocks")
    });
    assert_eq!(tally.skipped, file.records.len());
}

fn amount_input(value: &Value) -> Amount {
    Amount::from(text(value).parse::<u64>().expect("a decimal amount"))
}

#[test]
fn v06_arithmetic() {
    let file = load("V06-arithmetic");
    check_devnet(&file);
    let tally = run_class(&file, |record| {
        let economics = chain().economics(record.height);
        let input = &record.input;
        match record.op.as_str() {
            "fee.burned" => {
                let burned = economics
                    .burned_fee(amount_input(&input["fee"]))
                    .expect("a 64-bit fee");
                compare(
                    record.expected.as_ref().expect("an output"),
                    &json!({ "burnedFee": burned.to_string() }),
                )
            }
            "reward.calculate" => {
                let rank = u32::try_from(input["rank"].as_u64().expect("a rank")).expect("u32");
                match (&record.expected, economics.reward_for_rank(rank)) {
                    (Ok(expected), Some(reward)) => {
                        compare(expected, &json!({ "reward": reward.to_string() }))
                    }
                    (Err(_), None) => Outcome::Matched,
                    (expected, actual) => {
                        Outcome::Failed(format!("expected {expected:?}, got {actual:?}"))
                    }
                }
            }
            "reward.donations" => {
                let shares: Vec<Value> = economics
                    .donations_of(amount_input(&input["reward"]))
                    .expect("a 64-bit reward")
                    .into_iter()
                    .map(|(address, amount)| json!([address.to_string(), amount.to_string()]))
                    .collect();
                compare(
                    record.expected.as_ref().expect("an output"),
                    &json!({ "donations": shares }),
                )
            }
            "fee.minimum" => fee_minimum(record),
            "block.make" => Outcome::Skipped("blocks: the SDK builds no blocks"),
            other => Outcome::Failed(format!("unknown operation {other}")),
        }
    });
    assert_eq!(
        tally,
        Tally {
            matched: 108,
            divergent: 0,
            skipped: 2
        }
    );
}

/// The reference's type key of an operation, as the fee table names it.
fn fee_key(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Transfer => "transfer",
        OperationKind::Vote => "vote",
        OperationKind::Burn => "burn",
        OperationKind::RegisterSecondKey => "secondSignature",
        OperationKind::RegisterValidator => "delegateRegistration",
        OperationKind::ResignValidator => "delegateResignation",
    }
}

/// `fee.minimum`: the transaction in `hex`, decoded under the record's chain, and the exact fee
/// floor [`Chain::fee_floor`] gives for its kind and full size.
fn fee_minimum(record: &Record) -> Outcome {
    let chain = match record.input.get("milestones") {
        None => chain().clone(),
        Some(milestones) => {
            let network = serde_json::to_string(&chain().network().to_json()).expect("JSON");
            match Chain::from_parts(chain().profile(), &network, text(milestones)) {
                Ok(chain) => chain,
                Err(Error::BadResponse { reason })
                    if reason.contains("dynamicFees")
                        || reason.contains("blocksToRevokeDelegateResignation") =>
                {
                    return match &record.expected {
                        // The reference fails too, when it checks the fee.
                        Err(_) => Outcome::Matched,
                        Ok(_) => Outcome::Divergent(
                            "a fee table or revoke delay with a value of the wrong type: the \
                             reference loads it and coerces the value when it checks a fee; \
                             heartwood-crypto refuses the milestones at load",
                        ),
                    };
                }
                Err(other) => return Outcome::Failed(format!("the milestones: {other}")),
            }
        }
    };
    let bytes = hex::decode(text(&record.input["hex"])).expect("hex");
    let tx = match SignedTransaction::decode(&chain, &bytes, record.height) {
        Ok(tx) => tx,
        Err(error) => return Outcome::Failed(format!("the transaction: {error}")),
    };
    let Some(floor) = chain.fee_floor(tx.kind(), bytes.len(), record.height) else {
        // No enabled dynamic fee table: the reference's floor is zero, while the SDK reports no
        // floor at all and refuses a minimum fee.
        let zero = json!({ "key": fee_key(tx.kind()), "size": bytes.len(), "minimumFee": "0" });
        return match &record.expected {
            Ok(expected) => match compare(expected, &zero) {
                Outcome::Matched => Outcome::Divergent(
                    "no enabled fee table: the reference's floor is zero; the SDK has no floor, \
                     since the node's pool then applies its own settings, and a draft needs an \
                     exact fee",
                ),
                other => other,
            },
            Err(error) => Outcome::Failed(format!("the reference refused with {error}")),
        };
    };
    let actual = json!({
        "key": fee_key(tx.kind()),
        "size": bytes.len(),
        "minimumFee": floor.to_string(),
    });
    match &record.expected {
        Ok(expected)
            if expected["minimumFee"]
                .as_str()
                .is_some_and(|fee| fee.starts_with('-')) =>
        {
            let mut zero = expected.clone();
            zero["minimumFee"] = json!("0");
            match compare(&zero, &actual) {
                Outcome::Matched => Outcome::Divergent(
                    "a floor below zero (negative add-on bytes): every fee meets it, and the SDK \
                     reports it as zero, the least fee",
                ),
                other => other,
            }
        }
        Ok(expected) => compare(expected, &actual),
        Err(error) => Outcome::Failed(format!("the reference refused with {error}")),
    }
}

#[test]
fn v19_fee_floor() {
    let file = load("V19-fee-floor");
    check_devnet(&file);
    let tally = run_class(&file, |record| match record.op.as_str() {
        "fee.minimum" => fee_minimum(record),
        other => Outcome::Failed(format!("unknown operation {other}")),
    });
    // Divergent: 35 milestones heartwood-crypto refuses at load, 4 floors below zero, and 36
    // transactions under no enabled fee table (absent, null, disabled or without `enabled`, and
    // heights where a changing table is off), where the SDK has no floor.
    assert_eq!(
        tally,
        Tally {
            matched: 172,
            divergent: 75,
            skipped: 0
        }
    );
}

/// The vote asset bytes of `entries`, taken from an SDK draft's unsigned bytes: after the header
/// and the memo length byte (no memo).
fn vote_asset(entries: Vec<VoteEntry>, height: u32) -> Vec<u8> {
    let sender = account("vote asset");
    let request = DraftRequest {
        operation: Operation::Vote { entries },
        memo: None,
        fee: FeeChoice::Exact(Amount::from(1u64)),
    };
    let facts = OnlineFacts {
        sender: sender.public_key().clone(),
        nonce: 1,
        height,
        second_key: None,
    };
    let draft = Draft::build(chain(), &request, &facts).expect("a vote draft");
    draft.unsigned_bytes()[HEADER_SIZE + 1..].to_vec()
}

fn percentages(entries: &[(&str, f64)]) -> Map<String, Value> {
    entries
        .iter()
        .map(|(name, percent)| ((*name).to_owned(), json!(percent)))
        .collect()
}

/// `vote.splits`: every two-way split of 100 % in cents.
fn vote_splits(record: &Record) -> Outcome {
    let input = &record.input;
    let names: Vec<&str> = input["names"]
        .as_array()
        .expect("names")
        .iter()
        .map(text)
        .collect();
    let (from, to) = (
        input["from"].as_u64().expect("from"),
        input["to"].as_u64().expect("to"),
    );
    let (mut verdicts, mut assets, mut refused) = (Vec::new(), Vec::new(), Vec::new());
    for a in from..=to {
        let first = a as f64 / 100.0;
        let second = (10_000 - a) as f64 / 100.0;
        let object = percentages(&[(names[0], first), (names[1], second)]);
        let accepted = vote_from_percentages(&object).is_ok();
        if !accepted {
            refused.push(a);
        }
        verdicts.push(if accepted { b'1' } else { b'0' });
        let entries = vec![
            VoteEntry {
                validator: names[0].to_owned(),
                basis_points: (first * 100.0).round() as u16,
            },
            VoteEntry {
                validator: names[1].to_owned(),
                basis_points: (second * 100.0).round() as u16,
            },
        ];
        assets.extend(vote_asset(entries, record.height));
    }
    let mut expected = record.expected.clone().expect("an output");
    let assets_sha256 = expected["assetsSha256"].take();
    let verdicts = compare(
        &expected,
        &json!({
            "splits": to - from + 1,
            "accepted": to - from + 1 - refused.len() as u64,
            "refused": refused,
            "verdictsSha256": hex::encode(&sha256(&verdicts)),
            "assetsSha256": Value::Null,
        }),
    );
    match verdicts {
        Outcome::Matched if assets_sha256 == json!(hex::encode(&sha256(&assets))) => {
            Outcome::Matched
        }
        Outcome::Matched => Outcome::Divergent(
            "the verdicts match; the asset bytes are the codec's in the given order, and an SDK \
             draft always writes a vote in canonical order (largest share first)",
        ),
        other => other,
    }
}

/// `vote.shares`: the vote rules on the doubles within `ulps` units in the last place of every
/// cent, each beside an exact cent that completes the sum.
fn vote_shares(record: &Record) -> Outcome {
    let input = &record.input;
    let (from, to) = (
        u32::try_from(input["from"].as_u64().expect("from")).expect("u32"),
        u32::try_from(input["to"].as_u64().expect("to")).expect("u32"),
    );
    let ulps = i64::try_from(input["ulps"].as_u64().expect("ulps")).expect("i64");
    let (mut verdicts, mut accepted, mut off_cent) = (Vec::new(), 0_u64, Vec::new());
    for cent in from..=to {
        for step in -ulps..=ulps {
            let share = f64::from_bits(
                (f64::from(cent) / 100.0)
                    .to_bits()
                    .checked_add_signed(step)
                    .expect("a positive double"),
            );
            let basis_points = (share * 100.0).round();
            let mut votes = Map::new();
            votes.insert("a".into(), json!(share));
            if basis_points < 10_000.0 {
                votes.insert("b".into(), json!((10_000.0 - basis_points) / 100.0));
            }
            let ok = vote_from_percentages(&votes).is_ok();
            verdicts.push(if ok { b'1' } else { b'0' });
            if ok {
                accepted += 1;
                if step != 0 {
                    off_cent.push(js::number_to_string(share));
                }
            }
        }
    }
    let lines: String = off_cent.iter().map(|share| format!("{share}\n")).collect();
    compare(
        record.expected.as_ref().expect("an output"),
        &json!({
            "shares": u64::from(to - from + 1) * u64::try_from(2 * ulps + 1).expect("u64"),
            "accepted": accepted,
            "offCent": {
                "count": off_cent.len(),
                "first": off_cent.iter().take(20).collect::<Vec<_>>(),
                "sha256": hex::encode(&sha256(lines.as_bytes())),
            },
            "verdictsSha256": hex::encode(&sha256(&verdicts)),
        }),
    )
}

/// A vote share as the reference writes it: the percentage, an integer when it is whole.
fn percent_value(basis_points: u16) -> Value {
    if basis_points.is_multiple_of(100) {
        json!(basis_points / 100)
    } else {
        json!(f64::from(basis_points) / 100.0)
    }
}

#[test]
fn v07_vote_rules() {
    let file = load("V07-vote-rules");
    check_devnet(&file);
    let tally = run_class(&file, |record| match record.op.as_str() {
        "vote.splits" => vote_splits(record),
        "vote.shares" => vote_shares(record),
        "vote.validate" => {
            let object = record.input["votes"].as_object().expect("votes");
            match (&record.expected, vote_from_percentages(object)) {
                // The kept entries as given, in the object's property order.
                (Ok(expected), Ok(kept)) => compare(
                    expected,
                    &json!({
                        "votes": js::property_order(object)
                            .into_iter()
                            .filter(|(name, _)| kept.iter().any(|entry| &entry.validator == *name))
                            .map(|(name, value)| json!([name, value]))
                            .collect::<Vec<_>>(),
                    }),
                ),
                (Err(error), Err(_)) => compare(&error["class"], &json!("TransactionSchemaError")),
                (expected, actual) => {
                    Outcome::Failed(format!("expected {expected:?}, got {actual:?}"))
                }
            }
        }
        "vote.sort" => {
            let entries = builder_votes(&record.input["votes"]);
            let sender = account("vote sort");
            let request = DraftRequest {
                operation: Operation::Vote { entries },
                memo: None,
                fee: FeeChoice::Exact(Amount::from(1u64)),
            };
            let facts = OnlineFacts {
                sender: sender.public_key().clone(),
                nonce: 1,
                height: record.height,
                second_key: None,
            };
            let draft = Draft::build(chain(), &request, &facts).expect("a vote draft");
            let Operation::Vote { entries } = draft.operation() else {
                return Outcome::Failed("not a vote".into());
            };
            let sorted: Vec<Value> = entries
                .iter()
                .map(|entry| json!([entry.validator, percent_value(entry.basis_points)]))
                .collect();
            compare(
                record.expected.as_ref().expect("an output"),
                &json!({ "votes": sorted }),
            )
        }
        _ => transaction_record(record).unwrap_or(Outcome::Failed("unknown operation".into())),
    });
    assert_eq!(
        tally,
        Tally {
            matched: 38,
            divergent: 3,
            skipped: 0
        }
    );
}

#[test]
fn v10_genesis() {
    let file = load("V10-genesis");
    let tally = run_class(&file, |record| {
        let output = record.expected.as_ref().expect("an output");
        let files = &output["files"];
        // The node's crypto configuration of this chain loads, and pins its network hash.
        let configuration = format!(
            r#"{{"network":{},"milestones":{},"genesisBlock":{}}}"#,
            text(&files["crypto/network.json"]),
            text(&files["crypto/milestones.json"]),
            text(&files["crypto/genesisBlock.json"]),
        );
        let chain = match Chain::load(&devnet_profile(), &configuration) {
            Ok(chain) => chain,
            Err(error) => return Outcome::Failed(format!("the configuration: {error}")),
        };
        if chain.nethash() != text(&output["nethash"]) {
            return Outcome::Failed("another network hash".into());
        }
        // Every wallet's passphrase gives its key and address through the legacy import.
        let mut wallets: Vec<&Value> = vec![&output["generator"]];
        for role in [
            "genesisWallets",
            "donationWallets",
            "testWallets",
            "delegates",
        ] {
            wallets.extend(output[role].as_array().expect("wallets"));
        }
        for wallet in wallets {
            let account =
                Account::from_legacy_passphrase(chain.profile(), text(&wallet["passphrase"]))
                    .expect("a key");
            let ours = json!([account.public_key().to_hex(), account.address().to_string()]);
            let theirs = json!([wallet["publicKey"], wallet["address"]]);
            if json_text(&ours) != json_text(&theirs) {
                return Outcome::Failed(format!("wallet {theirs}: got {ours}"));
            }
        }
        Outcome::Matched
    });
    assert_eq!(
        tally,
        Tally {
            matched: 3,
            divergent: 0,
            skipped: 0
        }
    );
}

#[test]
fn v12_milestone_config() {
    let file = load("V12-milestone-config");
    check_devnet(&file);
    let network = serde_json::to_string(&chain().network().to_json()).expect("JSON");
    let tally = run_class(&file, |record| match record.op.as_str() {
        "config.load" => {
            let loaded = Chain::from_parts(
                chain().profile(),
                &network,
                text(&record.input["milestones"]),
            );
            match (&record.expected, loaded) {
                (Ok(expected), Ok(loaded)) => {
                    let merged: Vec<Value> = loaded
                        .milestones()
                        .all()
                        .iter()
                        .map(|params| Value::Object(params.as_json().clone()))
                        .collect();
                    let rewards: Vec<Value> = record.input["rewards"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .map(|pair| {
                            let height = pair[0].as_u64().expect("a height") as u32;
                            let rank = pair[1].as_u64().expect("a rank") as u32;
                            match loaded.economics(height).reward_for_rank(rank) {
                                Some(reward) => json!([height, rank, reward.to_string()]),
                                None => json!([height, rank, { "error": "refused" }]),
                            }
                        })
                        .collect();
                    let expected_rewards: Vec<Value> = expected["rewards"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .map(|entry| match &entry[2] {
                            Value::Object(_) => json!([entry[0], entry[1], { "error": "refused" }]),
                            _ => entry.clone(),
                        })
                        .collect();
                    let donations: Vec<Value> = record.input["donations"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .map(|pair| {
                            let height = pair[0].as_u64().expect("a height") as u32;
                            let reward = amount_input(&pair[1]);
                            let shares: Vec<Value> = loaded
                                .economics(height)
                                .donations_of(reward)
                                .expect("a 64-bit reward")
                                .into_iter()
                                .map(|(address, amount)| {
                                    json!([address.to_string(), amount.to_string()])
                                })
                                .collect();
                            json!([height, reward.to_string(), shares])
                        })
                        .collect();
                    // Numbers compare as JavaScript writes them, so 8.0 is 8.
                    let expected = json!([
                        expected["milestones"],
                        expected_rewards,
                        expected["donations"]
                    ]);
                    let actual = json!([merged, rewards, donations]);
                    if js::stringify(&expected, 0) == js::stringify(&actual, 0) {
                        Outcome::Matched
                    } else {
                        compare(&expected, &actual)
                    }
                }
                // heartwood-crypto's own tests check that each refusal names the reference's
                // height; here the SDK must pass the refusal on.
                (Err(_), Err(Error::BadResponse { .. })) => Outcome::Matched,
                (expected, actual) => Outcome::Failed(format!(
                    "expected {expected:?}, got {:?}",
                    actual.map(|_| "a loaded chain")
                )),
            }
        }
        "block.make" => Outcome::Skipped("blocks: the SDK builds no blocks"),
        _ => transaction_record(record).unwrap_or(Outcome::Failed("unknown operation".into())),
    });
    assert_eq!(
        tally,
        Tally {
            matched: 80,
            divergent: 0,
            skipped: 2
        }
    );
}

#[test]
fn every_class_is_run() {
    let mut classes: Vec<String> = std::fs::read_dir(vectors_dir().join("heartwood"))
        .expect("the vector directory")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".jsonl").map(str::to_owned)
        })
        .collect();
    classes.sort();
    assert_eq!(
        classes,
        [
            "V01-keys-addresses",
            "V02-transactions",
            "V03-noncanonical-removed",
            "V04-signatures",
            "V05-blocks",
            "V06-arithmetic",
            "V07-vote-rules",
            "V10-genesis",
            "V11-external",
            "V12-milestone-config",
            "V19-fee-floor",
        ],
        "a vector class was added or removed: give it a runner"
    );
    let _ = OperationKind::ALL;
}
