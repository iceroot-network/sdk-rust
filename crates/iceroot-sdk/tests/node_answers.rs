//! The core reading what the node API client decodes, on answers recorded from a local devnet of
//! the reference implementation (the client's fixtures in `crates/iceroot-sdk-api/tests/fixtures`).
//!
//! The chain is loaded from the node's crypto configuration, every transaction the devnet was sent
//! is read back through the core with the node's own id, and a draft is built from the facts the
//! node reported.

// Tests may panic on a broken fixture: that is how they fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use iceroot_sdk::api::{self, Response, SolarCompat, SubmitStatus};
use iceroot_sdk::error::ErrorCode;
use iceroot_sdk::fee::{FeeChoice, FeeSource};
use iceroot_sdk::profile::DevnetOptions;
use iceroot_sdk::transaction::{DraftRequest, Operation, Recipient};
use iceroot_sdk::{
    Address, Amount, Chain, Draft, Error, OnlineFacts, OperationKind, Profile, PublicKey,
    SignedTransaction,
};
use serde_json::Value;

const API: SolarCompat = SolarCompat::new(53);
/// The funded account that sent the recorded submissions.
const TEAM: &str = "daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8";
const TEAM_KEY: &str = "03f5679f03b0f7569d29708aed1ce026a0a2c1aa4145f6aa51a3298253d58d725f";
const NETHASH: &str = "d3f1bb4da4c6cd2e8ef15e2d7b3ad6ee4a5f2d9f7c8b4c1e0a4c2a1b0f5a9e1d";

fn fixture(file: &str) -> Vec<u8> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../iceroot-sdk-api/tests/fixtures/devnet");
    fs::read(dir.join(file)).unwrap_or_else(|error| panic!("{file}: {error}"))
}

fn answer(file: &str) -> Response {
    Response::new(200, fixture(file))
}

fn chain() -> Chain {
    let configuration = API
        .crypto_configuration()
        .decode(&answer("node-configuration-crypto.json"))
        .unwrap();
    Chain::from_node(&Profile::devnet(DevnetOptions::default()), &configuration).unwrap()
}

#[test]
fn the_chain_comes_from_the_node() {
    let chain = chain();
    assert_eq!(chain.network_byte(), 90);
    assert_eq!(
        chain.profile().chain().nethash.as_deref(),
        Some(chain.nethash())
    );

    // /node/configuration names the same chain.
    let node = API
        .node_configuration()
        .decode(&answer("node-configuration.json"))
        .unwrap();
    chain.check_node(&node).unwrap();

    // A node of another chain is refused, and so is a profile pinned to another chain.
    let mut other = node.clone();
    other.network.nethash = NETHASH.to_owned();
    assert!(matches!(
        chain.check_node(&other),
        Err(Error::NetworkMismatch { .. })
    ));
    let configuration = API
        .crypto_configuration()
        .decode(&answer("node-configuration-crypto.json"))
        .unwrap();
    let pinned = Profile::devnet(DevnetOptions {
        nethash: Some(NETHASH.to_owned()),
        ..DevnetOptions::default()
    });
    assert!(matches!(
        Chain::from_node(&pinned, &configuration),
        Err(Error::NetworkMismatch { .. })
    ));
    let mut tampered = configuration.clone();
    tampered.genesis_block_json = r#"{"payloadHash":"00"}"#.to_owned();
    assert!(matches!(
        Chain::from_node(&Profile::devnet(DevnetOptions::default()), &tampered),
        Err(Error::BadResponse { .. })
    ));
}

#[test]
fn submitted_transactions_read_back_with_the_node_ids() {
    let chain = chain();
    let mut read = 0;
    let mut unverified = 0;
    for file in ["submit-accepted.request.json", "submit-mixed.request.json"] {
        let body: Value = serde_json::from_slice(&fixture(file)).unwrap();
        for json in body["transactions"].as_array().unwrap() {
            let signed = SignedTransaction::from_json(&chain, json, 81).unwrap();
            if !signed.is_verified() {
                // The submission with a corrupted signature: the node refused it.
                unverified += 1;
                continue;
            }
            assert_eq!(signed.id(), json["id"].as_str().unwrap(), "{file}");
            assert_eq!(&signed.json(), json, "{file}");
            assert_eq!(signed.sender().to_string(), TEAM);
            let submit = signed.to_submit().unwrap();
            assert_eq!(submit.id(), signed.id());
            assert_eq!(submit.size(), signed.bytes().len());
            read += 1;
        }
    }
    assert_eq!((read, unverified), (6, 1));

    // The node's answer to the mixed submission, one outcome per transaction.
    let body: Value = serde_json::from_slice(&fixture("submit-mixed.request.json")).unwrap();
    let transactions: Vec<_> = body["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|json| {
            api::SubmitTx::new(json["id"].as_str().unwrap(), &json.to_string(), 200).unwrap()
        })
        .collect();
    let limits = API
        .node_configuration()
        .decode(&answer("node-configuration.json"))
        .unwrap()
        .pool;
    let plan = API.submit(&transactions, &limits).unwrap();
    let report = plan.finish(
        plan.calls()
            .iter()
            .map(|call| call.decode(&answer("submit-mixed.json")).unwrap()),
    );
    let mut accepted = 0;
    for outcome in &report.outcomes {
        match (&outcome.status, iceroot_sdk::node::submit_result(outcome)) {
            (SubmitStatus::Accepted { .. }, Ok(())) => accepted += 1,
            (SubmitStatus::Rejected { reason, .. }, Err(error)) => {
                assert_eq!(error.code(), ErrorCode::TxRejected);
                assert_eq!(error.details()["reason"], reason.as_str());
            }
            (status, result) => panic!("{status:?} gave {result:?}"),
        }
    }
    assert_eq!(accepted, 1);
}

#[test]
fn a_draft_from_the_facts_the_node_reports() {
    let chain = chain();
    let sender = PublicKey::from_hex(TEAM_KEY).unwrap();
    let account = API
        .account(TEAM)
        .unwrap()
        .decode(&answer("wallet-team.json"))
        .unwrap();
    let status = API
        .node_status()
        .decode(&answer("node-status.json"))
        .unwrap();
    let facts = OnlineFacts::from_node(&chain, &sender, Some(&account), &status).unwrap();
    assert_eq!(facts.nonce, account.nonce + 1);
    assert_eq!(u64::from(facts.height), status.height + 1);
    assert_eq!(facts.second_key, None);

    let recipient = Address::parse("dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn", chain.profile()).unwrap();
    let request = DraftRequest {
        operation: Operation::Transfer {
            recipients: vec![Recipient {
                address: recipient,
                amount: Amount::parse("1", chain.token().decimals).unwrap(),
            }],
        },
        memo: Some("from the node's facts".to_owned()),
        fee: FeeChoice::Minimum,
    };
    let draft = Draft::build(&chain, &request, &facts).unwrap();
    let fee = draft.fee();
    // The exact floor of the milestone the node serves.
    let floor = chain
        .fee_floor(OperationKind::Transfer, draft.size(), draft.height())
        .unwrap();
    assert_eq!(fee.source, FeeSource::Floor);
    assert_eq!((fee.amount, fee.floor), (floor, Some(floor)));
    assert_eq!(draft.nonce(), facts.nonce);
    assert_eq!(draft.sender().to_string(), TEAM);

    // Another account's answer is refused rather than lending its nonce.
    let other = API
        .account("dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn")
        .unwrap()
        .decode(&answer("wallet-genesis.json"))
        .unwrap();
    assert!(matches!(
        OnlineFacts::from_node(&chain, &sender, Some(&other), &status),
        Err(Error::WrongKey { .. })
    ));
}
