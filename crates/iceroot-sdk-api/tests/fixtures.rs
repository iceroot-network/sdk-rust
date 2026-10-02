//! The mappers against responses recorded from a local single-node devnet of the reference
//! implementation (`tests/fixtures/devnet`, described in its README).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use iceroot_sdk_api::{
    ApiError, AssetId, BlockRef, HistoryDirection, PageRequest, PoolLimits, RejectReason,
    Resignation, Response, SolarCompat, SubmitStatus, SubmitTx, TxDetails, TxDirection, TxFilter,
    TxKind, TxStatus, ValidatorStatus,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Entry {
    name: String,
    path: String,
    status: u16,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    file: String,
    #[serde(rename = "requestFile", default)]
    request_file: Option<String>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/devnet")
}

fn index() -> Vec<Entry> {
    let text = fs::read_to_string(dir().join("index.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn entry(name: &str) -> Entry {
    index()
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no fixture {name}"))
}

/// The recorded answer, with its status and headers.
fn fixture(name: &str) -> Response {
    let e = entry(name);
    let body = fs::read(dir().join(&e.file)).unwrap();
    e.headers
        .iter()
        .fold(Response::new(e.status, body), |r, (k, v)| {
            r.with_header(k.clone(), v.clone())
        })
}

/// The account or transaction a recorded lookup asked for: the last segment of its path.
fn looked_up(name: &str) -> String {
    let path = entry(name).path;
    let path = path.split('?').next().unwrap_or_default();
    path.rsplit('/').next().unwrap_or_default().to_owned()
}

const API: SolarCompat = SolarCompat::new(53);
const TEAM: &str = "daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8";
const GENESIS_1: &str = "dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn";
const GENESIS_2: &str = "dMVgdVMdEWR2rVH6RRgXqheywVTzbgLNyG";
const TWO_RECIPIENTS: &str = "b2abe2cabab608935280c144a15ebea3e4e8348c530a983ffbf6013a13ab54a9";

#[test]
fn every_fixture_is_listed_and_present() {
    let entries = index();
    assert!(entries.len() >= 60);
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), entries.len(), "fixture names are unique");
    for e in &entries {
        assert!(dir().join(&e.file).is_file(), "{}", e.file);
        if let Some(request) = &e.request_file {
            assert!(dir().join(request).is_file(), "{request}");
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Node

#[test]
fn node_status() {
    let response = fixture("node-status");
    assert_eq!(response.block_height(), Some(80));
    let status = API.node_status().decode(&response).unwrap();
    assert_eq!(status.height, 80);
    assert!(status.synced);
    assert_eq!(status.blocks_behind, 0);
    assert_eq!(status.chain_time, 634);
}

#[test]
fn node_configuration() {
    let c = API
        .node_configuration()
        .decode(&fixture("node-configuration"))
        .unwrap();
    assert_eq!(c.core_version, "4.3.1");
    assert_eq!(
        c.network.nethash,
        "c9b03ab996ef3ac216a2ac53eaee71118cbf7995fa44449a7fb7f94bbe18bcca"
    );
    assert_eq!(c.network.network_byte, 90);
    assert_eq!(c.network.slip44, 1);
    assert_eq!(c.network.wif, 252);
    assert_eq!(
        (c.token.name.as_str(), c.token.symbol.as_str()),
        ("dROOT", "dRT")
    );
    assert_eq!(c.explorer, None);
    assert_eq!((c.seats, c.block_time), (53, 8));
    assert_eq!(c.pool.max_transactions_per_request, 40);
    assert_eq!(c.pool.max_transaction_bytes, 2_000_000);
    assert_eq!(c.pool.max_transactions_in_pool, 15_000);
    assert_eq!(c.pool.max_transactions_per_sender, 150);
    assert_eq!(c.pool.max_transaction_age, 2_700);
    assert!(c.pool_fees.dynamic);
    assert_eq!(
        (c.pool_fees.min_fee_pool, c.pool_fees.min_fee_broadcast),
        (6_173, 6_173)
    );
    let addon = |kind: TxKind| {
        c.pool_fees
            .addon_bytes
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| *v)
    };
    assert_eq!(addon(TxKind::Transfer), Some(85));
    assert_eq!(addon(TxKind::Vote), Some(98));
    assert_eq!(addon(TxKind::RegisterValidator), Some(1_214_968));
    assert_eq!(addon(TxKind::Burn), Some(0));
    assert_eq!(c.pool_fees.addon_bytes.len(), 13);
    assert_eq!(
        c.pool_fees.addon_bytes.first(),
        Some(&(
            TxKind::Other {
                type_group: 1,
                type_id: 0
            },
            99
        ))
    );
    let milestone: serde_json::Value = serde_json::from_str(&c.milestone_json).unwrap();
    assert_eq!(milestone["dynamicReward"]["ranks"]["53"], 220_000_000);
    assert_eq!(SolarCompat::for_configuration(&c), API);
}

#[test]
fn node_configuration_without_dynamic_fees() {
    // The node drops `false` values, so disabled dynamic fees arrive as an empty object.
    let body = r#"{"data":{"core":{"version":"4.3.1"},"nethash":"ab","slip44":1,"wif":252,"token":"dROOT",
        "symbol":"dRT","version":90,"ports":{},"constants":{"activeDelegates":53,"blockTime":8},
        "pool":{"dynamicFees":{},"maxTransactionsInPool":15000,"maxTransactionsPerSender":150,
        "maxTransactionsPerRequest":40,"maxTransactionAge":2700,"maxTransactionBytes":2000000}}}"#;
    let c = API
        .node_configuration()
        .decode(&Response::new(200, body))
        .unwrap();
    assert!(!c.pool_fees.dynamic);
    assert_eq!(c.pool_fees.min_fee_pool, 0);
    assert!(c.pool_fees.addon_bytes.is_empty());
}

#[test]
fn crypto_configuration() {
    let c = API
        .crypto_configuration()
        .decode(&fixture("node-configuration-crypto"))
        .unwrap();
    assert_eq!(
        c.nethash,
        "c9b03ab996ef3ac216a2ac53eaee71118cbf7995fa44449a7fb7f94bbe18bcca"
    );
    assert_eq!(c.network_byte, 90);
    let milestones: serde_json::Value = serde_json::from_str(&c.milestones_json).unwrap();
    assert_eq!(milestones.as_array().unwrap().len(), 2);
    let genesis: serde_json::Value = serde_json::from_str(&c.genesis_block_json).unwrap();
    assert_eq!(genesis["height"], 1);
    assert_eq!(genesis["transactions"].as_array().unwrap().len(), 107);
    assert!(c.exceptions_json.is_some());
    // The texts are the node's own bytes, not a re-serialization.
    let body = fs::read_to_string(dir().join("node-configuration-crypto.json")).unwrap();
    assert!(body.contains(&c.network_json));
    assert!(body.contains(&c.milestones_json));
}

#[test]
fn supply() {
    let s = API.supply().decode(&fixture("blockchain")).unwrap();
    assert_eq!(s.height, 80);
    assert_eq!(
        s.block_id,
        "732d00871e3ee92f16311b459d7a186203f966fc12d31aca66d47af639448550"
    );
    assert_eq!(s.supply, 9_999_944_498_767_798);
    assert_eq!(s.burned.fees, 20_949_232_202);
    assert_eq!(s.burned.transactions, 50_402_000_000);
    assert_eq!(s.burned.total, s.burned.fees + s.burned.transactions);
}

#[test]
fn fee_statistics() {
    let windowed = API
        .fee_statistics(Some(30))
        .unwrap()
        .decode(&fixture("node-fees-30-days"))
        .unwrap();
    assert_eq!(windowed.days, Some(30));
    let transfer = windowed
        .entries
        .iter()
        .find(|e| e.kind == TxKind::Transfer)
        .unwrap();
    assert_eq!(
        (
            transfer.avg,
            transfer.min,
            transfer.max,
            transfer.sum,
            transfer.burned
        ),
        (43_400_002, 0, 50_000_000, 651_000_026, 585_900_023)
    );
    let kinds: Vec<TxKind> = windowed.entries.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [
            TxKind::RegisterSecondKey,
            TxKind::RegisterValidator,
            TxKind::Transfer,
            TxKind::ResignValidator,
            TxKind::Burn,
            TxKind::Vote
        ]
    );

    let recent = API
        .fee_statistics(None)
        .unwrap()
        .decode(&fixture("node-fees"))
        .unwrap();
    assert_eq!(recent.days, None);
    assert_eq!(recent.entries.len(), 13);
    assert!(recent.entries.contains(&iceroot_sdk_api::FeeStatistic {
        kind: TxKind::Other {
            type_group: 1,
            type_id: 5
        },
        avg: 0,
        min: 0,
        max: 0,
        sum: 0,
        burned: 0,
    }));
}

// ------------------------------------------------------------------------------------------------
// Accounts

#[test]
fn accounts() {
    let decode = |name: &str| {
        API.account(&looked_up(name))
            .unwrap()
            .decode(&fixture(name))
    };
    let genesis = decode("wallet-genesis").unwrap();
    assert_eq!(genesis.address, GENESIS_1);
    assert_eq!(genesis.balance(AssetId::ROOT), 3_200_001_050_000_000);
    assert_eq!(genesis.balances.len(), 1);
    assert_eq!(genesis.nonce, 1);
    assert!(genesis.vote.is_empty());
    assert!(genesis.second_public_key.is_none() && genesis.validator_name.is_none());

    let voter = decode("wallet-voter").unwrap();
    let vote: Vec<(&str, u16)> = voter
        .vote
        .iter()
        .map(|v| (v.validator.as_str(), v.basis_points))
        .collect();
    assert_eq!(vote, [("genesis_15", 5_000), ("genesis_2", 5_000)]);

    let second = decode("wallet-second-key").unwrap();
    assert_eq!(
        second.second_public_key.as_deref(),
        Some("0318b677beadb87f35e29150a9bfdb20e1bb934bd70f1208383f4bff7ad6be5d67")
    );
    assert_eq!(second.vote[0].basis_points, 10_000);

    let cold = decode("wallet-cold").unwrap();
    assert_eq!((cold.balance(AssetId::ROOT), cold.nonce), (0, 0));
    assert!(cold.public_key.is_none());

    for name in ["wallet-invalid", "wallet-bad-id"] {
        match decode(name) {
            Err(ApiError::Refused {
                status: 422, error, ..
            }) => assert_eq!(error, "Unprocessable Entity"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn validator_account_carries_its_name() {
    let call = API.account("dUhgZCGMUdxEgiGuLQLDJTaUDF9rmLbgBE").unwrap();
    let body = r#"{"data":{"address":"dUhgZCGMUdxEgiGuLQLDJTaUDF9rmLbgBE","publicKey":"02dc","balance":"1",
        "nonce":"1","attributes":{"delegate":{"username":"tx1n3233","voteBalance":"0"}},"votingFor":{}}}"#;
    let account = call.decode(&Response::new(200, body)).unwrap();
    assert_eq!(account.validator_name.as_deref(), Some("tx1n3233"));
}

#[test]
fn histories_carry_directions() {
    let page = PageRequest::first(10);
    let all = API
        .history(TEAM, HistoryDirection::All, page)
        .unwrap()
        .decode(&fixture("wallet-transactions"))
        .unwrap();
    assert_eq!(
        (all.items.len(), all.total, all.page, all.has_next),
        (3, 3, 1, false)
    );
    assert!(all.items.iter().all(|t| t.direction.is_some()));
    let sent = all.items.iter().find(|t| t.id == TWO_RECIPIENTS).unwrap();
    assert_eq!(sent.direction, Some(TxDirection::Sent));
    assert!(
        all.items
            .iter()
            .any(|t| t.direction == Some(TxDirection::Received))
    );

    let only_sent = API
        .history(TEAM, HistoryDirection::Sent, page)
        .unwrap()
        .decode(&fixture("wallet-transactions-sent"))
        .unwrap();
    assert!(
        only_sent
            .items
            .iter()
            .all(|t| t.direction == Some(TxDirection::Sent))
    );

    let received = API
        .history(GENESIS_1, HistoryDirection::Received, PageRequest::first(5))
        .unwrap()
        .decode(&fixture("wallet-transactions-received"))
        .unwrap();
    assert!(
        received
            .items
            .iter()
            .all(|t| t.direction == Some(TxDirection::Received))
    );
    let two = received
        .items
        .iter()
        .find(|t| t.id == TWO_RECIPIENTS)
        .unwrap();
    assert_eq!(two.amount_to(GENESIS_1), 1_000_000_000);
    assert_eq!(two.amount(), 3_000_000_000);
}

#[test]
fn account_votes() {
    let votes = API
        .account_votes("dTe1ruBESG2r63u3VCLrMpTcx18PSurKJJ", PageRequest::first(10))
        .unwrap()
        .decode(&fixture("wallet-votes"))
        .unwrap();
    assert_eq!(votes.items.len(), 2);
    assert!(votes.items.iter().all(|t| t.kind() == TxKind::Vote));
    assert!(
        votes
            .items
            .iter()
            .all(|t| t.direction == Some(TxDirection::Sent))
    );
}

// ------------------------------------------------------------------------------------------------
// Transactions

#[test]
fn transfer_with_two_recipients() {
    let tx = API
        .transaction(TWO_RECIPIENTS)
        .unwrap()
        .decode(&fixture("transaction-transfer-two-recipients"))
        .unwrap()
        .unwrap();
    assert_eq!(tx.id, TWO_RECIPIENTS);
    assert_eq!(tx.status, TxStatus::Confirmed);
    let block = tx.block.as_ref().unwrap();
    assert_eq!(block.height, 82);
    assert_eq!(
        block.id,
        "04bc52da30e3fcc46da881d48f9d50b6754befc6fdfe8faf6746f3591b8741ba"
    );
    assert_eq!(block.confirmations, 1);
    let time = block.time.unwrap();
    assert_eq!((time.chain, time.unix), (648, 1_790_484_455));
    assert_eq!(tx.sender, TEAM);
    assert_eq!(tx.nonce, 1);
    assert_eq!((tx.fee, tx.burned_fee), (2_000_000, Some(1_800_000)));
    assert_eq!(tx.memo.as_deref(), Some("fixture: two recipients"));
    assert_eq!(tx.version, 3);
    assert!(!tx.second_signed);
    assert!(tx.direction.is_none());
    match &tx.details {
        TxDetails::Transfer { recipients } => {
            assert_eq!(recipients.len(), 2);
            assert_eq!(recipients[0].address, GENESIS_1);
            assert_eq!(recipients[0].amount, 1_000_000_000);
            assert_eq!(recipients[1].address, GENESIS_2);
            assert_eq!(recipients[1].amount, 2_000_000_000);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(tx.amount(), 3_000_000_000);

    // The untransformed resource maps to the same record, apart from the time and confirmations
    // it does not carry.
    let raw = API
        .transaction(TWO_RECIPIENTS)
        .unwrap()
        .decode(&fixture("transaction-transfer-raw"))
        .unwrap()
        .unwrap();
    assert_eq!(raw.details, tx.details);
    assert_eq!(
        (raw.sender.as_str(), raw.nonce, raw.fee),
        (TEAM, 1, 2_000_000)
    );
    assert_eq!(raw.block.as_ref().unwrap().height, 82);
    assert!(raw.block.as_ref().unwrap().time.is_none());
}

#[test]
fn pending_transactions() {
    let pending = API
        .unconfirmed_transaction(TWO_RECIPIENTS)
        .unwrap()
        .decode(&fixture("transaction-unconfirmed-by-id"))
        .unwrap()
        .unwrap();
    assert_eq!(pending.status, TxStatus::Pending);
    assert!(pending.block.is_none());
    assert_eq!(pending.sender, TEAM);
    assert_eq!(pending.amount(), 3_000_000_000);

    let pool = API
        .unconfirmed_transactions(PageRequest::first(10))
        .decode(&fixture("transactions-unconfirmed"))
        .unwrap();
    assert_eq!(pool.items.len(), 1);
    assert_eq!(pool.items[0].status, TxStatus::Pending);
    assert_eq!(pool.items[0].details, pending.details);

    let gone = API
        .unconfirmed_transaction(TWO_RECIPIENTS)
        .unwrap()
        .decode(&fixture("transaction-unconfirmed-not-found"))
        .unwrap();
    assert!(gone.is_none());
}

#[test]
fn an_answer_about_another_account_or_transaction_is_refused() {
    // A relay that answers a lookup with another account or transaction than the one asked for:
    // its answer is refused, not taken for the one asked for.
    let error = API
        .account(GENESIS_2)
        .unwrap()
        .decode(&fixture("wallet-genesis"))
        .unwrap_err();
    assert_eq!(error.code(), "BadResponse");
    assert!(error.to_string().contains("another account"), "{error}");
    let other = "ab".repeat(32);
    for call in [
        API.transaction(&other).unwrap(),
        API.unconfirmed_transaction(&other).unwrap(),
        API.vote(&other).unwrap(),
    ] {
        let error = call
            .decode(&fixture("transaction-transfer-two-recipients"))
            .unwrap_err();
        assert_eq!(error.code(), "BadResponse");
        assert!(error.to_string().contains("another transaction"), "{error}");
    }
    // Hex digits in either case name the same transaction.
    let upper = API
        .transaction(&TWO_RECIPIENTS.to_ascii_uppercase())
        .unwrap();
    assert!(
        upper
            .decode(&fixture("transaction-transfer-two-recipients"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn missing_transaction_is_none() {
    let call = API.transaction(&"0".repeat(64)).unwrap();
    assert!(
        call.decode(&fixture("transaction-not-found"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn every_kind_maps() {
    let one = |name: &str| {
        API.transaction(&looked_up(name))
            .unwrap()
            .decode(&fixture(name))
            .unwrap()
            .unwrap()
    };
    match one("transaction-vote").details {
        TxDetails::Vote { entries } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                (entries[0].validator.as_str(), entries[0].basis_points),
                ("tx1n1160", 10_000)
            );
        }
        other => panic!("{other:?}"),
    }
    match one("transaction-vote-three-way").details {
        TxDetails::Vote { entries } => {
            let v: Vec<(&str, u16)> = entries
                .iter()
                .map(|e| (e.validator.as_str(), e.basis_points))
                .collect();
            assert_eq!(
                v,
                [
                    ("genesis_5", 7_593),
                    ("genesis_7", 1_992),
                    ("genesis_6", 415)
                ]
            );
            assert_eq!(v.iter().map(|(_, bp)| u32::from(*bp)).sum::<u32>(), 10_000);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        one("transaction-vote-withdrawal").details,
        TxDetails::Vote {
            entries: Vec::new()
        }
    );
    let burn = one("transaction-burn");
    assert_eq!(
        burn.details,
        TxDetails::Burn {
            amount: 100_000_000
        }
    );
    assert!(burn.second_signed);
    assert_eq!(burn.amount(), 100_000_000);
    assert_eq!(
        one("transaction-second-key").details,
        TxDetails::RegisterSecondKey {
            public_key: "0318b677beadb87f35e29150a9bfdb20e1bb934bd70f1208383f4bff7ad6be5d67".into()
        }
    );
    let registration = one("transaction-validator-registration");
    assert_eq!(
        registration.details,
        TxDetails::RegisterValidator {
            name: "tx1n3233".into()
        }
    );
    assert_eq!(registration.fee, 7_500_404_882);
    assert_eq!(
        one("transaction-resignation-temporary").details,
        TxDetails::ResignValidator {
            resignation: Resignation::Temporary
        }
    );
    assert_eq!(
        one("transaction-resignation-permanent").details,
        TxDetails::ResignValidator {
            resignation: Resignation::Permanent
        }
    );
    assert_eq!(
        one("transaction-resignation-revoke").details,
        TxDetails::ResignValidator {
            resignation: Resignation::Revoke
        }
    );
}

#[test]
fn listings_by_kind() {
    let page = PageRequest::first(5);
    for (name, kind) in [
        ("transactions-transfer", TxKind::Transfer),
        ("transactions-vote", TxKind::Vote),
        ("transactions-burn", TxKind::Burn),
        ("transactions-second-key", TxKind::RegisterSecondKey),
        (
            "transactions-validator-registration",
            TxKind::RegisterValidator,
        ),
        (
            "transactions-validator-resignation",
            TxKind::ResignValidator,
        ),
    ] {
        let filter = TxFilter {
            kind: Some(kind),
            ..TxFilter::default()
        };
        let listing = API
            .transactions(&filter, page)
            .decode(&fixture(name))
            .unwrap();
        assert!(!listing.items.is_empty(), "{name}");
        assert!(listing.items.iter().all(|t| t.kind() == kind), "{name}");
        assert!(
            listing
                .items
                .iter()
                .all(|t| t.status == TxStatus::Confirmed),
            "{name}"
        );
    }
    let all = API
        .transactions(&TxFilter::default(), PageRequest::first(10))
        .decode(&fixture("transactions-page"))
        .unwrap();
    assert_eq!(
        (all.items.len(), all.total, all.page_count, all.has_next),
        (10, 146, 15, true)
    );
    assert!(!all.total_is_estimate);
    let by_sender = API
        .transactions(
            &TxFilter {
                sender: Some(TEAM.into()),
                ..TxFilter::default()
            },
            PageRequest::first(10),
        )
        .decode(&fixture("transactions-by-sender"))
        .unwrap();
    assert!(by_sender.items.iter().all(|t| t.sender == TEAM));
}

#[test]
fn votes_listing_and_lookup() {
    let votes = API
        .votes(PageRequest::first(5))
        .decode(&fixture("votes-page"))
        .unwrap();
    assert_eq!((votes.items.len(), votes.total), (5, 65));
    assert!(votes.items.iter().all(|t| t.kind() == TxKind::Vote));
    let one = API
        .vote(&looked_up("vote-by-id"))
        .unwrap()
        .decode(&fixture("vote-by-id"))
        .unwrap()
        .unwrap();
    assert_eq!(
        one.id,
        "4ca10d5305756afb5d0189fad478dd16d5b7db660ea9f8a38a385d9f66b0aaca"
    );
}

// ------------------------------------------------------------------------------------------------
// Submission

fn submitted(name: &str) -> Vec<SubmitTx> {
    let e = entry(name);
    let text = fs::read_to_string(dir().join(e.request_file.unwrap())).unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    body["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tx| {
            let json = tx.to_string();
            SubmitTx::new(tx["id"].as_str().unwrap(), &json, 160).unwrap()
        })
        .collect()
}

fn limits() -> PoolLimits {
    API.node_configuration()
        .decode(&fixture("node-configuration"))
        .unwrap()
        .pool
}

#[test]
fn submit_accepted() {
    let txs = submitted("submit-accepted");
    let plan = API.submit(&txs, &limits()).unwrap();
    assert_eq!(plan.calls().len(), 1);
    let report = plan.finish([plan.calls()[0].decode(&fixture("submit-accepted")).unwrap()]);
    assert!(report.all_accepted());
    assert_eq!(report.outcomes[0].id, TWO_RECIPIENTS);
    assert_eq!(
        report.outcomes[0].status,
        SubmitStatus::Accepted { broadcast: true }
    );
}

#[test]
fn submit_mixed_maps_every_refusal() {
    let txs = submitted("submit-mixed");
    let plan = API.submit(&txs, &limits()).unwrap();
    let report = plan.finish([plan.calls()[0].decode(&fixture("submit-mixed")).unwrap()]);
    let reasons: Vec<(Option<RejectReason>, &str)> = report
        .outcomes
        .iter()
        .map(|o| match &o.status {
            SubmitStatus::Accepted { .. } => (None, ""),
            SubmitStatus::Rejected {
                reason, node_code, ..
            } => (Some(*reason), node_code.as_str()),
        })
        .collect();
    assert_eq!(
        reasons,
        [
            (None, ""),
            (Some(RejectReason::LowFee), "ERR_LOW_FEE"),
            (Some(RejectReason::Nonce), "ERR_APPLY"),
            (Some(RejectReason::Balance), "ERR_APPLY"),
            (Some(RejectReason::Invalid), "ERR_BAD_DATA"),
            (Some(RejectReason::Duplicate), "ERR_COOLDOWN"),
        ]
    );
    let ids: Vec<&str> = report.outcomes.iter().map(|o| o.id.as_str()).collect();
    let submitted_ids: Vec<&str> = txs.iter().map(SubmitTx::id).collect();
    assert_eq!(ids, submitted_ids);
    // The corrupted signature changed the id the node computed; the rejection still maps to the
    // submitted transaction.
    match &report.outcomes[4].status {
        SubmitStatus::Rejected { message, .. } => {
            assert!(message.contains("failed signature verification"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn submit_refusal_by_the_node() {
    let txs = submitted("submit-accepted");
    let plan = API.submit(&txs, &limits()).unwrap();
    match plan.calls()[0].decode(&fixture("submit-empty")) {
        Err(ApiError::Refused {
            status: 422,
            message,
            ..
        }) => {
            assert!(message.contains("at least 1 items"));
        }
        other => panic!("{other:?}"),
    }
}

// ------------------------------------------------------------------------------------------------
// Blocks

#[test]
fn blocks() {
    let latest = API.latest_block().decode(&fixture("blocks-last")).unwrap();
    assert!(latest.height > 80);
    assert!(latest.previous.is_some());

    let genesis = API
        .genesis_block()
        .decode(&fixture("blocks-first"))
        .unwrap();
    assert_eq!(genesis.height, 1);
    assert_eq!(genesis.previous, None);
    assert_eq!(genesis.producer_name, None);
    assert_eq!(genesis.transaction_count, 107);
    assert_eq!(genesis.total_amount, 10_000_000_000_000_000);
    assert_eq!(genesis.time.chain, 0);

    let by_height = API
        .block(&BlockRef::Height(82))
        .unwrap()
        .decode(&fixture("block-by-height"))
        .unwrap()
        .unwrap();
    let by_id = API
        .block(&BlockRef::Id(by_height.id.clone()))
        .unwrap()
        .decode(&fixture("block-by-id"))
        .unwrap()
        .unwrap();
    assert_eq!(by_height.id, by_id.id);
    assert_eq!(by_height.height, 82);
    assert_eq!(by_height.transaction_count, 2);
    assert_eq!(by_height.donations.len(), 2);
    assert!(
        by_height
            .donations
            .windows(2)
            .all(|w| w[0].address < w[1].address)
    );
    let donated: u128 = by_height.donations.iter().map(|d| d.amount).sum();
    assert_eq!(
        by_height.producer_earned,
        by_height.reward - donated + by_height.total_fee - by_height.burned_fee
    );
    assert!(by_height.producer_name.is_some());

    let none = API
        .block(&BlockRef::Height(99_999_999))
        .unwrap()
        .decode(&fixture("block-not-found"))
        .unwrap();
    assert!(none.is_none());

    let page = API
        .blocks(PageRequest::first(5))
        .decode(&fixture("blocks-page"))
        .unwrap();
    assert_eq!(page.items.len(), 5);
    assert!(page.has_next);

    let in_block = API
        .block_transactions(&BlockRef::Id(by_height.id.clone()), PageRequest::first(10))
        .unwrap()
        .decode(&fixture("block-transactions"))
        .unwrap();
    assert_eq!(in_block.items.len(), 2);
    assert!(
        in_block
            .items
            .iter()
            .all(|t| t.block.as_ref().map(|b| b.height) == Some(82))
    );

    let missed = API
        .missed_slots(PageRequest::first(10))
        .decode(&fixture("blocks-missed"))
        .unwrap();
    assert!(missed.items.is_empty());
    assert_eq!(missed.total, 0);
}

#[test]
fn missed_slot_maps() {
    let body = r#"{"meta":{"count":1,"pageCount":1,"totalCount":1,"next":null},"data":[{"height":120,
        "timestamp":{"epoch":952,"unix":1790484759,"human":"2026-09-27T04:52:39.000Z"},"username":"genesis_9"}]}"#;
    let page = API
        .missed_slots(PageRequest::first(10))
        .decode(&Response::new(200, body))
        .unwrap();
    assert_eq!(page.items[0].validator, "genesis_9");
    assert_eq!(page.items[0].height, 120);
    assert_eq!(page.items[0].time.chain, 952);
}

// ------------------------------------------------------------------------------------------------
// Validators, names and rounds

#[test]
fn validators() {
    let all = API
        .validators(PageRequest::first(100))
        .decode(&fixture("delegates-page"))
        .unwrap();
    assert_eq!((all.items.len(), all.total), (56, 56));
    let active = all
        .items
        .iter()
        .filter(|v| v.status == ValidatorStatus::Active)
        .count();
    assert_eq!(active, 52);
    let status = |name: &str| all.items.iter().find(|v| v.name == name).unwrap().status;
    assert_eq!(status("genesis_53"), ValidatorStatus::ResignedTemporary);
    assert_eq!(status("tx1n1160"), ValidatorStatus::ResignedPermanent);
    assert_eq!(status("tx1n2290"), ValidatorStatus::Standby);

    let top = &all.items[0];
    assert_eq!(top.name, "genesis_5");
    assert_eq!(top.rank, Some(1));
    assert_eq!(top.vote_weight, 6_326_806_303);
    assert_eq!(top.voters, 2);
    assert_eq!(top.vote_share_basis_points, 0);
    assert_eq!(top.production.produced, 2);
    assert_eq!(top.production.missed, 0);
    assert_eq!(
        top.production.last_block.as_ref().map(|b| b.id.as_str()),
        Some("36dda07d1dc104053a06671b4cf14b8b566765852c936f4d66fa3fd75a410566")
    );
    let e = top.earnings;
    assert_eq!(e.total, e.rewards + e.fees - e.burned_fees - e.donations);
    assert_eq!(top.version.as_deref(), Some("4.3.1"));

    // A page with more items than were asked for is refused: no relay makes a listing longer
    // than the pages it was asked for.
    let refused = API
        .validators(PageRequest::first(50))
        .decode(&fixture("delegates-page"))
        .unwrap_err();
    assert_eq!(refused.code(), "BadResponse");
    assert!(refused.to_string().contains("56 items"), "{refused}");

    let second_page = API
        .validators(PageRequest::new(2, 50).unwrap())
        .decode(&fixture("delegates-page-2"))
        .unwrap();
    assert_eq!(
        (
            second_page.items.len(),
            second_page.page,
            second_page.has_next
        ),
        (6, 2, false)
    );

    // With fewer seats, more validators are standby. A resigned validator keeps the rank the node
    // reports but never holds a seat: genesis_53 ranks fourth.
    let few = SolarCompat::new(10)
        .validators(PageRequest::first(100))
        .decode(&fixture("delegates-page"))
        .unwrap();
    assert_eq!(
        few.items
            .iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count(),
        9
    );
    let fourth = few.items.iter().find(|v| v.rank == Some(4)).unwrap();
    assert_eq!(
        (fourth.name.as_str(), fourth.status),
        ("genesis_53", ValidatorStatus::ResignedTemporary)
    );
}

#[test]
fn one_validator() {
    let by_name = API
        .validator("genesis_5")
        .unwrap()
        .decode(&fixture("delegate-by-name"))
        .unwrap()
        .unwrap();
    let by_address = API
        .validator("dQcSrSKWSj6gYD1dF92EmsVz56UNTae1kz")
        .unwrap()
        .decode(&fixture("delegate-by-address"))
        .unwrap()
        .unwrap();
    assert_eq!(by_name, by_address);
    assert_eq!(by_name.status, ValidatorStatus::Active);

    let unranked = API
        .validator("tx1n2290")
        .unwrap()
        .decode(&fixture("delegate-unranked"))
        .unwrap()
        .unwrap();
    assert_eq!(
        (unranked.rank, unranked.status),
        (None, ValidatorStatus::Standby)
    );
    assert!(unranked.production.last_block.is_none());

    let resigned = API
        .validator("genesis_53")
        .unwrap()
        .decode(&fixture("delegate-resigned"))
        .unwrap()
        .unwrap();
    assert_eq!(resigned.status, ValidatorStatus::ResignedTemporary);
    let revoked = API
        .validator("genesis_53")
        .unwrap()
        .decode(&fixture("delegate-revoked"))
        .unwrap()
        .unwrap();
    // Revoked: no longer resigned, and unranked until the next round is built.
    assert_eq!(
        (revoked.rank, revoked.status),
        (None, ValidatorStatus::Standby)
    );

    let missing = API
        .validator("no_such_validator")
        .unwrap()
        .decode(&fixture("delegate-not-found"))
        .unwrap();
    assert!(missing.is_none());
}

#[test]
fn names_resolve_by_name_only() {
    let name = API
        .resolve_name("genesis_5")
        .unwrap()
        .decode(&fixture("delegate-by-name"))
        .unwrap()
        .unwrap();
    assert_eq!(name.address, "dQcSrSKWSj6gYD1dF92EmsVz56UNTae1kz");
    let by_address = API
        .resolve_name("dQcSrSKWSj6gYD1dF92EmsVz56UNTae1kz")
        .unwrap()
        .decode(&fixture("delegate-by-address"))
        .unwrap();
    assert!(by_address.is_none());
    let missing = API
        .resolve_name("no_such_validator")
        .unwrap()
        .decode(&fixture("delegate-not-found"))
        .unwrap();
    assert!(missing.is_none());
}

#[test]
fn voters_blocks_and_missed_slots() {
    let voters = API
        .voters("genesis_15", PageRequest::first(10))
        .unwrap()
        .decode(&fixture("delegate-voters"))
        .unwrap();
    assert_eq!(voters.items.len(), 3);
    assert!(
        voters
            .items
            .iter()
            .all(|a| a.vote.iter().any(|v| v.validator == "genesis_15"))
    );
    let produced = API
        .validator_blocks("genesis_5", PageRequest::first(3))
        .unwrap()
        .decode(&fixture("delegate-blocks"))
        .unwrap();
    assert_eq!(produced.items.len(), 2);
    assert!(
        produced
            .items
            .iter()
            .all(|b| b.producer_name.as_deref() == Some("genesis_5"))
    );
    let missed = API
        .validator_missed_slots("genesis_5", PageRequest::first(10))
        .unwrap()
        .decode(&fixture("delegate-missed-blocks"))
        .unwrap();
    assert!(missed.items.is_empty());
}

#[test]
fn rounds() {
    for (name, round) in [("round-1-delegates", 1), ("round-2-delegates", 2)] {
        let seats = API
            .round_validators(round)
            .unwrap()
            .decode(&fixture(name))
            .unwrap();
        assert_eq!(seats.len(), 53, "{name}");
        assert!(seats.iter().all(|s| s.public_key.len() == 66));
    }
    let first = API
        .round_validators(1)
        .unwrap()
        .decode(&fixture("round-1-delegates"))
        .unwrap();
    assert!(first.iter().all(|s| s.vote_weight == 0));
}

// ------------------------------------------------------------------------------------------------
// Rate limit and errors

#[test]
fn rate_limit_refusal() {
    let response = fixture("rate-limited");
    assert_eq!(response.status(), 429);
    match API.node_status().decode(&response) {
        Err(error @ ApiError::RateLimited { retry_after: None }) => {
            assert!(error.is_retryable());
            assert_eq!(error.code(), "RateLimited");
        }
        other => panic!("{other:?}"),
    }
    let with_hint = Response::new(429, "{}").with_header("Retry-After", "7");
    assert_eq!(
        API.supply().decode(&with_hint),
        Err(ApiError::RateLimited {
            retry_after: Some(std::time::Duration::from_secs(7))
        })
    );
}

#[test]
fn malformed_answers_are_bad_responses() {
    let cases = [
        (200, "not json"),
        (200, r#"{"data":{"synced":true}}"#),
        (
            200,
            r#"{"data":{"synced":true,"now":-1,"blocksCount":0,"timestamp":0}}"#,
        ),
        (200, r#"{"data":[]}"#),
    ];
    for (status, body) in cases {
        match API.node_status().decode(&Response::new(status, body)) {
            Err(ApiError::BadResponse { .. }) => {}
            other => panic!("{body}: {other:?}"),
        }
    }
    let negative = r#"{"data":{"block":{"height":1,"id":"a"},"burned":{"fees":"-1","transactions":"0","total":"0"},"supply":"1"}}"#;
    assert!(matches!(
        API.supply().decode(&Response::new(200, negative)),
        Err(ApiError::BadResponse { .. })
    ));
    let bad_vote = r#"{"data":{"id":"a","blockHeight":2,"blockId":"b","version":3,"type":2,"typeGroup":2,
        "fee":"1","sender":"d","senderPublicKey":"02","asset":{"votes":{"x":33.333}},"nonce":"1"}}"#;
    assert!(matches!(
        API.transaction("a")
            .unwrap()
            .decode(&Response::new(200, bad_vote)),
        Err(ApiError::BadResponse { .. })
    ));
    let server = Response::new(
        503,
        r#"{"statusCode":503,"error":"Service Unavailable","message":"busy"}"#,
    );
    let error = API.supply().decode(&server).unwrap_err();
    assert!(error.is_retryable());
    assert!(matches!(
        API.supply().decode(&Response::new(302, "")),
        Err(ApiError::BadResponse { .. })
    ));
    assert!(matches!(
        API.supply().decode(&Response::new(404, "")),
        Err(ApiError::NotFound { .. })
    ));
}

#[test]
fn unknown_kinds_are_kept() {
    let body = r#"{"data":{"id":"a","blockHeight":2,"blockId":"b","version":3,"type":8,"typeGroup":1,
        "fee":"1","sender":"d","senderPublicKey":"02","asset":{"lock":{"secretHash":"00"}},"nonce":"1"}}"#;
    let tx = API
        .transaction("a")
        .unwrap()
        .decode(&Response::new(200, body))
        .unwrap()
        .unwrap();
    assert_eq!(
        tx.kind(),
        TxKind::Other {
            type_group: 1,
            type_id: 8
        }
    );
    match tx.details {
        TxDetails::Other { asset_json, .. } => assert_eq!(
            asset_json.as_deref(),
            Some(r#"{"lock":{"secretHash":"00"}}"#)
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn decoders_never_panic_on_mangled_bodies() {
    let page = PageRequest::first(10);
    let tx = SubmitTx::new("a", "{}", 1).unwrap();
    let submit = API.submit(&[tx], &limits()).unwrap().calls()[0].clone();
    type Decoder = Box<dyn Fn(&Response)>;
    let decoders: Vec<Decoder> = vec![
        Box::new(|r| drop(API.node_status().decode(r))),
        Box::new(|r| drop(API.node_configuration().decode(r))),
        Box::new(|r| drop(API.crypto_configuration().decode(r))),
        Box::new(|r| drop(API.supply().decode(r))),
        Box::new(|r| drop(API.fee_statistics(None).unwrap().decode(r))),
        Box::new(|r| drop(API.account("a").unwrap().decode(r))),
        Box::new(move |r| {
            drop(
                API.history("a", HistoryDirection::All, page)
                    .unwrap()
                    .decode(r),
            )
        }),
        Box::new(|r| drop(API.transaction("a").unwrap().decode(r))),
        Box::new(move |r| drop(submit.decode(r))),
        Box::new(|r| drop(API.latest_block().decode(r))),
        Box::new(move |r| drop(API.blocks(page).decode(r))),
        Box::new(move |r| drop(API.validators(page).decode(r))),
        Box::new(|r| drop(API.validator("a").unwrap().decode(r))),
        Box::new(|r| drop(API.resolve_name("a").unwrap().decode(r))),
        Box::new(move |r| drop(API.voters("a", page).unwrap().decode(r))),
        Box::new(move |r| drop(API.missed_slots(page).decode(r))),
        Box::new(|r| drop(API.round_validators(1).unwrap().decode(r))),
    ];
    for e in index() {
        let body = fs::read(dir().join(&e.file)).unwrap();
        let step = (body.len() / 20).max(1);
        let mut variants: Vec<Vec<u8>> = (0..body.len())
            .step_by(step)
            .map(|n| body[..n].to_vec())
            .collect();
        for at in (0..body.len()).step_by(step) {
            let mut flipped = body.clone();
            flipped[at] ^= 0x5a;
            variants.push(flipped);
        }
        for variant in variants {
            for status in [200, 404, 422] {
                let response = Response::new(status, variant.clone());
                for decode in &decoders {
                    decode(&response);
                }
            }
        }
    }
}
