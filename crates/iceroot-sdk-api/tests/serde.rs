//! The JSON form of every answer (feature `serde`): each recorded devnet response is decoded,
//! written as JSON and read back unchanged, and the form follows the rules of the crate
//! documentation, which every binding of the SDK relies on.

#![cfg(feature = "serde")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;

use iceroot_sdk_api::{
    BlockRef, HistoryDirection, PageRequest, Request, Response, SolarCompat, SubmitTx, TxFilter,
    TxKind,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[derive(Debug, serde::Deserialize)]
struct Entry {
    name: String,
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    file: String,
    #[serde(rename = "requestFile", default)]
    request_file: Option<String>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/devnet")
}

fn entry(name: &str) -> Entry {
    let text = fs::read_to_string(dir().join("index.json")).unwrap();
    let entries: Vec<Entry> = serde_json::from_str(&text).unwrap();
    entries
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no fixture {name}"))
}

fn fixture(name: &str) -> Response {
    let e = entry(name);
    let body = fs::read(dir().join(&e.file)).unwrap();
    e.headers
        .iter()
        .fold(Response::new(e.status, body), |r, (k, v)| {
            r.with_header(k.clone(), v.clone())
        })
}

const API: SolarCompat = SolarCompat::new(53);
fn page() -> PageRequest {
    PageRequest::first(10)
}

/// Writes `value` as JSON, reads it back through both the value and the text form, and returns the
/// JSON.
fn round_trip<T>(value: &T) -> Value
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let json = serde_json::to_value(value).unwrap();
    assert_eq!(&serde_json::from_value::<T>(json.clone()).unwrap(), value);
    let text = serde_json::to_string(value).unwrap();
    assert_eq!(&serde_json::from_str::<T>(&text).unwrap(), value);
    json
}

/// Every integer of 64 bits or more in `json` is a decimal string: numbers are allowed only under
/// the keys of small integers.
fn assert_wide_integers_are_text(json: &Value, path: &str) {
    const NUMBERS: &[&str] = &[
        "page",
        "pageCount",
        "networkByte",
        "slip44",
        "wif",
        "seats",
        "blockTime",
        "maxTransactionsInPool",
        "maxTransactionsPerSender",
        "maxTransactionsPerRequest",
        "maxTransactionAge",
        "maxTransactionBytes",
        "days",
        "basisPoints",
        "typeGroup",
        "typeId",
        "version",
        "rank",
        "voteShareBasisPoints",
        "productivityBasisPoints",
        "transactionCount",
        "payloadLength",
        "size",
    ];
    match json {
        Value::Object(map) => {
            for (key, value) in map {
                if value.is_number() {
                    assert!(NUMBERS.contains(&key.as_str()), "{path}.{key} is a number");
                }
                assert_wide_integers_are_text(value, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                assert_wide_integers_are_text(item, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

fn check<T>(value: &T) -> Value
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let json = round_trip(value);
    assert_wide_integers_are_text(&json, "");
    json
}

#[test]
fn node_answers() {
    let status = check(&API.node_status().decode(&fixture("node-status")).unwrap());
    assert_eq!(status["height"], "80");
    assert!(status["synced"].is_boolean());

    let configuration = check(
        &API.node_configuration()
            .decode(&fixture("node-configuration"))
            .unwrap(),
    );
    assert_eq!(configuration["network"]["networkByte"], 90);
    assert_eq!(configuration["pool"]["maxTransactionsPerRequest"], 40);
    assert!(configuration["poolFees"]["minFeePool"].is_string());
    let addon = configuration["poolFees"]["addonBytes"].as_array().unwrap();
    assert!(
        addon
            .iter()
            .any(|e| e["kind"] == "transfer" && e["bytes"].is_string())
    );
    assert!(
        addon
            .iter()
            .any(|e| e["kind"] == "other" && e["typeGroup"].is_number())
    );
    assert!(configuration["milestoneJson"].is_string());

    let crypto = check(
        &API.crypto_configuration()
            .decode(&fixture("node-configuration-crypto"))
            .unwrap(),
    );
    assert_eq!(crypto["networkByte"], 90);
    assert!(crypto["genesisBlockJson"].is_string());

    let supply = check(&API.supply().decode(&fixture("blockchain")).unwrap());
    assert!(supply["supply"].is_string());
    assert!(supply["burned"]["total"].is_string());

    for name in ["node-fees", "node-fees-30-days"] {
        let fees = check(
            &API.fee_statistics(None)
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
        let entries = fees["entries"].as_array().unwrap();
        assert!(!entries.is_empty());
        assert!(
            entries
                .iter()
                .all(|e| e["kind"].is_string() && e["min"].is_string())
        );
    }
}

#[test]
fn accounts_and_histories() {
    for name in [
        "wallet-genesis",
        "wallet-team",
        "wallet-voter",
        "wallet-second-key",
        "wallet-cold",
    ] {
        let account = check(&API.account("dA").unwrap().decode(&fixture(name)).unwrap());
        assert_eq!(account["balances"][0]["asset"], "ROOT", "{name}");
        assert!(account["nonce"].is_string());
    }
    let voter = check(
        &API.account("dA")
            .unwrap()
            .decode(&fixture("wallet-voter"))
            .unwrap(),
    );
    assert!(voter["vote"][0]["basisPoints"].is_number());
    let second = check(
        &API.account("dA")
            .unwrap()
            .decode(&fixture("wallet-second-key"))
            .unwrap(),
    );
    assert!(second["secondPublicKey"].is_string());
    let cold = check(
        &API.account("dA")
            .unwrap()
            .decode(&fixture("wallet-cold"))
            .unwrap(),
    );
    assert!(
        cold.get("publicKey").is_none(),
        "absent values are left out"
    );

    for (name, direction) in [
        ("wallet-transactions", HistoryDirection::All),
        ("wallet-transactions-sent", HistoryDirection::Sent),
        ("wallet-transactions-received", HistoryDirection::Received),
    ] {
        let page = check(
            &API.history("daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8", direction, page())
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
        assert!(page["hasNext"].is_boolean());
        assert!(page["total"].is_string());
        for item in page["items"].as_array().unwrap() {
            assert!(item["direction"].is_string());
        }
    }
    check(
        &API.account_votes("dA", page())
            .unwrap()
            .decode(&fixture("wallet-votes"))
            .unwrap(),
    );
    check(
        &API.voters("genesis_15", page())
            .unwrap()
            .decode(&fixture("delegate-voters"))
            .unwrap(),
    );
}

#[test]
fn transactions() {
    let mut kinds = Vec::new();
    for name in [
        "transaction-transfer",
        "transaction-transfer-two-recipients",
        "transaction-vote",
        "transaction-vote-withdrawal",
        "transaction-vote-three-way",
        "transaction-burn",
        "transaction-second-key",
        "transaction-validator-registration",
        "transaction-validator-resignation",
        "transaction-resignation-permanent",
        "transaction-resignation-temporary",
        "transaction-resignation-revoke",
        "transaction-unconfirmed-by-id",
        "transaction-not-found",
        "vote-by-id",
    ] {
        let record = check(
            &API.transaction("ab")
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
        if let Some(kind) = record.get("details").map(|d| d["kind"].clone()) {
            kinds.push(kind.as_str().unwrap().to_owned());
        }
    }
    kinds.sort();
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            "burn",
            "register-second-key",
            "register-validator",
            "resign-validator",
            "transfer",
            "vote"
        ]
    );

    for name in [
        "transactions-page",
        "transactions-by-sender",
        "transactions-transfer",
        "transactions-vote",
        "transactions-burn",
        "transactions-second-key",
        "transactions-validator-registration",
        "transactions-validator-resignation",
        "transactions-unconfirmed",
        "votes-page",
        "block-transactions",
    ] {
        check(
            &API.transactions(&TxFilter::default(), page())
                .decode(&fixture(name))
                .unwrap(),
        );
    }
}

#[test]
fn a_transfer_in_full() {
    let record = API
        .transaction("b2abe2cabab608935280c144a15ebea3e4e8348c530a983ffbf6013a13ab54a9")
        .unwrap()
        .decode(&fixture("transaction-transfer-two-recipients"))
        .unwrap()
        .unwrap();
    let json = check(&record);
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "id",
            "status",
            "block",
            "sender",
            "senderPublicKey",
            "nonce",
            "fee",
            "burnedFee",
            "memo",
            "secondSigned",
            "version",
            "details"
        ]
    );
    assert_eq!(json["status"], "confirmed");
    assert!(json["block"]["height"].is_string());
    assert!(json["block"]["time"]["unix"].is_string());
    assert_eq!(json["details"]["kind"], "transfer");
    let recipients = json["details"]["recipients"].as_array().unwrap();
    assert_eq!(recipients.len(), 2);
    assert!(recipients[0]["address"].is_string() && recipients[0]["amount"].is_string());
}

#[test]
fn blocks_validators_and_rounds() {
    for name in ["blocks-last", "blocks-first"] {
        check(&API.latest_block().decode(&fixture(name)).unwrap());
    }
    for name in ["block-by-height", "block-by-id", "block-not-found"] {
        check(
            &API.block(&BlockRef::Height(82))
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
    }
    check(&API.blocks(page()).decode(&fixture("blocks-page")).unwrap());
    check(
        &API.validator_blocks("genesis_5", page())
            .unwrap()
            .decode(&fixture("delegate-blocks"))
            .unwrap(),
    );
    for name in ["blocks-missed", "delegate-missed-blocks"] {
        check(&API.missed_slots(page()).decode(&fixture(name)).unwrap());
    }

    // The recorded listings hold up to 100 validators, the page size they were read with.
    for name in ["delegates-page", "delegates-page-2"] {
        let listing = API.validators(PageRequest::first(100));
        let page = check(&listing.decode(&fixture(name)).unwrap());
        for validator in page["items"].as_array().unwrap() {
            assert!(validator["voteWeight"].is_string());
            assert!(validator["production"]["produced"].is_string());
        }
    }
    let mut statuses = Vec::new();
    for name in [
        "delegate-by-name",
        "delegate-by-address",
        "delegate-resigned",
        "delegate-revoked",
        "delegate-unranked",
        "delegate-not-found",
    ] {
        let validator = check(
            &API.validator("genesis_5")
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
        if let Some(status) = validator.get("status") {
            statuses.push(status.as_str().unwrap().to_owned());
        }
    }
    statuses.sort();
    statuses.dedup();
    assert_eq!(statuses, ["active", "resigned-temporary", "standby"]);
    let resolved = check(
        &API.resolve_name("genesis_5")
            .unwrap()
            .decode(&fixture("delegate-by-name"))
            .unwrap(),
    );
    assert_eq!(resolved["name"], "genesis_5");

    for name in ["round-1-delegates", "round-2-delegates"] {
        check(
            &API.round_validators(1)
                .unwrap()
                .decode(&fixture(name))
                .unwrap(),
        );
    }
}

#[test]
fn submissions() {
    let limits = API
        .node_configuration()
        .decode(&fixture("node-configuration"))
        .unwrap()
        .pool;
    for name in ["submit-accepted", "submit-mixed"] {
        let e = entry(name);
        let text = fs::read_to_string(dir().join(e.request_file.unwrap())).unwrap();
        let body: Value = serde_json::from_str(&text).unwrap();
        let txs: Vec<SubmitTx> = body["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| {
                let value = json!({ "id": tx["id"], "json": tx, "size": 160 });
                serde_json::from_value(value).unwrap()
            })
            .collect();
        let plan = API.submit(&txs, &limits).unwrap();
        let report = plan.finish([plan.calls()[0].decode(&fixture(name)).unwrap()]);
        let json = check(&report);
        for outcome in json["outcomes"].as_array().unwrap() {
            match outcome["status"].as_str().unwrap() {
                "accepted" => assert!(outcome["broadcast"].is_boolean()),
                "rejected" => {
                    assert!(outcome["reason"].is_string());
                    assert!(outcome["nodeCode"].is_string());
                    assert!(outcome["message"].is_string());
                }
                other => panic!("{other}"),
            }
        }
        let request: Request =
            serde_json::from_value(serde_json::to_value(plan.calls()[0].request()).unwrap())
                .unwrap();
        assert_eq!(&request, plan.calls()[0].request());
    }
    let mixed = entry("submit-mixed");
    let text = fs::read_to_string(dir().join(mixed.request_file.unwrap())).unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    let first = &body["transactions"][0];
    let tx: SubmitTx =
        serde_json::from_value(json!({ "id": first["id"], "json": first, "size": 160 })).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&serde_json::to_string(&tx).unwrap()).unwrap()["json"],
        *first
    );
}

#[test]
fn recorded_responses_round_trip() {
    for name in ["node-status", "rate-limited", "delegates-page"] {
        let response = fixture(name);
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["body"].is_string());
        assert_eq!(serde_json::from_value::<Response>(json).unwrap(), response);
    }
    let decoded: Response = serde_json::from_value(json!({
        "status": 200,
        "headers": [["X-Block-Height", "80"]],
        "body": fs::read_to_string(dir().join("node-status.json")).unwrap(),
    }))
    .unwrap();
    assert_eq!(
        API.node_status().decode(&decoded).unwrap(),
        API.node_status().decode(&fixture("node-status")).unwrap()
    );
}

#[test]
fn request_arguments() {
    for (value, expected) in [
        (json!({ "height": "82" }), BlockRef::Height(82)),
        (json!({ "height": 82 }), BlockRef::Height(82)),
        (json!({ "id": "ab" }), BlockRef::Id("ab".into())),
    ] {
        assert_eq!(
            serde_json::from_value::<BlockRef>(value.clone()).unwrap(),
            expected
        );
    }
    assert_eq!(
        serde_json::to_value(BlockRef::Height(82)).unwrap(),
        json!({ "height": "82" })
    );
    for (text, direction) in [
        ("all", HistoryDirection::All),
        ("sent", HistoryDirection::Sent),
        ("received", HistoryDirection::Received),
    ] {
        assert_eq!(serde_json::to_value(direction).unwrap(), json!(text));
        assert_eq!(
            serde_json::from_value::<HistoryDirection>(json!(text)).unwrap(),
            direction
        );
    }
    let filter: TxFilter = serde_json::from_value(json!({ "kind": "burn" })).unwrap();
    assert_eq!(filter.kind, Some(TxKind::Burn));
}
