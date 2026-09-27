//! Every refusal has a stable code and structured details, as the SDK's other crates give them:
//! the TypeScript and Go SDKs report exactly these.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_vote::{
    Mode, Problem, Production, SelectError, SelectRequest, SnapshotError, SnapshotSource,
    ValidatorRecord, ValidatorStatus, VoteEntry, VoteRules, VoteSnapshot, Voter, check, select,
    split, validate_vote,
};
use serde_json::json;

/// 30 healthy seated validators with names of three letters, `vaa` to `vbd`.
fn snapshot() -> VoteSnapshot {
    let records = (0..30u32)
        .map(|i| {
            let letter = |n: u32| char::from(b'a' + u8::try_from(n).unwrap());
            let name = format!("v{}{}", letter(i / 26), letter(i % 26));
            ValidatorRecord {
                address: format!("addr-{name}"),
                name,
                rank: Some(i + 1),
                seated: true,
                status: ValidatorStatus::Active,
                registered_height: Some(1),
                seated_days_in_window: Some(30),
                vote_weight: 1_000,
                voters: 3,
                production: Some(Production {
                    forged: 100,
                    assigned: 100,
                }),
                penalties: None,
                declarations: None,
                payouts: None,
                self_funded_weight_bp: None,
            }
        })
        .collect();
    VoteSnapshot {
        height: 1_000_000,
        window_days: 30,
        seats: 53,
        block_time_seconds: 8,
        source: SnapshotSource::Indexer,
        records,
    }
}

fn refusal(snapshot: &VoteSnapshot, request: &SelectRequest<'_>) -> SelectError {
    select(snapshot, request).expect_err("refused")
}

#[test]
fn every_refusal_of_select_has_a_code_and_details() {
    let s = snapshot();
    let holder = SelectRequest::new(Mode::Diversity, "addr-holder");

    let error = refusal(
        &s,
        &SelectRequest {
            count: 19,
            ..holder
        },
    );
    assert_eq!(error.code(), "InvalidPickCount");
    assert_eq!(
        error.details(),
        json!({ "count": 19, "minimum": 20, "maximum": 53 })
    );

    let error = refusal(&s, &SelectRequest::new(Mode::Diversity, "addr-vac"));
    assert_eq!(error.code(), "ValidatorCannotVote");
    assert_eq!(error.details(), json!({}));

    let mut bad = s.clone();
    bad.records[1].name = "vaa".to_owned();
    let error = refusal(&bad, &holder);
    assert_eq!(error.code(), "InvalidSnapshot");
    assert_eq!(
        error.details(),
        json!({ "reason": "duplicate-name", "name": "vaa" })
    );

    let error = refusal(
        &s,
        &SelectRequest {
            count: 31,
            ..holder
        },
    );
    assert_eq!(error.code(), "NotEnoughValidators");
    assert_eq!(error.details(), json!({ "requested": 31, "available": 30 }));

    // 16 names of three letters take 1 + 16 × 6 = 97 bytes, 17 take 103.
    let tight = VoteRules {
        max_bytes: 100,
        ..VoteRules::ICEROOT
    };
    let error = refusal(
        &s,
        &SelectRequest {
            rules: tight,
            ..holder
        },
    );
    assert_eq!(error.code(), "DoesNotFit");
    assert_eq!(
        error.details(),
        json!({ "fits": 16, "minimum": 20, "maxEntries": 53, "maxBytes": 100 })
    );

    let four_percent = VoteRules {
        max_entry_basis_points: 400,
        ..VoteRules::ICEROOT
    };
    let error = refusal(
        &s,
        &SelectRequest {
            rules: four_percent,
            ..holder
        },
    );
    assert_eq!(error.code(), "BreaksRules");
    let details = error.details();
    let problems = details["problems"].as_array().unwrap();
    assert_eq!(problems.len(), 20);
    for problem in problems {
        assert_eq!(problem["reason"], "share-too-large");
        assert_eq!(problem["basisPoints"], 500);
        assert_eq!(problem["maximum"], 400);
        assert!(problem["validator"].as_str().unwrap().starts_with('v'));
    }
}

#[test]
fn snapshot_problems_have_reasons_and_values() {
    let cases: [(SnapshotError, serde_json::Value); 7] = [
        (
            SnapshotError::Window { days: 90 },
            json!({ "reason": "window", "days": 90 }),
        ),
        (SnapshotError::NoSeats, json!({ "reason": "no-seats" })),
        (
            SnapshotError::NoBlockTime,
            json!({ "reason": "no-block-time" }),
        ),
        (
            SnapshotError::InvalidName {
                name: "A".to_owned(),
            },
            json!({ "reason": "name", "name": "A" }),
        ),
        (
            SnapshotError::DuplicateName {
                name: "vala".to_owned(),
            },
            json!({ "reason": "duplicate-name", "name": "vala" }),
        ),
        (
            SnapshotError::DuplicateAddress {
                address: "addr".to_owned(),
            },
            json!({ "reason": "duplicate-address", "address": "addr" }),
        ),
        (
            SnapshotError::Inconsistent {
                name: "vala".to_owned(),
                field: "seated days",
            },
            json!({ "reason": "inconsistent", "name": "vala", "field": "seatedDaysInWindow" }),
        ),
    ];
    for (error, details) in cases {
        assert_eq!(error.code(), "InvalidSnapshot");
        assert_eq!(error.details(), details, "{error}");
    }

    // The field of an inconsistent record, as a snapshot's check reports it.
    let mut s = snapshot();
    s.records[0].registered_height = Some(s.height + 1);
    let selection = select(
        &snapshot(),
        &SelectRequest::new(Mode::Diversity, "addr-holder"),
    )
    .unwrap();
    let error = check(&selection, &s).unwrap_err();
    assert_eq!(
        error.details(),
        json!({ "reason": "inconsistent", "name": "vaa", "field": "registeredHeight" })
    );
    s.records[0].registered_height = Some(1);
    s.records[0].self_funded_weight_bp = Some(10_001);
    assert_eq!(
        check(&selection, &s).unwrap_err().details()["field"],
        "selfFundedWeightBp"
    );
    s.records[0].self_funded_weight_bp = None;
    s.records[0].status = ValidatorStatus::ResignedTemporary;
    assert_eq!(
        check(&selection, &s).unwrap_err().details()["field"],
        "status"
    );
}

#[test]
fn a_split_that_cannot_be_made_is_an_invalid_vote() {
    let names: Vec<String> = (0..10_001).map(|i| format!("v{i}")).collect();
    let error = split(&names).unwrap_err();
    assert_eq!(error.code(), "InvalidVote");
    assert_eq!(
        error.details(),
        json!({ "reason": "too-many-entries", "count": 10_001, "maximum": 10_000 })
    );
}

#[test]
fn vote_problems_have_reasons_and_values() {
    let entry = |validator: &str, basis_points: u16| VoteEntry {
        validator: validator.to_owned(),
        basis_points,
    };
    // One of each problem but too many entries: a validator's account, 3 entries of at least 20,
    // a name IceRoot refuses, a validator named twice, a zero share, a share above 500 basis
    // points, a sum of 1,500 and, with a limit of 10 bytes, 1 + 3 × 6 = 19 bytes.
    let entries = [entry("Bad", 500), entry("vaa", 1_000), entry("vaa", 0)];
    let rules = VoteRules {
        max_bytes: 10,
        ..VoteRules::ICEROOT
    };
    let problems: Vec<serde_json::Value> = validate_vote(&entries, &rules, Voter::Validator)
        .iter()
        .map(Problem::details)
        .collect();
    assert_eq!(
        problems,
        [
            json!({ "reason": "validator-account" }),
            json!({ "reason": "too-few-entries", "count": 3, "minimum": 20 }),
            json!({ "reason": "name", "validator": "Bad" }),
            json!({
                "reason": "share-too-large",
                "validator": "vaa",
                "basisPoints": 1_000,
                "maximum": 500,
            }),
            json!({ "reason": "duplicate", "validator": "vaa" }),
            json!({ "reason": "zero-share", "validator": "vaa" }),
            json!({ "reason": "sum", "basisPoints": 1_500 }),
            json!({ "reason": "too-large", "bytes": 19, "maximum": 10 }),
        ]
    );
    let many: Vec<VoteEntry> = (0..54).map(|i| entry(&format!("v{i}"), 1)).collect();
    let problem = validate_vote(&many, &VoteRules::SOLAR_COMPATIBLE, Voter::Ordinary)
        .first()
        .map(Problem::details);
    assert_eq!(
        problem,
        Some(json!({ "reason": "too-many-entries", "count": 54, "maximum": 53 }))
    );
}
