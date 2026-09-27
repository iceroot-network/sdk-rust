//! Reproducibility vectors: a fixture, an account, a mode, a count, a draw number and the vote
//! rules give exactly the recorded selection. The vectors pin the selection rules of
//! `LIBRARY_VERSION`; once a version is released, any change to the draw, the weights or the
//! criteria must come with a new version.
//!
//! An input's `rules` is `iceroot` or `solar-compatible` (the two stages' vote rules), and an
//! optional `maxBytes` replaces the size limit, so that some vectors keep only the start of the
//! draw that fits.
//!
//! To regenerate after a deliberate change, run with `ICEROOT_VOTE_WRITE_VECTORS=1`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use iceroot_vote::{LIBRARY_VERSION, Mode, SelectRequest, VoteRules, select};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use common::{data_path, fixture, selection_output};

const VECTORS: &str = "select-v1.jsonl";
const FIXTURES: [(&str, &str); 2] = [
    ("synthetic-80", "synthetic-80.json"),
    ("devnet-relay", "devnet-relay.json"),
];

/// The vote rules of the stage a fixture describes.
fn stage(fixture: &str) -> &'static str {
    match fixture {
        "devnet-relay" => "solar-compatible",
        _ => "iceroot",
    }
}

/// The inputs the vector file covers.
fn inputs() -> Vec<Value> {
    let mut inputs = Vec::new();
    for (fixture, _) in FIXTURES {
        for mode in Mode::ALL {
            for account in ["holder-a", "holder-b", "tice1holderexample"] {
                for draw in [0u32, 1] {
                    inputs.push(json!({
                        "fixture": fixture,
                        "account": account,
                        "mode": mode.id(),
                        "count": 20,
                        "draw": draw,
                        "rules": stage(fixture),
                    }));
                }
            }
        }
    }
    for mode in Mode::ALL {
        for count in [21u8, 30, 53] {
            inputs.push(json!({
                "fixture": "synthetic-80",
                "account": "holder-a",
                "mode": mode.id(),
                "count": count,
                "draw": 7,
                "rules": "iceroot",
            }));
        }
    }
    inputs.push(json!({
        "fixture": "synthetic-80",
        "account": "holder-a",
        "mode": "diversity",
        "count": 20,
        "draw": u32::MAX,
        "rules": "iceroot",
    }));
    // A tighter size limit keeps only the start of each draw.
    for (fixture, max_bytes) in [("synthetic-80", 400), ("devnet-relay", 560)] {
        for mode in Mode::ALL {
            inputs.push(json!({
                "fixture": fixture,
                "account": "holder-b",
                "mode": mode.id(),
                "count": 53,
                "draw": 3,
                "rules": stage(fixture),
                "maxBytes": max_bytes,
            }));
        }
    }
    inputs
}

/// The vote rules of an input.
fn rules(input: &Value) -> VoteRules {
    let rules = match input["rules"].as_str().unwrap() {
        "iceroot" => VoteRules::ICEROOT,
        "solar-compatible" => VoteRules::SOLAR_COMPATIBLE,
        other => panic!("unknown rules {other}"),
    };
    match input.get("maxBytes") {
        Some(max_bytes) => VoteRules {
            max_bytes: u16::try_from(max_bytes.as_u64().unwrap()).unwrap(),
            ..rules
        },
        None => rules,
    }
}

fn run(input: &Value) -> Value {
    let snapshot = fixture(input["fixture"].as_str().unwrap());
    let request = SelectRequest {
        mode: Mode::from_id(input["mode"].as_str().unwrap()).unwrap(),
        account: input["account"].as_str().unwrap(),
        count: u8::try_from(input["count"].as_u64().unwrap()).unwrap(),
        draw: u32::try_from(input["draw"].as_u64().unwrap()).unwrap(),
        rules: rules(input),
    };
    selection_output(&select(&snapshot, &request).unwrap())
}

fn fixture_digests() -> Value {
    let mut digests = serde_json::Map::new();
    for (name, file) in FIXTURES {
        let bytes = std::fs::read(data_path(file)).unwrap();
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        digests.insert(name.to_owned(), json!({ "file": file, "sha256": digest }));
    }
    Value::Object(digests)
}

fn meta(records: usize) -> Value {
    json!({
        "op": "meta",
        "format": "heartwood-vectors/1",
        "class": "vote-select-v1",
        "records": records,
        "library": LIBRARY_VERSION,
        "generator": "crates/iceroot-vote/tests/vectors.rs with ICEROOT_VOTE_WRITE_VECTORS=1",
        "fixtures": fixture_digests(),
    })
}

#[test]
fn selections_match_the_vectors() {
    let path = data_path(VECTORS);
    if std::env::var_os("ICEROOT_VOTE_WRITE_VECTORS").is_some() {
        let inputs = inputs();
        let mut text = serde_json::to_string(&meta(inputs.len())).unwrap();
        text.push('\n');
        for input in &inputs {
            let record = json!({ "op": "vote.select", "input": input, "output": run(input) });
            text.push_str(&serde_json::to_string(&record).unwrap());
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines = text.lines();
    let header: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let records: Vec<Value> = lines.map(|l| serde_json::from_str(l).unwrap()).collect();
    // The fixtures are the ones the vectors were made from, and every input is covered.
    assert_eq!(header, meta(records.len()));
    let covered: Vec<&Value> = records.iter().map(|r| &r["input"]).collect();
    let expected = inputs();
    assert_eq!(covered, expected.iter().collect::<Vec<_>>());
    for record in &records {
        assert_eq!(record["op"], "vote.select");
        assert_eq!(
            run(&record["input"]),
            record["output"],
            "{}",
            record["input"]
        );
    }
}

#[test]
fn the_first_vector_by_hand() {
    // One selection spelled out, so that a reader can check the file format against it.
    let text = std::fs::read_to_string(data_path(VECTORS)).unwrap();
    let first: Value = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
    assert_eq!(
        first["input"],
        json!({"fixture": "synthetic-80", "account": "holder-a", "mode": "diversity", "count": 20, "draw": 0, "rules": "iceroot"})
    );
    let seed = iceroot_vote::seed("holder-a", Mode::Diversity, 5_000_000, 0);
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(first["output"]["seed"], json!(hex));
    let entries = first["output"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 20);
    assert!(entries.iter().all(|e| e[1] == json!(500)));
}
