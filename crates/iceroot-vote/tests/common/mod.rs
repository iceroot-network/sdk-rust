//! Fixture loading shared by the integration tests. The fixtures are JSON in the shape of the
//! TypeScript API: camelCase fields, 64- and 128-bit integers as decimal strings.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use iceroot_vote::{
    Declarations, Payouts, Penalties, Production, RelaySnapshot, RelayValidator, Resignation,
    Selection, SnapshotSource, ValidatorRecord, ValidatorStatus, VoteSnapshot,
};
use serde_json::{Value, json};

/// The path of a file in `tests/data`.
pub fn data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

/// A JSON file in `tests/data`.
pub fn load_json(name: &str) -> Value {
    let text = std::fs::read_to_string(data_path(name)).expect("fixture readable");
    serde_json::from_str(&text).expect("fixture is JSON")
}

fn big<T: std::str::FromStr>(value: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    value
        .as_str()
        .expect("big integers are strings")
        .parse()
        .expect("decimal")
}

fn opt_big<T: std::str::FromStr>(value: &Value) -> Option<T>
where
    T::Err: std::fmt::Debug,
{
    (!value.is_null()).then(|| big(value))
}

fn u32_of(value: &Value) -> u32 {
    u32::try_from(value.as_u64().expect("number")).expect("u32")
}

fn opt_u32(value: &Value) -> Option<u32> {
    (!value.is_null()).then(|| u32_of(value))
}

fn opt_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

/// A snapshot from its JSON form.
pub fn snapshot_from_json(value: &Value) -> VoteSnapshot {
    let records = value["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(record_from_json)
        .collect();
    VoteSnapshot {
        height: big(&value["height"]),
        window_days: u32_of(&value["windowDays"]),
        seats: u32_of(&value["seats"]),
        block_time_seconds: u32_of(&value["blockTimeSeconds"]),
        source: SnapshotSource::from_id(value["source"].as_str().expect("source"))
            .expect("known source"),
        records,
    }
}

fn record_from_json(value: &Value) -> ValidatorRecord {
    ValidatorRecord {
        name: value["name"].as_str().expect("name").to_owned(),
        address: value["address"].as_str().expect("address").to_owned(),
        rank: opt_u32(&value["rank"]),
        seated: value["seated"].as_bool().expect("seated"),
        status: ValidatorStatus::from_id(value["status"].as_str().expect("status"))
            .expect("known status"),
        registered_height: opt_big(&value["registeredHeight"]),
        seated_days_in_window: opt_u32(&value["seatedDaysInWindow"]),
        vote_weight: big(&value["voteWeight"]),
        voters: u32_of(&value["voters"]),
        production: (!value["production"].is_null()).then(|| Production {
            forged: value["production"]["forged"].as_u64().expect("forged"),
            assigned: value["production"]["assigned"].as_u64().expect("assigned"),
        }),
        penalties: (!value["penalties"].is_null()).then(|| {
            let p = &value["penalties"];
            Penalties {
                jailed_in_window: p["jailedInWindow"].as_bool().expect("bool"),
                equivocation_in_window: p["equivocationInWindow"].as_bool().expect("bool"),
                ever: p["ever"].as_bool().expect("bool"),
            }
        }),
        declarations: (!value["declarations"].is_null()).then(|| {
            let d = &value["declarations"];
            Declarations {
                operator: opt_string(&d["operator"]),
                hosting: opt_string(&d["hosting"]),
                country: opt_string(&d["country"]),
                complete: d["complete"].as_bool().expect("bool"),
            }
        }),
        payouts: (!value["payouts"].is_null()).then(|| Payouts {
            per_unit_weight: big(&value["payouts"]["perUnitWeight"]),
            intervals: u32_of(&value["payouts"]["intervals"]),
        }),
        self_funded_weight_bp: (!value["selfFundedWeightBp"].is_null()).then(|| {
            u16::try_from(value["selfFundedWeightBp"].as_u64().expect("number")).expect("u16")
        }),
    }
}

/// Relay data from its JSON form.
pub fn relay_from_json(value: &Value) -> RelaySnapshot {
    let validators = value["validators"]
        .as_array()
        .expect("validators")
        .iter()
        .map(|v| RelayValidator {
            name: v["name"].as_str().expect("name").to_owned(),
            address: v["address"].as_str().expect("address").to_owned(),
            rank: opt_u32(&v["rank"]),
            resignation: match v["resignation"].as_str() {
                None => None,
                Some("temporary") => Some(Resignation::Temporary),
                Some("permanent") => Some(Resignation::Permanent),
                Some(other) => panic!("unknown resignation {other}"),
            },
            vote_weight: big(&v["voteWeight"]),
            voters: u32_of(&v["voters"]),
            produced_blocks: v["producedBlocks"].as_u64().expect("produced"),
            missed_blocks: v["missedBlocks"].as_u64(),
            registered_height: opt_big(&v["registeredHeight"]),
            first_forged_height: opt_big(&v["firstForgedHeight"]),
        })
        .collect();
    RelaySnapshot {
        height: big(&value["height"]),
        seats: u32_of(&value["seats"]),
        block_time_seconds: u32_of(&value["blockTimeSeconds"]),
        validators,
    }
}

/// The synthetic snapshot of 80 validators with windowed production, declarations and payouts.
pub fn synthetic() -> VoteSnapshot {
    snapshot_from_json(&load_json("synthetic-80.json"))
}

/// The devnet-shaped relay data (56 validators, about 11 days of chain).
pub fn devnet_relay() -> RelaySnapshot {
    relay_from_json(&load_json("devnet-relay.json"))
}

/// The devnet-shaped snapshot, from the relay data.
pub fn devnet() -> VoteSnapshot {
    VoteSnapshot::from_relay(devnet_relay())
}

/// A fixture by name: `synthetic-80` or `devnet-relay`.
pub fn fixture(name: &str) -> VoteSnapshot {
    match name {
        "synthetic-80" => synthetic(),
        "devnet-relay" => devnet(),
        other => panic!("unknown fixture {other}"),
    }
}

/// The reproducible part of a selection as JSON: seed, pool, top-up count, the entries in
/// canonical order and the names in draw order.
pub fn selection_output(selection: &Selection) -> Value {
    let mut steps: Vec<(u32, &str)> = selection
        .entries
        .iter()
        .map(|pick| (pick.step, pick.validator.as_str()))
        .collect();
    steps.sort_unstable();
    json!({
        "seed": selection.seed_hex(),
        "pool": selection.pool,
        "toppedUp": selection.topped_up,
        "entries": selection
            .entries
            .iter()
            .map(|pick| json!([pick.validator, pick.basis_points]))
            .collect::<Vec<_>>(),
        "drawOrder": steps.iter().map(|(_, name)| *name).collect::<Vec<_>>(),
    })
}
