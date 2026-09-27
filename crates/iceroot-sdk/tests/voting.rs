//! The vote library on a node's own data: the rules of the chain a local devnet of the reference
//! implementation served, and its validator list, recorded in the node API client's fixtures
//! (`crates/iceroot-sdk-api/tests/fixtures`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use iceroot_sdk::api::{PageRequest, Response, SolarCompat, ValidatorInfo};
use iceroot_sdk::profile::DevnetOptions;
use iceroot_sdk::vote::{
    Mode, PickSource, SelectError, SelectRequest, SnapshotSource, ValidatorStatus, VoteRules,
    VoteSnapshot, Voter, select, validate_vote,
};
use iceroot_sdk::voting::{relay_snapshot, relay_validator, vote_rules};
use iceroot_sdk::{Chain, Profile};

const API: SolarCompat = SolarCompat::new(53);

fn answer(file: &str) -> Response {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../iceroot-sdk-api/tests/fixtures/devnet");
    Response::new(200, fs::read(dir.join(file)).unwrap())
}

fn chain() -> Chain {
    let configuration = API
        .crypto_configuration()
        .decode(&answer("node-configuration-crypto.json"))
        .unwrap();
    Chain::from_node(&Profile::devnet(DevnetOptions::default()), &configuration).unwrap()
}

fn validators() -> Vec<ValidatorInfo> {
    let page = API
        .validators(PageRequest::first(100))
        .decode(&answer("delegates-page.json"))
        .unwrap();
    assert!(!page.has_next);
    page.items
}

fn snapshot(chain: &Chain) -> (u32, VoteSnapshot) {
    let status = API
        .node_status()
        .decode(&answer("node-status.json"))
        .unwrap();
    let height = u32::try_from(status.height).unwrap();
    let validators = validators().iter().map(relay_validator).collect();
    (height, relay_snapshot(chain, height, validators))
}

#[test]
fn the_devnet_s_vote_rules_are_the_solar_compatible_ones() {
    let chain = chain();
    let rules = chain.rules(2);
    assert_eq!(vote_rules(&rules), VoteRules::SOLAR_COMPATIBLE);
    // The most entries follow the seats of the milestone in force.
    let mut fewer = rules.clone();
    fewer.vote.max_entries = 21;
    assert_eq!(vote_rules(&fewer).max_entries, 21);
}

#[test]
fn a_snapshot_of_the_validator_list() {
    let chain = chain();
    let (height, snapshot) = snapshot(&chain);
    snapshot.validate().unwrap();
    assert_eq!(snapshot.height, u64::from(height));
    assert_eq!((snapshot.seats, snapshot.block_time_seconds), (53, 8));
    assert_eq!(snapshot.source, SnapshotSource::RelayApproximate);
    assert_eq!(snapshot.records.len(), 56);
    let status = |name: &str| snapshot.record(name).unwrap().status;
    assert_eq!(status("genesis_5"), ValidatorStatus::Active);
    assert_eq!(status("genesis_53"), ValidatorStatus::ResignedTemporary);
    assert_eq!(status("tx1n1160"), ValidatorStatus::ResignedPermanent);
    assert_eq!(status("tx1n2290"), ValidatorStatus::Standby);
    let top = snapshot.record("genesis_5").unwrap();
    assert_eq!(top.rank, Some(1));
    assert_eq!(top.vote_weight, 6_326_806_303);
    assert_eq!(top.voters, 2);
    let production = top.production.unwrap();
    assert_eq!((production.forged, production.assigned), (2, 2));
    // No first forged block was looked up: the seated days of a validator that forged are
    // unknown.
    assert_eq!(top.seated_days_in_window, None);
}

#[test]
fn a_selection_from_the_node_s_data() {
    let chain = chain();
    let (height, snapshot) = snapshot(&chain);
    let rules = vote_rules(&chain.rules(height));
    let holder = "daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8";
    for mode in Mode::ALL {
        let request = SelectRequest {
            rules,
            ..SelectRequest::new(mode, holder)
        };
        let selection = select(&snapshot, &request).unwrap();
        assert_eq!(selection.entries.len(), 20, "{mode}");
        assert!(
            validate_vote(&selection.vote(), &rules, Voter::Ordinary).is_empty(),
            "{mode}"
        );
        // The relay has no windowed record, declarations or payouts: every mode but Diversity
        // tops up from Diversity, and says so.
        if mode != Mode::Diversity {
            assert!(selection.topped_up > 0, "{mode}");
            assert!(selection.top_up_notice().is_some(), "{mode}");
            assert!(
                selection
                    .entries
                    .iter()
                    .any(|pick| pick.source == PickSource::TopUp)
            );
        }
    }

    // IceRoot's rules refuse the devnet's names, which have digits and underscores.
    let refused = select(&snapshot, &SelectRequest::new(Mode::Diversity, holder)).unwrap_err();
    assert_eq!(refused.code(), "BreaksRules");

    // A validator's account cannot vote, even on a network whose rules let it.
    let validator = &snapshot.record("genesis_5").unwrap().address;
    let refused = select(
        &snapshot,
        &SelectRequest {
            rules,
            ..SelectRequest::new(Mode::Diversity, validator)
        },
    )
    .unwrap_err();
    assert_eq!(refused, SelectError::ValidatorAccount);
    assert_eq!(refused.code(), "ValidatorCannotVote");
}
