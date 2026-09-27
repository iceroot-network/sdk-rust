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
    Mode, PickSource, SelectError, SelectRequest, Shortfall, SnapshotSource, ValidatorStatus,
    VoteRules, VoteSnapshot, Voter, check, select, validate_vote,
};
use iceroot_sdk::voting::{relay_snapshot, relay_validator, votable, vote_rules};
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

fn height() -> u32 {
    let status = API
        .node_status()
        .decode(&answer("node-status.json"))
        .unwrap();
    u32::try_from(status.height).unwrap()
}

fn snapshot_of(chain: &Chain, validators: &[ValidatorInfo]) -> VoteSnapshot {
    let relay = validators.iter().filter_map(relay_validator).collect();
    relay_snapshot(chain, height(), relay)
}

fn snapshot(chain: &Chain) -> (u32, VoteSnapshot) {
    (height(), snapshot_of(chain, &validators()))
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
    // 56 registered validators; one has not resigned and its node was never seen, so a vote may
    // not name it and the snapshot leaves it out.
    let listed = validators();
    assert_eq!(listed.len(), 56);
    let unseen: Vec<&str> = listed
        .iter()
        .filter(|info| !votable(info))
        .map(|info| info.name.as_str())
        .collect();
    assert_eq!(unseen, ["tx1n2290"]);
    assert_eq!(snapshot.records.len(), 55);
    assert!(snapshot.record("tx1n2290").is_none());
    let status = |name: &str| snapshot.record(name).unwrap().status;
    assert_eq!(status("genesis_5"), ValidatorStatus::Active);
    // Resigned validators have no node version and stay: every mode passes them over, and a
    // check reports a resigned pick as resigned.
    assert_eq!(status("genesis_53"), ValidatorStatus::ResignedTemporary);
    assert_eq!(status("tx1n1160"), ValidatorStatus::ResignedPermanent);
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

#[test]
fn a_validator_whose_node_is_not_seen_is_never_picked() {
    // A node refuses a vote naming a validator that has not resigned and whose node it has not
    // seen running (ERR_OFFLINE), which the list shows without a node version. Take the seated
    // validators ranked 2 and 20 out of sight: no selection of any mode names them, and a check
    // of a selection made while they were seen reports them.
    let chain = chain();
    let rules = vote_rules(&chain.rules(height()));
    let holder = "daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8";
    let mut listed = validators();
    let hidden: Vec<String> = listed
        .iter()
        .filter(|info| matches!(info.rank, Some(2 | 20)))
        .map(|info| info.name.clone())
        .collect();
    assert_eq!(hidden.len(), 2);
    let seen = snapshot_of(&chain, &listed);
    let before = (0..40)
        .map(|draw| {
            select(
                &seen,
                &SelectRequest {
                    rules,
                    draw,
                    ..SelectRequest::new(Mode::Diversity, holder)
                },
            )
            .unwrap()
        })
        .find(|selection| {
            selection
                .entries
                .iter()
                .any(|pick| hidden.contains(&pick.validator))
        })
        .expect("a draw that picks one of them while their nodes are seen");

    for info in &mut listed {
        if hidden.contains(&info.name) {
            info.version = None;
        }
    }
    let unseen = snapshot_of(&chain, &listed);
    assert_eq!(unseen.records.len(), seen.records.len() - 2);
    for mode in Mode::ALL {
        for draw in 0..20 {
            let selection = select(
                &unseen,
                &SelectRequest {
                    rules,
                    draw,
                    ..SelectRequest::new(mode, holder)
                },
            )
            .unwrap();
            assert!(
                selection
                    .entries
                    .iter()
                    .all(|pick| !hidden.contains(&pick.validator)),
                "{mode} {draw}"
            );
        }
    }
    let findings = check(&before, &unseen).unwrap();
    for finding in findings {
        if hidden.contains(&finding.validator) {
            assert!(!finding.still_meets);
            assert_eq!(finding.shortfalls, [Shortfall::NotInSnapshot]);
            assert_eq!(
                finding.why(),
                "No longer among the validators a vote can name"
            );
        } else {
            assert!(finding.still_meets, "{}", finding.why());
        }
    }
}
