//! `check` reports picks that no longer meet their criteria, and changes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use iceroot_vote::{
    Declarations, Finding, Mode, Penalties, PickSource, Production, SelectRequest, Selection,
    Shortfall, ValidatorStatus, VoteSnapshot, check, select,
};

use common::{devnet, synthetic};

fn selection(snapshot: &VoteSnapshot, mode: Mode, account: &str) -> Selection {
    select(snapshot, &SelectRequest::new(mode, account)).unwrap()
}

fn failing(findings: &[Finding]) -> Vec<(&str, &[Shortfall])> {
    findings
        .iter()
        .filter(|f| !f.still_meets)
        .map(|f| (f.validator.as_str(), f.shortfalls.as_slice()))
        .collect()
}

fn record_mut<'a>(
    snapshot: &'a mut VoteSnapshot,
    name: &str,
) -> &'a mut iceroot_vote::ValidatorRecord {
    snapshot
        .records
        .iter_mut()
        .find(|r| r.name == name)
        .unwrap()
}

#[test]
fn unchanged_data_meets_every_criterion() {
    for snapshot in [synthetic(), devnet()] {
        for mode in Mode::ALL {
            let chosen = selection(&snapshot, mode, "addr-holder-check");
            let findings = check(&chosen, &snapshot).unwrap();
            assert_eq!(findings.len(), chosen.entries.len());
            assert!(findings.iter().all(|f| f.still_meets), "{mode}");
            assert!(
                findings
                    .iter()
                    .all(|f| f.why() == "Still meets its criteria")
            );
            for (finding, pick) in findings.iter().zip(&chosen.entries) {
                assert_eq!(finding.validator, pick.validator);
            }
        }
    }
}

#[test]
fn a_resigned_validator_is_flagged_and_the_selection_is_untouched() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::Diversity, "addr-holder-check");
    let before = chosen.clone();
    let name = chosen.entries[3].validator.clone();
    let record = record_mut(&mut snapshot, &name);
    record.status = ValidatorStatus::ResignedTemporary;
    record.seated = false;
    record.rank = None;
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(chosen, before);
    assert_eq!(
        failing(&findings),
        vec![(
            name.as_str(),
            &[Shortfall::Resigned {
                status: ValidatorStatus::ResignedTemporary
            }][..]
        )]
    );
    let finding = findings.iter().find(|f| f.validator == name).unwrap();
    assert_eq!(finding.why(), "Validator resigned for now");
    // A validator that left the snapshot altogether.
    let mut gone = synthetic();
    gone.records.retain(|r| r.name != name);
    let findings = check(&chosen, &gone).unwrap();
    assert_eq!(
        failing(&findings),
        vec![(name.as_str(), &[Shortfall::NotInSnapshot][..])]
    );
}

#[test]
fn reliability_picks_lose_their_record() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::Reliability, "addr-holder-check");
    let slow = chosen.entries[0].validator.clone();
    let jailed = chosen.entries[1].validator.clone();
    record_mut(&mut snapshot, &slow).production = Some(Production {
        forged: 900,
        assigned: 1_000,
    });
    record_mut(&mut snapshot, &jailed).penalties = Some(Penalties {
        jailed_in_window: true,
        equivocation_in_window: false,
        ever: true,
    });
    let findings = check(&chosen, &snapshot).unwrap();
    let failed = failing(&findings);
    assert_eq!(failed.len(), 2);
    assert!(failed.contains(&(
        slow.as_str(),
        &[Shortfall::LowProduction {
            forged: 900,
            assigned: 1_000,
            minimum_bp: 9_500
        }][..]
    )));
    assert!(failed.contains(&(
        jailed.as_str(),
        &[Shortfall::PenalizedInWindow {
            jailed: true,
            equivocation: false
        }][..]
    )));
}

#[test]
fn a_newcomer_that_climbed_no_longer_needs_support() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::SupportNewcomers, "addr-holder-check");
    let climber = chosen.entries[0].validator.clone();
    record_mut(&mut snapshot, &climber).rank = Some(30);
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(
        failing(&findings),
        vec![(
            climber.as_str(),
            &[Shortfall::NotNearCutoff {
                rank: 30,
                seats: 53
            }][..]
        )]
    );
}

#[test]
fn newcomer_picks_that_fall_far_below_or_exceed_the_operator_cap() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::SupportNewcomers, "addr-holder-check");
    assert_eq!(chosen.topped_up, 0);
    let mut by_step: Vec<_> = chosen.entries.iter().collect();
    by_step.sort_by_key(|p| p.step);
    // One pick falls to rank 74, more than 20 ranks below the last seat.
    let fell = by_step[0].validator.clone();
    record_mut(&mut snapshot, &fell).rank = Some(74);
    // Three later picks now declare the same operator: the third by draw order exceeds the cap.
    let same: Vec<String> = by_step[1..4].iter().map(|p| p.validator.clone()).collect();
    for name in &same {
        let record = record_mut(&mut snapshot, name);
        record.declarations.as_mut().unwrap().operator = Some("Merged Operator".to_owned());
    }
    let findings = check(&chosen, &snapshot).unwrap();
    let failed = failing(&findings);
    assert_eq!(failed.len(), 2, "{failed:?}");
    assert!(failed.contains(&(
        fell.as_str(),
        &[Shortfall::FarBelowCutoff {
            rank: 74,
            seats: 53,
            ranks_below: 20
        }][..]
    )));
    assert!(failed.contains(&(
        same[2].as_str(),
        &[Shortfall::OperatorCap {
            operator: Some("Merged Operator".to_owned()),
            maximum: 2
        }][..]
    )));
    let finding = findings.iter().find(|f| f.validator == fell).unwrap();
    assert_eq!(
        finding.why(),
        "Rank 74 is more than 20 ranks below the last seat (53)"
    );
}

#[test]
fn a_diversity_pick_that_falls_out_of_the_ranks_is_flagged() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::Diversity, "addr-holder-check");
    let name = chosen.entries[2].validator.clone();
    record_mut(&mut snapshot, &name).rank = Some(64);
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(
        failing(&findings),
        vec![(
            name.as_str(),
            &[Shortfall::FarBelowCutoff {
                rank: 64,
                seats: 53,
                ranks_below: 10
            }][..]
        )]
    );
}

#[test]
fn rewards_picks_that_stop_paying_or_exceed_the_operator_cap() {
    let mut snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::MaximumRewards, "addr-holder-check");
    let mut by_step: Vec<_> = chosen.entries.iter().collect();
    by_step.sort_by_key(|p| p.step);
    // One pick stops paying.
    let stopped = by_step[0].validator.clone();
    record_mut(&mut snapshot, &stopped).payouts = None;
    // Three later picks now declare the same operator: the third by draw order exceeds the cap.
    let same: Vec<String> = by_step[1..4].iter().map(|p| p.validator.clone()).collect();
    for name in &same {
        let record = record_mut(&mut snapshot, name);
        let declarations = record
            .declarations
            .get_or_insert_with(Declarations::default);
        declarations.operator = Some("Merged Operator".to_owned());
    }
    let findings = check(&chosen, &snapshot).unwrap();
    let failed = failing(&findings);
    assert_eq!(failed.len(), 2, "{failed:?}");
    assert!(failed.contains(&(stopped.as_str(), &[Shortfall::NoMeasuredPayouts][..])));
    assert!(failed.contains(&(
        same[2].as_str(),
        &[Shortfall::OperatorCap {
            operator: Some("Merged Operator".to_owned()),
            maximum: 2
        }][..]
    )));
}

#[test]
fn rewards_top_ups_count_towards_a_declared_operator() {
    // 42 Maximum Rewards picks and 11 top-ups. A top-up whose validator now declares the same
    // operator as two earlier picks exceeds the cap; one that declares no operator never does.
    let mut snapshot = synthetic();
    let mut request = SelectRequest::new(Mode::MaximumRewards, "addr-holder-check");
    request.count = 53;
    let chosen = select(&snapshot, &request).unwrap();
    let mut by_step: Vec<_> = chosen.entries.iter().collect();
    by_step.sort_by_key(|p| p.step);
    let top_up = by_step
        .iter()
        .find(|p| p.source == PickSource::TopUp)
        .unwrap()
        .validator
        .clone();
    let earlier: Vec<String> = by_step
        .iter()
        .filter(|p| p.source == PickSource::Mode)
        .take(2)
        .map(|p| p.validator.clone())
        .collect();
    for name in earlier.iter().chain([&top_up]) {
        let record = record_mut(&mut snapshot, name);
        let declarations = record
            .declarations
            .get_or_insert_with(Declarations::default);
        declarations.operator = Some("Merged Operator".to_owned());
    }
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(
        failing(&findings),
        vec![(
            top_up.as_str(),
            &[Shortfall::OperatorCap {
                operator: Some("Merged Operator".to_owned()),
                maximum: 2
            }][..]
        )]
    );
    // The same top-up declaring no operator is fine.
    let record = record_mut(&mut snapshot, &top_up);
    if let Some(declarations) = record.declarations.as_mut() {
        declarations.operator = None;
    }
    assert!(
        check(&chosen, &snapshot)
            .unwrap()
            .iter()
            .all(|f| f.still_meets)
    );
}

#[test]
fn top_up_picks_are_judged_by_diversity() {
    // On the devnet, Support Newcomers has no pool: every pick is a Diversity top-up, which
    // still meets Diversity's criteria though no validator meets the Newcomers criteria.
    let mut snapshot = devnet();
    let chosen = selection(&snapshot, Mode::SupportNewcomers, "dev-holder-check");
    assert!(chosen.entries.iter().all(|p| p.source == PickSource::TopUp));
    assert!(
        check(&chosen, &snapshot)
            .unwrap()
            .iter()
            .all(|f| f.still_meets)
    );
    let name = chosen.entries[5].validator.clone();
    let record = record_mut(&mut snapshot, &name);
    record.production = Some(Production {
        forged: 10,
        assigned: 100,
    });
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(failing(&findings).len(), 1);
    assert!(matches!(
        failing(&findings)[0].1,
        [Shortfall::LowProduction { .. }]
    ));
}

#[test]
fn holder_picks_are_judged_by_registration_only() {
    let mut snapshot = synthetic();
    let mut chosen = selection(&snapshot, Mode::Reliability, "addr-holder-check");
    // The holder replaced two picks on the review screen with validators of their own choice.
    chosen.entries[0].validator = "mesquite".to_owned(); // 94 %: fails every mode's health bar
    chosen.entries[0].source = PickSource::Holder;
    chosen.entries[1].validator = "hazel".to_owned();
    chosen.entries[1].source = PickSource::Holder;
    let findings = check(&chosen, &snapshot).unwrap();
    assert!(findings[0].still_meets && findings[1].still_meets);
    let record = record_mut(&mut snapshot, "hazel");
    record.status = ValidatorStatus::ResignedPermanent;
    record.seated = false;
    let findings = check(&chosen, &snapshot).unwrap();
    assert_eq!(
        failing(&findings),
        vec![(
            "hazel",
            &[Shortfall::Resigned {
                status: ValidatorStatus::ResignedPermanent
            }][..]
        )]
    );
}

#[test]
fn an_invalid_snapshot_is_an_error() {
    let snapshot = synthetic();
    let chosen = selection(&snapshot, Mode::Diversity, "addr-holder-check");
    let mut bad = snapshot.clone();
    bad.window_days = 90;
    assert!(check(&chosen, &bad).is_err());
}
