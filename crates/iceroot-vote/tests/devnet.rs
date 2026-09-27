//! The devnet-shaped snapshot: a node's relay data, with lifetime counters only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;

use iceroot_vote::{
    Dimension, Mode, PickSource, Problem, Reason, SelectError, SelectRequest, SnapshotSource,
    ValidatorStatus, VoteRules, VoteSnapshot, Voter, evaluate, select, validate_vote,
};

use common::{devnet, devnet_relay};

/// A first draw of 20 under the devnet's rules, the Solar-compatible stage.
fn request(mode: Mode, account: &str) -> SelectRequest<'_> {
    SelectRequest {
        rules: VoteRules::SOLAR_COMPATIBLE,
        ..SelectRequest::new(mode, account)
    }
}

fn pool_size(snapshot: &VoteSnapshot, mode: Mode) -> usize {
    evaluate(snapshot, mode)
        .unwrap()
        .iter()
        .filter(|c| c.eligible)
        .count()
}

/// The same validators at height 318 of a fresh chain: a few blocks each, first forged in the
/// first round.
fn fresh() -> VoteSnapshot {
    let mut relay = devnet_relay();
    relay.height = 318;
    for (i, validator) in relay.validators.iter_mut().enumerate() {
        let i = u64::try_from(i).unwrap();
        validator.registered_height = Some(0);
        if validator.produced_blocks > 0 {
            validator.produced_blocks = 5 + i % 2;
            validator.missed_blocks = Some(i % 3 / 2);
            validator.first_forged_height = Some(1 + i % 53);
        }
    }
    VoteSnapshot::from_relay(relay)
}

#[test]
fn relay_data_becomes_an_approximate_snapshot() {
    let s = devnet();
    assert_eq!(s.source, SnapshotSource::RelayApproximate);
    assert_eq!(s.window_days, 30);
    assert_eq!(s.records.len(), 56);
    assert_eq!(s.validate(), Ok(()));
    let temporary = s.record("genesis_17").unwrap();
    assert_eq!(temporary.status, ValidatorStatus::ResignedTemporary);
    assert!(!temporary.seated);
    assert_eq!(
        s.record("genesis_42").unwrap().status,
        ValidatorStatus::ResignedPermanent
    );
    let early = s.record("early_bird").unwrap();
    assert_eq!(early.status, ValidatorStatus::Active);
    assert_eq!(early.rank, Some(2));
    assert_eq!(early.seated_days_in_window, Some(5));
    let production = early.production.unwrap();
    assert_eq!((production.forged, production.assigned), (700, 702));
    // Seated, never forged: no production record and no seated days yet.
    let quiet = s.record("quiet.one").unwrap();
    assert_eq!(quiet.status, ValidatorStatus::Active);
    assert_eq!(quiet.production, None);
    assert_eq!(quiet.seated_days_in_window, Some(0));
    // Below the cutoff, and the node reports no missed count.
    let late = s.record("late_joiner").unwrap();
    assert_eq!(late.status, ValidatorStatus::Standby);
    assert_eq!(late.production, None);
    // About 11 days of chain.
    assert_eq!(
        s.record("genesis_1").unwrap().seated_days_in_window,
        Some(11)
    );
    for record in &s.records {
        assert_eq!(record.penalties, None);
        assert_eq!(record.declarations, None);
        assert_eq!(record.payouts, None);
        assert_eq!(record.self_funded_weight_bp, None);
    }
}

#[test]
fn diversity_works_on_rank_bands() {
    let s = devnet();
    // Every validator that has not resigned, except one at 90 % over its lifetime.
    assert_eq!(pool_size(&s, Mode::Diversity), 53);
    let mut largest_band_total = 0;
    for i in 0..200 {
        let account = format!("dev-holder-{i}");
        let selection = select(&s, &request(Mode::Diversity, &account)).unwrap();
        assert_eq!(selection.snapshot_source, SnapshotSource::RelayApproximate);
        assert_eq!(selection.topped_up, 0);
        assert!(
            validate_vote(
                &selection.vote(),
                &VoteRules::SOLAR_COMPATIBLE,
                Voter::Ordinary
            )
            .is_empty()
        );
        let mut bands: BTreeMap<String, usize> = BTreeMap::new();
        for pick in &selection.entries {
            let band = pick
                .reasons
                .iter()
                .find_map(|r| match r {
                    Reason::Group {
                        dimension: Dimension::RankBand,
                        value,
                        ..
                    } => value.clone(),
                    _ => None,
                })
                .unwrap();
            *bands.entry(band).or_insert(0) += 1;
            // Undeclared operator, hosting and region: one group each, shared by every pick.
            let undeclared = pick
                .reasons
                .iter()
                .filter(|r| matches!(r, Reason::Group { value: None, .. }))
                .count();
            assert_eq!(undeclared, 3);
            let production = pick.reasons.iter().find_map(|r| match r {
                Reason::Production { approximate, .. } => Some(*approximate),
                _ => None,
            });
            assert!(production.unwrap_or(true));
        }
        // Six bands of 9 or 8 validators, and 20 picks.
        assert!(bands.len() >= 5, "{bands:?}");
        largest_band_total += bands.values().max().unwrap();
    }
    // A uniform draw of 20 from six bands of 9 or 8 validators puts about 5.3 picks in the
    // largest band on average; the rank-band spread keeps it lower.
    assert!(largest_band_total < 200 * 48 / 10, "{largest_band_total}");
    // The text says the figures are lifetime counts.
    let selection = select(&s, &request(Mode::Diversity, "dev-holder")).unwrap();
    let text: Vec<String> = selection.entries[0]
        .reasons
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        text.iter()
            .any(|t| t.contains("over its lifetime") || t.contains("No production record")),
        "{text:?}"
    );
    assert!(text.iter().any(|t| t.contains("keeps no penalty record")));
}

#[test]
fn reliability_needs_seven_seated_days() {
    // Eleven days of chain: every genesis validator counts, except the one at 90 % and the two
    // that resigned; the newer validator has 5 days.
    let s = devnet();
    assert_eq!(pool_size(&s, Mode::Reliability), 50);
    let selection = select(&s, &request(Mode::Reliability, "dev-holder")).unwrap();
    assert_eq!(selection.topped_up, 0);
    assert!(
        selection
            .entries
            .iter()
            .all(|p| p.source == PickSource::Mode)
    );
    assert!(
        !selection
            .entries
            .iter()
            .any(|p| p.validator == "early_bird")
    );
    // A fresh chain has no validator with 7 seated days: the pool is empty and Diversity fills
    // the whole selection, saying so.
    let fresh = fresh();
    assert_eq!(pool_size(&fresh, Mode::Reliability), 0);
    assert!(pool_size(&fresh, Mode::Diversity) >= 20);
    let selection = select(&fresh, &request(Mode::Reliability, "dev-holder")).unwrap();
    assert_eq!(selection.pool, 0);
    assert_eq!(selection.topped_up, 20);
    assert!(
        selection
            .entries
            .iter()
            .all(|p| p.source == PickSource::TopUp
                && p.reasons[0]
                    == Reason::TopUp {
                        mode: Mode::Reliability,
                        mode_picks: 0
                    })
    );
    assert_eq!(
        selection.top_up_notice().unwrap(),
        "No validator meets the Reliability criteria, so all 20 picks come from Diversity"
    );
}

#[test]
fn rewards_and_newcomers_top_up_on_the_devnet() {
    let s = devnet();
    for mode in [Mode::MaximumRewards, Mode::SupportNewcomers] {
        assert_eq!(pool_size(&s, mode), 0, "{mode}");
        for count in [20u8, 40, 53] {
            let selection = select(
                &s,
                &SelectRequest {
                    count,
                    ..request(mode, "dev-holder")
                },
            )
            .unwrap();
            assert_eq!(selection.topped_up, u32::from(count));
            assert!(selection.top_up_notice().is_some());
            assert!(
                validate_vote(
                    &selection.vote(),
                    &VoteRules::SOLAR_COMPATIBLE,
                    Voter::Ordinary
                )
                .is_empty()
            );
        }
        let all = SelectRequest {
            count: 53,
            ..request(mode, "dev-holder")
        };
        let selection = select(&s, &all).unwrap();
        assert_eq!(selection.entries.len(), 53);
        assert_eq!(
            selection
                .entries
                .iter()
                .filter(|p| p.basis_points == 189)
                .count(),
            36
        );
    }
}

#[test]
fn devnet_names_and_accounts() {
    let s = devnet();
    let selection = select(&s, &request(Mode::Diversity, "dev-holder")).unwrap();
    // Solar-compatible names like genesis_1 are not IceRoot names: the IceRoot rules refuse
    // them, the devnet's rules accept them.
    let problems = validate_vote(&selection.vote(), &VoteRules::ICEROOT, Voter::Ordinary);
    assert!(
        problems
            .iter()
            .all(|p| matches!(p, Problem::InvalidName { .. }))
    );
    assert!(
        validate_vote(
            &selection.vote(),
            &VoteRules::SOLAR_COMPATIBLE,
            Voter::Ordinary
        )
        .is_empty()
    );
    // So a selection asked for under IceRoot's rules on the devnet is refused, never signed.
    let refused = select(&s, &SelectRequest::new(Mode::Diversity, "dev-holder")).unwrap_err();
    assert!(matches!(
        &refused,
        SelectError::BreaksRules { problems }
            if !problems.is_empty()
                && problems.iter().all(|p| matches!(p, Problem::InvalidName { .. }))
    ));
    // A validator's account is refused; a permanently resigned one may vote.
    assert_eq!(
        select(&s, &request(Mode::Diversity, "dev-address-genesis_5")),
        Err(SelectError::ValidatorAccount)
    );
    assert_eq!(
        select(&s, &request(Mode::Diversity, "dev-address-genesis_17")),
        Err(SelectError::ValidatorAccount)
    );
    assert!(select(&s, &request(Mode::Diversity, "dev-address-genesis_42")).is_ok());
}
