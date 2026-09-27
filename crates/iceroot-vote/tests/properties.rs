//! Every selection is a valid vote, over 10,000 random snapshots.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{BTreeMap, BTreeSet};

use iceroot_vote::{
    Declarations, MAX_PICKS_PER_OPERATOR, Mode, NameRule, Payouts, Penalties, PickSource,
    Production, SelectError, SelectRequest, Selection, SnapshotSource, ValidatorRecord,
    ValidatorStatus, VoteRules, VoteSnapshot, Voter, canonical_order, check, evaluate, seed,
    select, validate_vote,
};
use proptest::prelude::*;

const OPERATORS: [&str; 6] = ["Northwind", "northwind ", "Ridge", "Cove", "", "Delta"];
const HOSTS: [&str; 5] = ["Hostco", "Cloudnine", "Metalbox", "hostco", "Orbit"];
const COUNTRIES: [&str; 7] = ["DE", "US", "fi", "SG", "ZZ", "BR", "KE"];

fn status() -> impl Strategy<Value = ValidatorStatus> {
    prop_oneof![
        6 => Just(ValidatorStatus::Active),
        3 => Just(ValidatorStatus::Standby),
        1 => Just(ValidatorStatus::ResignedTemporary),
        1 => Just(ValidatorStatus::ResignedPermanent),
    ]
}

fn production() -> impl Strategy<Value = Option<Production>> {
    prop_oneof![
        1 => Just(None),
        6 => (0u64..20_000, 0u64..=100).prop_map(|(assigned, missed_percent)| {
            // Mostly healthy: up to 4 % missed in nine cases out of ten.
            let missed = assigned * missed_percent.min(if missed_percent < 90 { 4 } else { 100 }) / 100;
            Some(Production {
                forged: assigned - missed,
                assigned,
            })
        }),
        1 => (any::<u64>(), any::<u64>()).prop_map(|(a, b)| Some(Production {
            forged: a.min(b),
            assigned: a.max(b),
        })),
    ]
}

fn penalties() -> impl Strategy<Value = Option<Penalties>> {
    prop_oneof![
        1 => Just(None),
        4 => (
            prop::bool::weighted(0.05),
            prop::bool::weighted(0.03),
            prop::bool::weighted(0.1),
        )
            .prop_map(|(jailed, equivocation, ever)| Some(Penalties {
                jailed_in_window: jailed,
                equivocation_in_window: equivocation,
                ever: ever || jailed || equivocation,
            })),
    ]
}

fn declarations() -> impl Strategy<Value = Option<Declarations>> {
    let pick = |list: &'static [&'static str]| {
        prop::option::weighted(0.8, prop::sample::select(list)).prop_map(|v| v.map(str::to_owned))
    };
    prop::option::weighted(
        0.8,
        (
            pick(&OPERATORS),
            pick(&HOSTS),
            pick(&COUNTRIES),
            prop::bool::weighted(0.8),
        )
            .prop_map(|(operator, hosting, country, complete)| Declarations {
                operator,
                hosting,
                country,
                complete,
            }),
    )
}

fn payouts() -> impl Strategy<Value = Option<Payouts>> {
    prop_oneof![
        1 => Just(None),
        3 => (0u128..10_000, 0u32..40).prop_map(|(per_unit_weight, intervals)| Some(Payouts {
            per_unit_weight,
            intervals,
        })),
        1 => (any::<u128>(), 1u32..40).prop_map(|(per_unit_weight, intervals)| Some(Payouts {
            per_unit_weight,
            intervals,
        })),
    ]
}

prop_compose! {
    fn record(height: u64)(
        rank in prop::option::weighted(0.95, 1u32..140),
        status in status(),
        seated_roll in prop::bool::weighted(0.8),
        registered in prop::option::weighted(0.95, 0..=height),
        seated_days in prop::option::weighted(0.9, 0u32..=30),
        vote_weight in any::<u128>(),
        voters in 0u32..500,
        production in production(),
        penalties in penalties(),
        declarations in declarations(),
        payouts in payouts(),
        self_funded in prop::option::of(0u16..=10_000),
    ) -> ValidatorRecord {
        ValidatorRecord {
            name: String::new(),
            address: String::new(),
            rank,
            seated: !status.is_resigned() && seated_roll,
            status,
            registered_height: registered,
            seated_days_in_window: seated_days,
            vote_weight,
            voters,
            production,
            penalties,
            declarations,
            payouts,
            self_funded_weight_bp: self_funded,
        }
    }
}

fn snapshot() -> impl Strategy<Value = VoteSnapshot> {
    (
        0u64..20_000_000,
        1u32..=60,
        1u32..=30,
        prop::bool::ANY,
        prop::collection::btree_set("[a-z][a-z0-9_.]{0,11}", 30..150),
    )
        .prop_flat_map(|(height, seats, block_time, relay, names)| {
            let n = names.len();
            (
                Just((height, seats, block_time, relay, names)),
                prop::collection::vec(record(height), n),
            )
        })
        .prop_map(|((height, seats, block_time, relay, names), mut records)| {
            for (record, name) in records.iter_mut().zip(names) {
                record.address = format!("addr-{name}");
                record.name = name;
            }
            VoteSnapshot {
                height,
                window_days: 30,
                seats,
                block_time_seconds: block_time,
                source: if relay {
                    SnapshotSource::RelayApproximate
                } else {
                    SnapshotSource::Indexer
                },
                records,
            }
        })
}

/// IceRoot's limits with the names the snapshot uses (Solar-compatible names include IceRoot's).
const RULES: VoteRules = VoteRules {
    names: NameRule::SolarCompatible,
    ..VoteRules::ICEROOT
};

fn eligible(snapshot: &VoteSnapshot, mode: Mode) -> BTreeSet<String> {
    evaluate(snapshot, mode)
        .unwrap()
        .into_iter()
        .filter(|c| c.eligible)
        .map(|c| c.validator)
        .collect()
}

fn operator_key(snapshot: &VoteSnapshot, name: &str) -> Option<String> {
    snapshot
        .record(name)?
        .declarations
        .as_ref()?
        .operator
        .as_ref()
        .map(|o| o.trim().to_ascii_lowercase())
        .filter(|o| !o.is_empty())
}

fn assert_valid(snapshot: &VoteSnapshot, request: &SelectRequest<'_>, selection: &Selection) {
    let count = usize::from(request.count);
    assert_eq!(selection.entries.len(), count);
    assert_eq!(selection.mode, request.mode);
    assert_eq!(selection.account, request.account);
    assert_eq!(selection.draw, request.draw);
    assert_eq!(selection.snapshot_height, snapshot.height);
    assert_eq!(selection.snapshot_source, snapshot.source);
    assert_eq!(
        selection.seed,
        seed(request.account, request.mode, snapshot.height, request.draw)
    );

    // A valid vote: 20 to 53 entries, at most 500 basis points each, exactly 10,000, names the
    // rules accept, no duplicates, within the size limit, from an ordinary account.
    let vote = selection.vote();
    assert_eq!(validate_vote(&vote, &RULES, Voter::Ordinary), vec![]);
    assert_eq!(snapshot.voter(request.account), Voter::Ordinary);
    let total: u32 = vote.iter().map(|e| u32::from(e.basis_points)).sum();
    assert_eq!(total, 10_000);
    assert!(vote.iter().all(|e| e.basis_points <= 500));
    // In the canonical order, strictly (names are unique).
    assert!(selection.entries.windows(2).all(|w| {
        canonical_order(
            &iceroot_vote::VoteEntry {
                validator: w[0].validator.clone(),
                basis_points: w[0].basis_points,
            },
            &iceroot_vote::VoteEntry {
                validator: w[1].validator.clone(),
                basis_points: w[1].basis_points,
            },
        )
        .is_lt()
    }));
    // Even shares, the extra basis points to the first picks drawn.
    let share = 10_000 / u16::from(request.count);
    let extra = 10_000 % u32::from(request.count);
    let mut steps: Vec<u32> = selection.entries.iter().map(|p| p.step).collect();
    steps.sort_unstable();
    assert_eq!(steps, (1..=u32::from(request.count)).collect::<Vec<_>>());
    for pick in &selection.entries {
        let expected = if pick.step <= extra { share + 1 } else { share };
        assert_eq!(pick.basis_points, expected);
        assert!(!pick.reasons.is_empty());
    }

    // Mode picks meet the mode's criteria, top-up picks Diversity's.
    let mode_pool = eligible(snapshot, request.mode);
    let diverse = eligible(snapshot, Mode::Diversity);
    assert_eq!(selection.pool, u32::try_from(mode_pool.len()).unwrap());
    let from_mode: Vec<_> = selection
        .entries
        .iter()
        .filter(|p| p.source == PickSource::Mode)
        .collect();
    let top_ups: Vec<_> = selection
        .entries
        .iter()
        .filter(|p| p.source == PickSource::TopUp)
        .collect();
    assert_eq!(from_mode.len() + top_ups.len(), count);
    assert_eq!(selection.topped_up, u32::try_from(top_ups.len()).unwrap());
    for pick in &from_mode {
        assert!(mode_pool.contains(&pick.validator));
    }
    for pick in &top_ups {
        assert!(diverse.contains(&pick.validator));
    }
    // Top-ups come after every mode pick, and only when the mode ran out.
    let last_mode_step = from_mode.iter().map(|p| p.step).max().unwrap_or(0);
    assert!(top_ups.iter().all(|p| p.step > last_mode_step));
    match request.mode {
        Mode::Diversity => assert!(top_ups.is_empty()),
        Mode::MaximumRewards => {
            let mut per_operator: BTreeMap<Option<String>, u32> = BTreeMap::new();
            for pick in &from_mode {
                *per_operator
                    .entry(operator_key(snapshot, &pick.validator))
                    .or_insert(0) += 1;
            }
            assert!(per_operator.values().all(|&n| n <= MAX_PICKS_PER_OPERATOR));
            if !top_ups.is_empty() {
                // Every validator of the pool was picked or its operator was full.
                for name in &mode_pool {
                    let picked = from_mode.iter().any(|p| &p.validator == name);
                    let full = per_operator
                        .get(&operator_key(snapshot, name))
                        .is_some_and(|&n| n == MAX_PICKS_PER_OPERATOR);
                    assert!(picked || full, "{name}");
                }
            }
        }
        _ => {
            if !top_ups.is_empty() {
                assert_eq!(from_mode.len(), mode_pool.len());
            }
            for pick in &top_ups {
                assert!(!mode_pool.contains(&pick.validator));
            }
        }
    }

    // Reproducible, and still meeting every criterion on the same data.
    assert_eq!(select(snapshot, request).as_ref(), Ok(selection));
    let findings = check(selection, snapshot).unwrap();
    assert!(findings.iter().all(|f| f.still_meets));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_selection_is_a_valid_vote(
        snapshot in snapshot(),
        counts in prop::array::uniform4(20u8..=53),
        draw in any::<u32>(),
        voter_index in prop::option::weighted(0.05, any::<prop::sample::Index>()),
        holder in any::<u32>(),
    ) {
        let account = match voter_index {
            Some(index) => snapshot.records[index.index(snapshot.records.len())].address.clone(),
            None => format!("holder-{holder}"),
        };
        for (mode, count) in Mode::ALL.into_iter().zip(counts) {
            let request = SelectRequest { mode, account: &account, count, draw };
            match select(&snapshot, &request) {
                Ok(selection) => assert_valid(&snapshot, &request, &selection),
                Err(SelectError::ValidatorAccount) => {
                    prop_assert_eq!(snapshot.voter(&account), Voter::Validator);
                }
                Err(SelectError::NotEnoughValidators { requested, available }) => {
                    prop_assert_eq!(requested, count);
                    prop_assert!(available < u32::from(count));
                    if mode != Mode::MaximumRewards {
                        let union: BTreeSet<String> = eligible(&snapshot, mode)
                            .union(&eligible(&snapshot, Mode::Diversity))
                            .cloned()
                            .collect();
                        prop_assert_eq!(available, u32::try_from(union.len()).unwrap());
                    }
                }
                Err(other) => prop_assert!(false, "unexpected {other:?}"),
            }
        }
    }
}
