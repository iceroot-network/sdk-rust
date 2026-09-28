//! Every selection is a valid vote, over 10,000 random snapshots and vote rules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{BTreeMap, BTreeSet};

use iceroot_vote::{
    DIVERSITY_RANKS_BELOW_CUTOFF, Declarations, Dimension, MAX_PICKS_PER_OPERATOR, MIN_PICKS, Mode,
    NEAR_CUTOFF_SEATS, NEWCOMER_RANKS_BELOW_CUTOFF, NameRule, Payouts, Penalties, PickSource,
    Problem, Production, Reason, SelectError, SelectRequest, Selection, Shortfall, SnapshotSource,
    ValidatorRecord, ValidatorStatus, VoteRules, VoteSnapshot, Voter, canonical_order, check,
    evaluate, seed, select, validate_vote, vote_bytes,
};
use proptest::prelude::*;

/// Operators, with two spellings of one and an empty one; enough of them that the operator cap
/// of Maximum Rewards and Support Newcomers leaves most snapshots enough validators.
const OPERATORS: [&str; 14] = [
    "Northwind",
    "northwind ",
    "Ridge",
    "Cove",
    "",
    "Delta",
    "Aurora",
    "Basalt",
    "Cinder",
    "Drift",
    "Ember",
    "Fjord",
    "Glacier",
    "Harbor",
];
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
        // Up to the largest count a snapshot accepts, 2^53 - 1.
        1 => (0u64..1 << 53, 0u64..1 << 53).prop_map(|(a, b)| Some(Production {
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
    /// A record ranked mostly within 12 ranks below the seats and sometimes further down, so
    /// that the bounded pools of Diversity and Support Newcomers are often but not always large
    /// enough.
    fn record(height: u64, seats: u32)(
        rank in prop::option::weighted(
            0.95,
            prop_oneof![15 => 1u32..=seats + 12, 4 => 1u32..=seats + 40, 1 => any::<u32>()],
        ),
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
        prop::collection::btree_set("[a-z][a-z0-9_.]{0,19}", 30..150),
    )
        .prop_flat_map(|(height, seats, block_time, relay, names)| {
            let n = names.len();
            (
                Just((height, seats, block_time, relay, names)),
                prop::collection::vec(record(height, seats), n),
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

/// Vote rules for a selection: IceRoot's limits, the Solar-compatible stage's, or IceRoot's with
/// a tighter size limit, under which long names leave fewer picks or none. Sometimes rules the
/// selection may break: IceRoot's own names, which most generated names are not, or a largest
/// share that the requested number of picks may exceed.
fn rules() -> impl Strategy<Value = VoteRules> {
    prop_oneof![
        4 => Just(RULES),
        4 => Just(VoteRules::SOLAR_COMPATIBLE),
        2 => (200u16..=1_280).prop_map(|max_bytes| VoteRules { max_bytes, ..RULES }),
        1 => Just(VoteRules::ICEROOT),
        1 => (150u16..=600).prop_map(|max_entry_basis_points| VoteRules {
            max_entry_basis_points,
            ..RULES
        }),
    ]
}

/// The rules with any name and any share accepted, and the same limits on entries and bytes.
fn relaxed(rules: VoteRules) -> VoteRules {
    VoteRules {
        names: NameRule::SolarCompatible,
        max_entry_basis_points: 10_000,
        ..rules
    }
}

/// The whole draw of a request, with no limit on entries or bytes and any name and share
/// accepted.
fn unlimited(snapshot: &VoteSnapshot, request: &SelectRequest<'_>) -> Selection {
    let rules = VoteRules {
        max_entries: u8::MAX,
        max_bytes: u16::MAX,
        ..relaxed(request.rules)
    };
    select(snapshot, &SelectRequest { rules, ..*request }).unwrap()
}

/// A selection's names in draw order.
fn draw_order(selection: &Selection) -> Vec<iceroot_vote::VoteEntry> {
    let mut picks: Vec<_> = selection.entries.iter().collect();
    picks.sort_by_key(|p| p.step);
    picks
        .into_iter()
        .map(|p| iceroot_vote::VoteEntry {
            validator: p.validator.clone(),
            basis_points: p.basis_points,
        })
        .collect()
}

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
    let count = selection.entries.len();
    assert!(count <= usize::from(request.count));
    assert!(count >= usize::from(MIN_PICKS));
    assert_eq!(selection.requested, request.count);
    assert_eq!(selection.rules, request.rules);
    assert_eq!(selection.mode, request.mode);
    assert_eq!(selection.account, request.account);
    assert_eq!(selection.draw, request.draw);
    assert_eq!(selection.snapshot_height, snapshot.height);
    assert_eq!(selection.snapshot_source, snapshot.source);
    assert_eq!(
        selection.seed,
        seed(
            request.account,
            request.mode,
            snapshot.election_height(),
            request.draw
        )
    );

    // The longest start of the whole draw that fits the rules, and the same selection as one
    // requested with that many picks.
    let whole = draw_order(&unlimited(snapshot, request));
    let kept = draw_order(selection);
    let names = |entries: &[iceroot_vote::VoteEntry]| -> Vec<String> {
        entries.iter().map(|e| e.validator.clone()).collect()
    };
    assert_eq!(names(&kept), names(&whole[..count]));
    if count < usize::from(request.count) {
        assert!(selection.size_notice().is_some());
        let longer = &whole[..=count];
        assert!(
            longer.len() > usize::from(request.rules.max_entries)
                || vote_bytes(longer) > usize::from(request.rules.max_bytes)
        );
        let fewer = SelectRequest {
            count: u8::try_from(count).unwrap(),
            ..*request
        };
        let same = Selection {
            requested: request.count,
            ..select(snapshot, &fewer).unwrap()
        };
        assert_eq!(&same, selection);
    } else {
        assert!(selection.size_notice().is_none());
    }

    // A valid vote: 20 to 53 entries, at most 500 basis points each, exactly 10,000, names the
    // rules accept, no duplicates, within the size limit, from an ordinary account.
    let vote = selection.vote();
    assert_eq!(validate_vote(&vote, &RULES, Voter::Ordinary), vec![]);
    assert_eq!(
        validate_vote(&vote, &request.rules, Voter::Ordinary),
        vec![]
    );
    assert!(vote_bytes(&vote) <= usize::from(request.rules.max_bytes));
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
    let n = u16::try_from(count).unwrap();
    let share = 10_000 / n;
    let extra = u32::from(10_000 % n);
    let mut steps: Vec<u32> = selection.entries.iter().map(|p| p.step).collect();
    steps.sort_unstable();
    assert_eq!(steps, (1..=u32::from(n)).collect::<Vec<_>>());
    for pick in &selection.entries {
        let expected = if pick.step <= extra { share + 1 } else { share };
        assert_eq!(pick.basis_points, expected);
        assert!(!pick.reasons.is_empty());
        assert_diversity_bound(&pick.reasons);
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
        Mode::MaximumRewards | Mode::SupportNewcomers => {
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
            // Top-up picks never take a declared operator past the cap either.
            let mut per_declared: BTreeMap<String, u32> = BTreeMap::new();
            for pick in from_mode.iter().chain(&top_ups) {
                if let Some(operator) = operator_key(snapshot, &pick.validator) {
                    *per_declared.entry(operator).or_insert(0) += 1;
                }
            }
            assert!(
                per_declared.values().all(|&n| n <= MAX_PICKS_PER_OPERATOR),
                "{per_declared:?}"
            );
            // A validator of the mode's pool comes as a top-up only when it declares no operator
            // and the mode's picks already gave that group its two.
            for pick in &top_ups {
                if mode_pool.contains(&pick.validator) {
                    assert_eq!(operator_key(snapshot, &pick.validator), None);
                    assert_eq!(per_operator.get(&None), Some(&MAX_PICKS_PER_OPERATOR));
                }
            }
        }
        Mode::Reliability => {
            if !top_ups.is_empty() {
                assert_eq!(from_mode.len(), mode_pool.len());
            }
            for pick in &top_ups {
                assert!(!mode_pool.contains(&pick.validator));
            }
        }
    }

    // The name rule and the largest share only check the result: under relaxed rules the same
    // selection comes out.
    let rules = relaxed(request.rules);
    let same = select(snapshot, &SelectRequest { rules, ..*request }).unwrap();
    assert_eq!(
        &Selection {
            rules: request.rules,
            ..same
        },
        selection
    );

    // Reproducible, and still meeting every criterion on the same data.
    assert_eq!(select(snapshot, request).as_ref(), Ok(selection));
    let findings = check(selection, snapshot).unwrap();
    assert!(findings.iter().all(|f| f.still_meets));
}

/// A Diversity pick weighs from `⌊2^64 / (1 + r)⌋`, with `r` the earlier picks in its rank band,
/// to twice that, whatever it declares.
fn assert_diversity_bound(reasons: &[Reason]) {
    let Some(Reason::Drawn {
        pool: Mode::Diversity,
        weight,
        ..
    }) = reasons.last()
    else {
        return;
    };
    let band = reasons
        .iter()
        .find_map(|r| match r {
            Reason::Group {
                dimension: Dimension::RankBand,
                earlier_picks,
                ..
            } => Some(*earlier_picks),
            _ => None,
        })
        .unwrap();
    let base = (1u128 << 64) / (1 + u128::from(band));
    assert!(
        (base..=2 * base).contains(weight),
        "{weight} against {base}"
    );
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
        rules in rules(),
    ) {
        let account = match voter_index {
            Some(index) => snapshot.records[index.index(snapshot.records.len())].address.clone(),
            None => format!("holder-{holder}"),
        };
        // A candidate is eligible exactly when it has no shortfall, and then has weight.
        for mode in Mode::ALL {
            for candidate in evaluate(&snapshot, mode).unwrap() {
                prop_assert_eq!(candidate.eligible, candidate.shortfalls.is_empty());
                prop_assert_eq!(candidate.eligible, candidate.weight > 0);
            }
        }
        // The pools are bounded by rank: Diversity to the seats and the next 10 ranks, Support
        // Newcomers to the last 10 seats and the next 20 ranks. A validator ranked further down
        // says so, and one without a rank too unless it resigned.
        let seats = u64::from(snapshot.seats);
        for (mode, below) in [
            (Mode::Diversity, DIVERSITY_RANKS_BELOW_CUTOFF),
            (Mode::SupportNewcomers, NEWCOMER_RANKS_BELOW_CUTOFF),
        ] {
            let below = u64::from(below);
            for candidate in evaluate(&snapshot, mode).unwrap() {
                let record = snapshot.record(&candidate.validator).unwrap();
                let rank = record.rank.map(u64::from);
                let far = rank.is_some_and(|r| r > seats + below);
                prop_assert_eq!(
                    candidate
                        .shortfalls
                        .iter()
                        .any(|s| matches!(s, Shortfall::FarBelowCutoff { .. })),
                    far
                );
                prop_assert_eq!(
                    candidate.shortfalls.contains(&Shortfall::NoRank),
                    rank.is_none() && !record.status.is_resigned()
                );
                if candidate.eligible {
                    let rank = rank.unwrap();
                    prop_assert!(rank <= seats + below);
                    if mode == Mode::SupportNewcomers {
                        prop_assert!(rank > seats.saturating_sub(u64::from(NEAR_CUTOFF_SEATS)));
                    }
                }
            }
        }
        for (mode, count) in Mode::ALL.into_iter().zip(counts) {
            let request = SelectRequest { mode, account: &account, count, draw, rules };
            match select(&snapshot, &request) {
                Ok(selection) => assert_valid(&snapshot, &request, &selection),
                Err(SelectError::ValidatorAccount) => {
                    prop_assert_eq!(snapshot.voter(&account), Voter::Validator);
                }
                Err(SelectError::NotEnoughValidators { requested, available }) => {
                    prop_assert_eq!(requested, count);
                    prop_assert!(available < u32::from(count));
                    let union: BTreeSet<String> = eligible(&snapshot, mode)
                        .union(&eligible(&snapshot, Mode::Diversity))
                        .cloned()
                        .collect();
                    if matches!(mode, Mode::MaximumRewards | Mode::SupportNewcomers) {
                        // The operator cap can hold some back.
                        prop_assert!(available <= u32::try_from(union.len()).unwrap());
                    } else {
                        prop_assert_eq!(available, u32::try_from(union.len()).unwrap());
                    }
                }
                Err(SelectError::DoesNotFit { fits, minimum, max_entries, max_bytes }) => {
                    // Even the fewest picks of the whole draw do not fit.
                    prop_assert_eq!(minimum, MIN_PICKS);
                    prop_assert_eq!((max_entries, max_bytes), (rules.max_entries, rules.max_bytes));
                    prop_assert!(fits < u32::from(minimum));
                    let whole = draw_order(&unlimited(&snapshot, &request));
                    let fewest = &whole[..usize::from(minimum)];
                    prop_assert!(vote_bytes(fewest) > usize::from(max_bytes));
                    let fitting = &whole[..usize::try_from(fits).unwrap()];
                    prop_assert!(vote_bytes(fitting) <= usize::from(max_bytes));
                    let one_more = &whole[..=usize::try_from(fits).unwrap()];
                    prop_assert!(vote_bytes(one_more) > usize::from(max_bytes));
                }
                Err(SelectError::BreaksRules { problems }) => {
                    // Exactly what the rules find wrong with the selection the relaxed rules
                    // give: names they refuse and shares above their largest, nothing else.
                    let relaxed = select(
                        &snapshot,
                        &SelectRequest { rules: relaxed(rules), ..request },
                    );
                    let Ok(relaxed) = relaxed else {
                        return Err(TestCaseError::fail(format!("relaxed: {relaxed:?}")));
                    };
                    prop_assert!(!problems.is_empty());
                    prop_assert_eq!(
                        &problems,
                        &validate_vote(&relaxed.vote(), &rules, Voter::Ordinary)
                    );
                    let names_or_shares = problems.iter().all(|p| {
                        matches!(p, Problem::InvalidName { .. } | Problem::ShareTooLarge { .. })
                    });
                    prop_assert!(names_or_shares);
                }
                Err(other) => prop_assert!(false, "unexpected {other:?}"),
            }
        }
    }
}
