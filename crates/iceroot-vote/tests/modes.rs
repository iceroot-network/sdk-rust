//! Each mode scored as specified on the synthetic snapshot of 80 validators.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use iceroot_vote::{
    Candidate, Mode, PickSource, Reason, SelectError, SelectRequest, Selection, Shortfall,
    ValidatorStatus, VoteRules, VoteSnapshot, Voter, evaluate, select, validate_vote,
};

use common::{load_json, synthetic};

fn candidates(snapshot: &VoteSnapshot, mode: Mode) -> BTreeMap<String, Candidate> {
    evaluate(snapshot, mode)
        .unwrap()
        .into_iter()
        .map(|c| (c.validator.clone(), c))
        .collect()
}

fn pool(snapshot: &VoteSnapshot, mode: Mode) -> BTreeSet<String> {
    candidates(snapshot, mode)
        .into_values()
        .filter(|c| c.eligible)
        .map(|c| c.validator)
        .collect()
}

fn shortfalls(snapshot: &VoteSnapshot, mode: Mode, name: &str) -> Vec<Shortfall> {
    candidates(snapshot, mode)[name].shortfalls.clone()
}

fn account(i: usize) -> String {
    format!("addr-holder-{i}")
}

/// Selections for many accounts.
fn many(snapshot: &VoteSnapshot, mode: Mode, count: u8, accounts: usize) -> Vec<Selection> {
    (0..accounts)
        .map(|i| {
            let account = account(i);
            let mut request = SelectRequest::new(mode, &account);
            request.count = count;
            select(snapshot, &request).unwrap()
        })
        .collect()
}

/// How often each validator is picked.
fn frequency(selections: &[Selection]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for selection in selections {
        for pick in &selection.entries {
            *counts.entry(pick.validator.clone()).or_insert(0) += 1;
        }
    }
    counts
}

#[test]
fn pools_and_weights_match_the_criteria() {
    let snapshot = synthetic();
    assert_eq!(snapshot.records.len(), 80);
    let expected = load_json("synthetic-80.expected.json");
    for mode in Mode::ALL {
        let want: BTreeSet<String> = expected["pools"][mode.id()]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(pool(&snapshot, mode), want, "{mode}");
        let judged = candidates(&snapshot, mode);
        for candidate in judged.values() {
            assert_eq!(candidate.eligible, candidate.shortfalls.is_empty());
            assert_eq!(candidate.eligible, candidate.weight > 0);
        }
        if mode == Mode::Diversity {
            assert!(
                judged
                    .values()
                    .filter(|c| c.eligible)
                    .all(|c| c.weight == 1 << 64)
            );
            continue;
        }
        for (name, weight) in expected["weights"][mode.id()].as_object().unwrap() {
            let weight: u128 = weight.as_str().unwrap().parse().unwrap();
            assert_eq!(judged[name].weight, weight, "{mode} {name}");
        }
    }
    assert_eq!(pool(&snapshot, Mode::Diversity).len(), 71);
    assert_eq!(pool(&snapshot, Mode::Reliability).len(), 48);
    assert_eq!(pool(&snapshot, Mode::MaximumRewards).len(), 46);
    assert_eq!(pool(&snapshot, Mode::SupportNewcomers).len(), 26);
}

#[test]
fn diversity_criteria() {
    let s = synthetic();
    let m = Mode::Diversity;
    // Resigned validators, for now or for good.
    for name in ["lemon", "palm", "tamarind", "olive"] {
        assert!(matches!(
            shortfalls(&s, m, name)[..],
            [Shortfall::Resigned { .. }]
        ));
    }
    // 94.00 %, exactly 95 %, one slot below 95 %.
    assert!(matches!(
        shortfalls(&s, m, "mesquite")[..],
        [Shortfall::LowProduction {
            forged: 5_734,
            assigned: 6_100,
            minimum_bp: 9_500
        }]
    ));
    assert!(shortfalls(&s, m, "mangrove").is_empty());
    assert!(matches!(
        shortfalls(&s, m, "ebony")[..],
        [Shortfall::LowProduction { .. }]
    ));
    // Jailed, equivocated; a penalty before the window does not count.
    assert_eq!(
        shortfalls(&s, m, "spruce"),
        vec![Shortfall::PenalizedInWindow {
            jailed: true,
            equivocation: false
        }]
    );
    assert_eq!(
        shortfalls(&s, m, "catalpa"),
        vec![Shortfall::PenalizedInWindow {
            jailed: false,
            equivocation: true
        }]
    );
    assert!(shortfalls(&s, m, "cherry").is_empty());
    // A standby validator with no production record is healthy; one with a poor earlier record
    // is not.
    let hazel = &candidates(&s, m)["hazel"];
    assert!(hazel.eligible);
    assert!(hazel.reasons.contains(&Reason::NoProductionRecord));
    assert!(matches!(
        shortfalls(&s, m, "balsa")[..],
        [Shortfall::LowProduction { .. }]
    ));
    // Undeclared validators are eligible and form one group.
    assert!(shortfalls(&s, m, "quince").is_empty());
}

#[test]
fn diversity_spreads_the_vote() {
    let s = synthetic();
    let selections = many(&s, Mode::Diversity, 20, 400);
    let eligible: Vec<String> = pool(&s, Mode::Diversity).into_iter().collect();
    // A uniform draw from the same pool, as a baseline.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut uniform = Vec::new();
    for _ in 0..400 {
        let mut left = eligible.clone();
        let mut picks = Vec::new();
        for _ in 0..20 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let index =
                usize::try_from((state >> 33) % u64::try_from(left.len()).unwrap()).unwrap();
            picks.push(left.remove(index));
        }
        uniform.push(picks);
    }
    let key = |name: &str, dimension: usize| -> String {
        let record = s.record(name).unwrap();
        let d = record.declarations.as_ref();
        match dimension {
            0 => d
                .and_then(|d| d.operator.clone())
                .map(|o| o.trim().to_ascii_lowercase())
                .unwrap_or_default(),
            1 => d.and_then(|d| d.hosting.clone()).unwrap_or_default(),
            2 => d
                .and_then(|d| d.country.clone())
                .and_then(|c| iceroot_vote::Region::of_country(&c))
                .map(|r| r.name().to_owned())
                .unwrap_or_default(),
            _ => record
                .rank
                .map(|r| ((r - 1) / 10).to_string())
                .unwrap_or_default(),
        }
    };
    // The largest group in a selection, averaged over selections, per dimension.
    let largest = |names: &[&str], dimension: usize| -> usize {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for name in names {
            *counts.entry(key(name, dimension)).or_insert(0) += 1;
        }
        counts.into_values().max().unwrap()
    };
    for dimension in 1..4 {
        let diverse: usize = selections
            .iter()
            .map(|sel| {
                let names: Vec<&str> = sel.entries.iter().map(|p| p.validator.as_str()).collect();
                largest(&names, dimension)
            })
            .sum();
        let baseline: usize = uniform
            .iter()
            .map(|picks| {
                let names: Vec<&str> = picks.iter().map(String::as_str).collect();
                largest(&names, dimension)
            })
            .sum();
        assert!(
            diverse * 10 < baseline * 9,
            "dimension {dimension}: diverse {diverse}, uniform {baseline}"
        );
    }
    // Frostline has five eligible validators; Diversity takes more than two of them far less
    // often than a uniform draw does.
    let heavy = |picks: &[Vec<&str>]| {
        picks
            .iter()
            .filter(|names| names.iter().filter(|n| key(n, 0) == "frostline").count() > 2)
            .count()
    };
    let diverse_names: Vec<Vec<&str>> = selections
        .iter()
        .map(|sel| sel.entries.iter().map(|p| p.validator.as_str()).collect())
        .collect();
    let uniform_names: Vec<Vec<&str>> = uniform
        .iter()
        .map(|picks| picks.iter().map(String::as_str).collect())
        .collect();
    let (diverse_heavy, uniform_heavy) = (heavy(&diverse_names), heavy(&uniform_names));
    assert!(
        diverse_heavy * 2 < uniform_heavy,
        "diverse {diverse_heavy}, uniform {uniform_heavy}"
    );
    // Every pick explains its groups and its draw.
    for pick in &selections[0].entries {
        let groups = pick
            .reasons
            .iter()
            .filter(|r| matches!(r, Reason::Group { .. }))
            .count();
        assert_eq!(groups, 4);
        assert!(matches!(pick.reasons.last(), Some(Reason::Drawn { .. })));
    }
}

#[test]
fn reliability_criteria_and_weights() {
    let s = synthetic();
    let m = Mode::Reliability;
    // 5 and 6 days seated are too few, 7 are enough.
    assert_eq!(
        shortfalls(&s, m, "fig"),
        vec![Shortfall::TooFewSeatedDays {
            days: Some(5),
            minimum: 7
        }]
    );
    assert!(shortfalls(&s, m, "almond").is_empty());
    assert!(matches!(
        shortfalls(&s, m, "apricot")[..],
        [Shortfall::TooFewSeatedDays { days: Some(6), .. }]
    ));
    // A standby validator with 12 seated days in the window and a good record counts.
    assert!(shortfalls(&s, m, "alder").is_empty());
    // Never seated: no seated days and no record.
    assert_eq!(
        shortfalls(&s, m, "hazel"),
        vec![
            Shortfall::TooFewSeatedDays {
                days: Some(0),
                minimum: 7
            },
            Shortfall::NoProductionRecord
        ]
    );
    assert!(shortfalls(&s, m, "mangrove").is_empty());
    assert!(!shortfalls(&s, m, "ebony").is_empty());
    assert!(!shortfalls(&s, m, "spruce").is_empty());
    // Missing 1 % of the slots halves the weight.
    let judged = candidates(&s, m);
    assert_eq!(judged["fig"].weight, 0);
    assert_eq!(
        judged["alder"].weight,
        1_000_000 * 2_400 / (2_400 + 100 * 24)
    );
    assert_eq!(judged["alder"].weight, 500_000);
    assert_eq!(
        judged["mangrove"].weight,
        1_000_000 * 6_000 / (6_000 + 100 * 300)
    );
    // The better record is drawn more often.
    let freq = frequency(&many(&s, m, 20, 600));
    let perfect: Vec<&String> = judged
        .values()
        .filter(|c| c.weight == 1_000_000)
        .map(|c| &c.validator)
        .collect();
    assert!(!perfect.is_empty());
    for name in perfect {
        assert!(
            freq.get(name).copied().unwrap_or(0) > freq.get("mangrove").copied().unwrap_or(0),
            "{name}"
        );
    }
}

#[test]
fn maximum_rewards_criteria_weights_and_cap() {
    let s = synthetic();
    let m = Mode::MaximumRewards;
    for name in ["maple", "willow", "chestnut"] {
        // Every name here is eligible or explained; the checks below name the cases.
        let _ = shortfalls(&s, m, name);
    }
    // Standby validators earn nothing to share, whatever they paid before.
    assert!(shortfalls(&s, m, "elm").contains(&Shortfall::NotSeated));
    assert!(shortfalls(&s, m, "hickory").contains(&Shortfall::NotSeated));
    // Measured payouts are required: none, no interval, or zero.
    let judged = candidates(&s, m);
    let unmeasured: Vec<&str> = judged
        .values()
        .filter(|c| c.shortfalls == vec![Shortfall::NoMeasuredPayouts])
        .map(|c| c.validator.as_str())
        .collect();
    assert_eq!(unmeasured.len(), 5, "{unmeasured:?}");
    // The best payer weighs 10,000 squared; half the best payout, a quarter of that.
    assert_eq!(judged["chestnut"].weight, 100_000_000);
    let best_reason = judged["chestnut"]
        .reasons
        .iter()
        .find_map(|r| match r {
            Reason::MeasuredPayouts { of_best_bp, .. } => Some(*of_best_bp),
            _ => None,
        })
        .unwrap();
    assert_eq!(best_reason, 10_000);
    assert_eq!(judged["dogwood"].weight, 6_000 * 6_000);
    // At most two picks per declared operator, in every selection; the undeclared group too.
    let selections = many(&s, m, 20, 600);
    for selection in &selections {
        let mut per_operator: BTreeMap<String, usize> = BTreeMap::new();
        for pick in &selection.entries {
            let operator = s
                .record(&pick.validator)
                .unwrap()
                .declarations
                .as_ref()
                .and_then(|d| d.operator.clone())
                .map(|o| o.trim().to_ascii_lowercase())
                .unwrap_or_default();
            *per_operator.entry(operator).or_insert(0) += 1;
            assert!(
                pick.reasons
                    .iter()
                    .any(|r| matches!(r, Reason::OperatorPicks { maximum: 2, .. }))
            );
        }
        assert!(per_operator.values().all(|&n| n <= 2), "{per_operator:?}");
    }
    // Frostline pays the most: its validators are drawn far more often than a low payer, and
    // the cap holds them to two per selection.
    let freq = frequency(&selections);
    let frostline: usize = ["chestnut", "persimmon", "aspen", "locust"]
        .iter()
        .map(|n| freq.get(*n).copied().unwrap_or(0))
        .sum();
    assert!(frostline >= 2 * 600 * 9 / 10, "{frostline}");
    assert!(frostline <= 2 * 600);
    // Among validators without a shared operator, the better payers are drawn more often: the
    // top quarter by payout at least one and a half times as often as the bottom quarter. With
    // 20 picks from about 40 candidates, every candidate is drawn often; the weights decide
    // which.
    let mut single: Vec<&Candidate> = judged
        .values()
        .filter(|c| c.eligible)
        .filter(|c| {
            let operator = s.record(&c.validator).unwrap().declarations.as_ref();
            operator.is_some_and(|d| d.operator.as_deref().is_some_and(|o| o.ends_with(" Nodes")))
        })
        .collect();
    single.sort_by_key(|c| c.weight);
    let quarter = single.len() / 4;
    let picked = |group: &[&Candidate]| -> usize {
        group
            .iter()
            .map(|c| freq.get(&c.validator).copied().unwrap_or(0))
            .sum()
    };
    let (bottom, top) = (
        picked(&single[..quarter]),
        picked(&single[single.len() - quarter..]),
    );
    assert!(2 * top > 3 * bottom, "top {top}, bottom {bottom}");
    // And a selection's mean payout comes close to the best 20 the cap allows.
    let payout = |name: &str| s.record(name).unwrap().payouts.unwrap().per_unit_weight;
    let operator = |name: &str| {
        s.record(name)
            .unwrap()
            .declarations
            .as_ref()
            .and_then(|d| d.operator.clone())
            .map(|o| o.trim().to_ascii_lowercase())
            .unwrap_or_default()
    };
    let mut by_payout: Vec<&Candidate> = judged.values().filter(|c| c.eligible).collect();
    by_payout.sort_by_key(|c| std::cmp::Reverse(payout(&c.validator)));
    let mut best: Vec<u128> = Vec::new();
    let mut taken: BTreeMap<String, usize> = BTreeMap::new();
    for c in by_payout {
        let n = taken.entry(operator(&c.validator)).or_insert(0);
        if *n < 2 && best.len() < 20 {
            *n += 1;
            best.push(payout(&c.validator));
        }
    }
    let best_mean = best.iter().sum::<u128>() / 20;
    let picks: Vec<u128> = selections
        .iter()
        .flat_map(|sel| sel.entries.iter().map(|p| payout(&p.validator)))
        .collect();
    let picks_mean = picks.iter().sum::<u128>() / u128::try_from(picks.len()).unwrap();
    assert!(
        picks_mean * 100 >= best_mean * 85,
        "picks {picks_mean}, best {best_mean}"
    );
}

#[test]
fn support_newcomers_criteria_and_weights() {
    let s = synthetic();
    let m = Mode::SupportNewcomers;
    let judged = candidates(&s, m);
    // Near the cutoff: the last ten seats and everything below; rank 43 is not.
    assert_eq!(
        shortfalls(&s, m, "kapok"),
        vec![Shortfall::NotNearCutoff {
            rank: 43,
            seats: 53
        }]
    );
    assert!(judged["acacia"].eligible); // rank 44
    assert!(judged["pear"].eligible); // rank 53, the last seat
    assert!(judged["papaya"].eligible); // rank 54, the first below
    // Registered 3 days, 7 days exactly, and one hour short of 7 days.
    assert_eq!(
        shortfalls(&s, m, "hazel"),
        vec![Shortfall::RegisteredTooRecently {
            days: Some(3),
            minimum: 7
        }]
    );
    assert!(judged["hemlock"].eligible);
    assert_eq!(
        shortfalls(&s, m, "eucalyptus"),
        vec![Shortfall::RegisteredTooRecently {
            days: Some(6),
            minimum: 7
        }]
    );
    // A penalty long ago still counts; incomplete or missing declarations exclude.
    assert_eq!(shortfalls(&s, m, "medlar"), vec![Shortfall::PenalizedEver]);
    assert_eq!(
        shortfalls(&s, m, "pecan"),
        vec![Shortfall::DeclarationsIncomplete]
    );
    assert_eq!(
        shortfalls(&s, m, "damson"),
        vec![Shortfall::DeclarationsIncomplete]
    );
    assert_eq!(
        shortfalls(&s, m, "poplar"),
        vec![Shortfall::DeclarationsIncomplete]
    );
    // Earlier seated history is judged: 99 % passes, 90 % does not.
    assert!(judged["alder"].eligible);
    assert!(
        judged["alder"]
            .reasons
            .iter()
            .any(|r| matches!(r, Reason::Production { .. }))
    );
    assert!(matches!(
        shortfalls(&s, m, "balsa")[..],
        [Shortfall::LowProduction { .. }]
    ));
    // A validator without a penalty record is not refused for it.
    assert!(judged["buckeye"].eligible);
    assert!(judged["buckeye"].reasons.contains(&Reason::NoPenaltyRecord));
    // Weight rises towards the cutoff from both sides.
    assert_eq!(judged["pear"].weight, 10_000);
    assert_eq!(judged["papaya"].weight, 10_000);
    assert_eq!(judged["acacia"].weight, 100_000 / 19);
    assert_eq!(judged["lime"].weight, 100_000 / 32);
    let freq = frequency(&many(&s, m, 20, 600));
    assert!(freq["papaya"] > freq["lime"]);
    assert!(freq["pear"] > freq["acacia"]);
}

#[test]
fn full_selections_on_the_synthetic_snapshot() {
    let s = synthetic();
    for mode in Mode::ALL {
        for count in [20u8, 21, 33, 53] {
            let mut request = SelectRequest::new(mode, "addr-holder-full");
            request.count = count;
            let selection = select(&s, &request).unwrap();
            assert_eq!(selection.entries.len(), usize::from(count));
            let vote = selection.vote();
            assert!(validate_vote(&vote, &VoteRules::ICEROOT, Voter::Ordinary).is_empty());
            assert_eq!(
                vote.iter().map(|e| u32::from(e.basis_points)).sum::<u32>(),
                10_000
            );
            if count == 20 {
                assert_eq!(selection.topped_up, 0, "{mode}");
                assert!(vote.iter().all(|e| e.basis_points == 500));
            }
        }
    }
}

#[test]
fn small_pools_top_up_from_diversity_and_say_so() {
    let s = synthetic();
    // Support Newcomers has 26 eligible validators.
    let mut request = SelectRequest::new(Mode::SupportNewcomers, "addr-holder-top-up");
    request.count = 30;
    let selection = select(&s, &request).unwrap();
    assert_eq!(selection.pool, 26);
    assert_eq!(selection.topped_up, 4);
    let top_ups: Vec<_> = selection
        .entries
        .iter()
        .filter(|p| p.source == PickSource::TopUp)
        .collect();
    assert_eq!(top_ups.len(), 4);
    let newcomers = pool(&s, Mode::SupportNewcomers);
    let diverse = pool(&s, Mode::Diversity);
    for pick in &selection.entries {
        match pick.source {
            PickSource::Mode => assert!(newcomers.contains(&pick.validator)),
            PickSource::TopUp => {
                assert!(diverse.contains(&pick.validator));
                assert!(!newcomers.contains(&pick.validator));
                assert_eq!(
                    pick.reasons[0],
                    Reason::TopUp {
                        mode: Mode::SupportNewcomers,
                        mode_picks: 26
                    }
                );
                assert!(pick.step > 26);
            }
            PickSource::Holder => unreachable!(),
        }
    }
    assert_eq!(
        selection.top_up_notice().unwrap(),
        "26 validators meet the Support Newcomers criteria, so 26 picks come from Support Newcomers and 4 from Diversity"
    );
    // Maximum Rewards: 46 eligible, but the operator cap leaves 42 picks.
    let mut request = SelectRequest::new(Mode::MaximumRewards, "addr-holder-top-up");
    request.count = 53;
    let selection = select(&s, &request).unwrap();
    assert_eq!(selection.pool, 46);
    assert_eq!(selection.topped_up, 11);
    assert!(
        selection
            .entries
            .iter()
            .all(|p| p.basis_points == 189 || p.basis_points == 188)
    );
    assert_eq!(
        selection.top_up_notice().unwrap(),
        "46 validators meet the Maximum Rewards criteria, at most 2 per operator, so 42 picks come from Maximum Rewards and 11 from Diversity"
    );
    // No top-up in Diversity itself, and none when the pool suffices.
    let selection = select(
        &s,
        &SelectRequest::new(Mode::Diversity, "addr-holder-top-up"),
    )
    .unwrap();
    assert_eq!(selection.topped_up, 0);
    assert!(selection.top_up_notice().is_none());
}

#[test]
fn refusals() {
    let s = synthetic();
    for count in [0u8, 19, 54, 255] {
        let mut request = SelectRequest::new(Mode::Diversity, "addr-holder");
        request.count = count;
        assert_eq!(select(&s, &request), Err(SelectError::Count { count }));
    }
    // A validator's account cannot vote, even resigned for now; resigned for good it can.
    for address in ["addr-chestnut", "addr-hazel", "addr-lemon"] {
        assert_eq!(
            select(&s, &SelectRequest::new(Mode::Diversity, address)),
            Err(SelectError::ValidatorAccount),
            "{address}"
        );
    }
    assert_eq!(
        s.record("palm").unwrap().status,
        ValidatorStatus::ResignedPermanent
    );
    assert!(select(&s, &SelectRequest::new(Mode::Diversity, "addr-palm")).is_ok());
    // Too few validators in the mode and in Diversity together.
    let mut small = s.clone();
    small.records.truncate(25);
    let available = pool(&small, Mode::Diversity).len();
    assert!(available < 53);
    let mut request = SelectRequest::new(Mode::Reliability, "addr-holder");
    request.count = 53;
    assert_eq!(
        select(&small, &request),
        Err(SelectError::NotEnoughValidators {
            requested: 53,
            available: u32::try_from(available).unwrap()
        })
    );
    // An invalid snapshot is refused, never half-used.
    let mut bad = s.clone();
    bad.records[3].name = bad.records[4].name.clone();
    assert!(matches!(
        select(&bad, &SelectRequest::new(Mode::Diversity, "addr-holder")),
        Err(SelectError::Snapshot(_))
    ));
}

#[test]
fn reasons_read_as_plain_english() {
    let s = synthetic();
    for mode in Mode::ALL {
        let selection = select(&s, &SelectRequest::new(mode, "addr-holder-text")).unwrap();
        for pick in &selection.entries {
            assert!(!pick.reasons.is_empty());
            for reason in &pick.reasons {
                let text = reason.to_string();
                assert!(!text.is_empty());
                assert!(!text.contains('\u{2014}'), "{text}");
                assert!(text.is_ascii(), "{text}");
            }
        }
    }
    let judged = evaluate(&s, Mode::SupportNewcomers).unwrap();
    for candidate in judged {
        for shortfall in candidate.shortfalls {
            let text = shortfall.to_string();
            assert!(text.is_ascii() && !text.is_empty(), "{text}");
        }
    }
}
