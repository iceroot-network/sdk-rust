//! Attempts to game the draw, with bounds on how often the gamed validators are picked.
//!
//! Declarations are statements, not verified facts. A validator that invents unique values
//! must not win near-certain picks, one that declares nothing must not be pushed out (not even
//! when every other validator invents unique values), the validators of a small last rank band
//! must not be favoured, and one very large payer must not flatten the Maximum Rewards weights
//! of everyone else. Validators registered in bulk must not crowd the Diversity and Support
//! Newcomers draws, however many they are.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;

use iceroot_vote::{
    DIVERSITY_RANKS_BELOW_CUTOFF, Declarations, Dimension, Mode, NEWCOMER_RANKS_BELOW_CUTOFF,
    Payouts, Penalties, Production, Reason, SelectRequest, Selection, Shortfall, SnapshotSource,
    ValidatorRecord, ValidatorStatus, VoteSnapshot, evaluate, select,
};

/// Selections per scenario.
const HOLDERS: usize = 2_000;

/// A lowercase name for index `i`: `vaa`, `vab`, ...
fn name(i: usize) -> String {
    let a = char::from(b'a' + u8::try_from(i % 26).unwrap());
    let b = char::from(b'a' + u8::try_from(i / 26 % 26).unwrap());
    format!("v{b}{a}")
}

/// A healthy validator at `rank`, seated within the first 53, without declarations.
fn validator(i: usize, rank: u32) -> ValidatorRecord {
    ValidatorRecord {
        name: name(i),
        address: format!("addr-{}", name(i)),
        rank: Some(rank),
        seated: rank <= 53,
        status: if rank <= 53 {
            ValidatorStatus::Active
        } else {
            ValidatorStatus::Standby
        },
        registered_height: Some(1),
        seated_days_in_window: Some(30),
        vote_weight: 1_000,
        voters: 3,
        production: Some(Production {
            forged: 1_000,
            assigned: 1_000,
        }),
        penalties: Some(Penalties::default()),
        declarations: None,
        payouts: None,
        self_funded_weight_bp: None,
    }
}

fn declared(operator: &str, hosting: &str, country: &str) -> Option<Declarations> {
    Some(Declarations {
        operator: Some(operator.to_owned()),
        hosting: Some(hosting.to_owned()),
        country: Some(country.to_owned()),
        complete: true,
    })
}

fn snapshot(records: Vec<ValidatorRecord>) -> VoteSnapshot {
    VoteSnapshot {
        height: 1_000_000,
        window_days: 30,
        seats: 53,
        block_time_seconds: 8,
        source: SnapshotSource::Indexer,
        records,
    }
}

/// A snapshot whose seats keep every validator within Diversity's pool (the seats and the next 10
/// ranks), so that a test measures the Diversity weights alone: at least 53 seats, more when
/// there are more than 63 validators.
fn open_snapshot(mut records: Vec<ValidatorRecord>) -> VoteSnapshot {
    let seats = u32::try_from(records.len())
        .unwrap()
        .saturating_sub(DIVERSITY_RANKS_BELOW_CUTOFF)
        .max(53);
    for record in &mut records {
        record.seated = record.rank.is_some_and(|rank| rank <= seats);
        record.status = if record.seated {
            ValidatorStatus::Active
        } else {
            ValidatorStatus::Standby
        };
    }
    VoteSnapshot {
        seats,
        ..snapshot(records)
    }
}

/// Each validator's pick rate over [`HOLDERS`] selections of 20, by index; every Diversity pick
/// is checked against the weight bound on the way.
fn pick_rates(s: &VoteSnapshot, mode: Mode) -> Vec<f64> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for holder in 0..HOLDERS {
        let account = format!("holder-{holder}");
        let selection = select(s, &SelectRequest::new(mode, &account)).unwrap();
        for pick in &selection.entries {
            *counts.entry(pick.validator.clone()).or_insert(0) += 1;
            assert_weight_bound(&pick.reasons);
        }
    }
    (0..s.records.len())
        .map(|i| counts.get(&name(i)).copied().unwrap_or(0) as f64 / HOLDERS as f64)
        .collect()
}

/// A Diversity pick weighs from `⌊2^64 / (1 + r)⌋`, with `r` the earlier picks in its rank band,
/// to twice that, whatever it declares.
fn assert_weight_bound(reasons: &[Reason]) {
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

fn mean(rates: impl IntoIterator<Item = f64>) -> f64 {
    let rates: Vec<f64> = rates.into_iter().collect();
    rates.iter().sum::<f64>() / rates.len() as f64
}

#[test]
fn invented_unique_declarations_do_not_buy_near_certain_picks() {
    // 60 validators on common infrastructure (operators in pairs, three hosting providers, most
    // of them in Europe) and 5 that declare an operator, a hosting provider and a region no one
    // else has, one in each of five rank bands.
    let hosts = [
        "Hostco",
        "Hostco",
        "Hostco",
        "Metalbox",
        "Metalbox",
        "Cloudnine",
    ];
    let countries = ["DE", "DE", "US", "FI", "FR", "DE", "US", "NL"];
    let far = ["BR", "ZA", "AU", "JP", "AR"];
    let cluster = [4usize, 17, 30, 43, 56];
    let mut records = Vec::new();
    let mut honest = 0;
    for i in 0..65 {
        let mut record = validator(i, u32::try_from(i + 1).unwrap());
        record.declarations = match cluster.iter().position(|&c| c == i) {
            Some(k) => declared(&format!("Solo {k}"), &format!("Own rack {k}"), far[k]),
            None => {
                honest += 1;
                declared(
                    &format!("Pair {}", honest / 2),
                    hosts[honest % hosts.len()],
                    countries[honest % countries.len()],
                )
            }
        };
        records.push(record);
    }
    let s = open_snapshot(records);
    let rates = pick_rates(&s, Mode::Diversity);
    let uniform = 20.0 / 65.0;
    let clustered = mean(cluster.iter().map(|&i| rates[i]));
    let common = mean((0..65).filter(|i| !cluster.contains(i)).map(|i| rates[i]));
    println!("unique declarations {clustered:.3}, common {common:.3}, uniform {uniform:.3}");
    // With an unbounded bonus the five were picked by 99 % of holders, the rest by 25 %.
    for &i in &cluster {
        println!("  {}: {:.3}", name(i), rates[i]);
        assert!(rates[i] < 0.5, "{}: {:.3}", name(i), rates[i]);
    }
    assert!(
        clustered < 1.6 * common,
        "{clustered:.3} against {common:.3}"
    );
    assert!(common > 0.8 * uniform, "{common:.3}");
}

#[test]
fn declaring_nothing_is_not_pushed_out() {
    // 70 validators that declare nothing and 10 that declare unique values.
    let countries = ["BR", "ZA", "AU", "JP", "AR", "KE", "NZ", "CL", "IN", "EG"];
    let records: Vec<ValidatorRecord> = (0..80)
        .map(|i| {
            let mut record = validator(i, u32::try_from(i + 1).unwrap());
            if i % 8 == 0 {
                record.declarations =
                    declared(&format!("Op {i}"), &format!("Host {i}"), countries[i / 8]);
            }
            record
        })
        .collect();
    let s = open_snapshot(records);
    let rates = pick_rates(&s, Mode::Diversity);
    let uniform = 20.0 / 80.0;
    let declaring = mean((0..80).filter(|i| i % 8 == 0).map(|i| rates[i]));
    let silent = mean((0..80).filter(|i| i % 8 != 0).map(|i| rates[i]));
    println!("declaring {declaring:.3}, declaring nothing {silent:.3}, uniform {uniform:.3}");
    // With an unbounded bonus the ten were always picked and the rest by 14 %.
    assert!(declaring < 0.5, "{declaring:.3}");
    assert!(
        declaring < 2.0 * silent,
        "{declaring:.3} against {silent:.3}"
    );
    assert!(silent > 0.8 * uniform, "{silent:.3}");
    for i in (0..80).filter(|i| i % 8 != 0) {
        assert!(rates[i] > 0.6 * uniform, "{}: {:.3}", name(i), rates[i]);
    }
}

#[test]
fn declaring_nothing_costs_at_most_half_when_everyone_else_invents() {
    // The worst case for silence: 60 validators each declare an operator and a hosting provider
    // that no one else has, spread over all seven regions, and 6 declare nothing. Each draw can
    // weigh a declaring validator at most twice as much as a silent one.
    let regions = ["DE", "US", "BR", "ZA", "AU", "JP", "AQ"];
    let silent = [4usize, 15, 26, 37, 48, 59];
    let mut declaring_index = 0;
    let records: Vec<ValidatorRecord> = (0..66)
        .map(|i| {
            let mut record = validator(i, u32::try_from(i + 1).unwrap());
            if !silent.contains(&i) {
                let k = declaring_index;
                declaring_index += 1;
                record.declarations = declared(
                    &format!("Solo {k}"),
                    &format!("Own rack {k}"),
                    regions[k % regions.len()],
                );
            }
            record
        })
        .collect();
    let s = open_snapshot(records);
    let rates = pick_rates(&s, Mode::Diversity);
    let uniform = 20.0 / 66.0;
    let quiet = mean(silent.iter().map(|&i| rates[i]));
    let declaring = mean((0..66).filter(|i| !silent.contains(i)).map(|i| rates[i]));
    println!("declaring nothing {quiet:.3}, all unique {declaring:.3}, uniform {uniform:.3}");
    assert!(quiet > 0.5 * declaring, "{quiet:.3} against {declaring:.3}");
    assert!(quiet > 0.55 * uniform, "{quiet:.3}");
    assert!(declaring < 1.15 * uniform, "{declaring:.3}");
    for &i in &silent {
        assert!(rates[i] > 0.5 * uniform, "{}: {:.3}", name(i), rates[i]);
    }
}

#[test]
fn a_small_last_rank_band_is_not_favoured() {
    // Without declarations only rank bands spread the picks. With bands of ten ranks, the
    // validator ranked 41st of 41 formed a band of its own and was picked far more often.
    for n in [21usize, 41, 42, 51, 53, 56, 61, 71] {
        let s = open_snapshot(
            (0..n)
                .map(|i| validator(i, u32::try_from(i + 1).unwrap()))
                .collect(),
        );
        let rates = pick_rates(&s, Mode::Diversity);
        let uniform = 20.0 / n as f64;
        let (low, high) = rates
            .iter()
            .fold((f64::MAX, 0.0f64), |(l, h), &r| (l.min(r), h.max(r)));
        println!("{n} validators: pick rates {low:.3} to {high:.3}, uniform {uniform:.3}");
        assert!(high < 1.2 * uniform, "{n}: {high:.3}");
        assert!(low > 0.8 * uniform, "{n}: {low:.3}");
        let last = rates[n - 1];
        assert!(last < 1.15 * uniform, "{n}: the last rank {last:.3}");
    }
}

#[test]
fn one_huge_payer_does_not_flatten_the_others() {
    // One validator pays 20,000 times the next best, then two million and a billion times (for
    // example a validator with almost no vote weight that pays its own voter); 20 pay 1,000 and
    // 39 pay 500, all seated. As a share of the best payer's in basis points, the others all
    // rounded to 0 at 20,000 times and weighed the same; in parts per million they did at two
    // million times, and both groups were picked by 32 % of holders.
    for times in [20_000u128, 2_000_000, 1_000_000_000] {
        let records: Vec<ValidatorRecord> = (0..60)
            .map(|i| {
                let mut record = validator(i, u32::try_from(i + 1).unwrap());
                record.seated = true;
                record.status = ValidatorStatus::Active;
                record.declarations = declared(&format!("Op {i}"), "Hostco", "DE");
                let paid = match i {
                    0 => 1_000 * times,
                    1..=20 => 1_000,
                    _ => 500,
                };
                record.payouts = Some(Payouts {
                    per_unit_weight: paid,
                    intervals: 30,
                });
                record
            })
            .collect();
        let s = VoteSnapshot {
            seats: 60,
            ..snapshot(records)
        };
        let weights: Vec<u128> = evaluate(&s, Mode::MaximumRewards)
            .unwrap()
            .into_iter()
            .map(|c| c.weight)
            .collect();
        // Candidates come in name order, which is index order here. Shares are in 10^15 parts
        // of the best payer's: the 1,000-payers keep exactly four times the 500-payers' weight.
        let share = 10u128.pow(15) / times;
        assert_eq!(weights[0], 10u128.pow(30));
        assert!(
            weights[1..=20].iter().all(|&w| w == share * share),
            "{times}"
        );
        assert!(
            weights[21..].iter().all(|&w| w == share * share / 4),
            "{times}"
        );
        let rates = pick_rates(&s, Mode::MaximumRewards);
        let better = mean(rates[1..=20].iter().copied());
        let lesser = mean(rates[21..].iter().copied());
        println!(
            "{times} times: huge payer {:.3}, pays 1,000 {better:.3}, pays 500 {lesser:.3}",
            rates[0]
        );
        assert!(rates[0] > 0.99);
        // 19 picks among 59 others: at four times the weight, the better payers take most of
        // them. Flattened, both would be picked by about 32 % of holders.
        assert!(
            better > 2.0 * lesser,
            "{times}: {better:.3} against {lesser:.3}"
        );
        assert!(better > 0.5, "{times}: {better:.3}");
        assert!(lesser < 0.25, "{times}: {lesser:.3}");
    }
}

/// 53 seated validators on common infrastructure: operators in pairs, three hosting providers,
/// mostly in Europe, every declaration complete.
fn seated() -> Vec<ValidatorRecord> {
    let hosts = [
        "Hostco",
        "Hostco",
        "Hostco",
        "Metalbox",
        "Metalbox",
        "Cloudnine",
    ];
    let countries = ["DE", "DE", "US", "FI", "FR", "DE", "US", "NL"];
    (0..53)
        .map(|i| {
            let mut record = validator(i, u32::try_from(i + 1).unwrap());
            record.declarations = declared(
                &format!("Pair {}", i / 2),
                hosts[i % hosts.len()],
                countries[i % countries.len()],
            );
            record
        })
        .collect()
}

/// `count` validators ranked from 54 down, below the seated ones: registered long ago, never
/// assigned a slot, with complete declarations naming `operator(k)` for the k-th of them and a
/// hosting provider and region no one else declares (the most a declaration can gain).
fn below_the_seats(count: usize, operator: impl Fn(usize) -> String) -> Vec<ValidatorRecord> {
    let far = ["BR", "ZA", "AU", "JP", "AQ", "MX", "NZ"];
    (0..count)
        .map(|k| {
            let i = 53 + k;
            let mut record = validator(i, u32::try_from(i + 1).unwrap());
            record.production = None;
            record.seated_days_in_window = Some(0);
            record.declarations = declared(&operator(k), &format!("Own rack {k}"), far[k % 7]);
            record
        })
        .collect()
}

/// A first draw of 20 for each of [`HOLDERS`] accounts.
fn selections(s: &VoteSnapshot, mode: Mode) -> Vec<Selection> {
    (0..HOLDERS)
        .map(|holder| {
            let account = format!("holder-{holder}");
            select(s, &SelectRequest::new(mode, &account)).unwrap()
        })
        .collect()
}

/// The picks ranked below the seats, per selection on average, and the deepest rank picked.
fn below_the_seats_picked(s: &VoteSnapshot, selections: &[Selection]) -> (f64, u32) {
    let mut below = 0usize;
    let mut deepest = 0;
    for selection in selections {
        for pick in &selection.entries {
            let rank = s.record(&pick.validator).unwrap().rank.unwrap();
            deepest = deepest.max(rank);
            below += usize::from(rank > 53);
        }
    }
    (below as f64 / selections.len() as f64, deepest)
}

/// How many validators ranked below the seats meet a mode's criteria.
fn eligible_below_the_seats(s: &VoteSnapshot, mode: Mode) -> usize {
    evaluate(s, mode)
        .unwrap()
        .iter()
        .filter(|c| c.eligible && s.record(&c.validator).unwrap().rank.unwrap() > 53)
        .count()
}

#[test]
fn a_standby_flood_gains_nothing_from_its_size() {
    // Validators registered in bulk at the registration fee and without votes rank below every
    // validator that has votes. With open pools, 100 of them declaring nothing took 13 of 20
    // Diversity picks. Diversity now draws from the seats and the next 10 ranks, Support
    // Newcomers from the last 10 seats and the 20 ranks below the cutoff, so 20, 53 and 100 of
    // them give exactly the same selections. Here each invents an operator, a hosting provider
    // and a region, the most a declaration can gain.
    let mut first: Option<(Vec<Selection>, Vec<Selection>)> = None;
    for flood in [20usize, 53, 100] {
        let mut records = seated();
        records.extend(
            below_the_seats(flood, |k| format!("Solo {k}"))
                .into_iter()
                .map(|record| ValidatorRecord {
                    vote_weight: 0,
                    voters: 0,
                    ..record
                }),
        );
        let s = snapshot(records);
        assert_eq!(eligible_below_the_seats(&s, Mode::Diversity), 10);
        assert_eq!(eligible_below_the_seats(&s, Mode::SupportNewcomers), 20);
        // The last of them is outside a pool whose ranks it passes, and the review screen says
        // why.
        let last = name(52 + flood);
        let rank = u32::try_from(53 + flood).unwrap();
        for (mode, ranks_below) in [
            (Mode::Diversity, DIVERSITY_RANKS_BELOW_CUTOFF),
            (Mode::SupportNewcomers, NEWCOMER_RANKS_BELOW_CUTOFF),
        ] {
            let judged = evaluate(&s, mode).unwrap();
            let candidate = judged.iter().find(|c| c.validator == last).unwrap();
            let outside = if rank > 53 + ranks_below {
                vec![Shortfall::FarBelowCutoff {
                    rank,
                    seats: 53,
                    ranks_below,
                }]
            } else {
                Vec::new()
            };
            assert_eq!(candidate.shortfalls, outside, "{flood} {mode}");
        }

        let diverse = selections(&s, Mode::Diversity);
        let (diverse_mean, diverse_deepest) = below_the_seats_picked(&s, &diverse);
        let newcomers = selections(&s, Mode::SupportNewcomers);
        let (newcomer_mean, newcomer_deepest) = below_the_seats_picked(&s, &newcomers);
        println!(
            "{flood} standby validators: {diverse_mean:.2} of 20 Diversity picks (deepest rank {diverse_deepest}), {newcomer_mean:.2} of 20 Support Newcomers picks (deepest rank {newcomer_deepest})"
        );
        // Ten of 63 validators in Diversity's pool, with at most twice the weight for their
        // invented values: under a fifth of the picks.
        assert!(diverse_deepest <= 63);
        assert!(diverse_mean < 4.0, "{diverse_mean:.2}");
        // Under names of their own the operator cap cannot hold them back: they fill 20 of the 30
        // ranks Support Newcomers draws from and take about 13 of 20 picks, never more as they
        // grow, and nothing ranked below 73.
        assert!(newcomer_deepest <= 73);
        assert!(newcomer_mean < 13.5, "{newcomer_mean:.2}");
        match &first {
            None => first = Some((diverse, newcomers)),
            Some((d, n)) => {
                assert!(&diverse == d, "{flood}: Diversity selections differ");
                assert!(
                    &newcomers == n,
                    "{flood}: Support Newcomers selections differ"
                );
            }
        }
    }
}

#[test]
fn a_party_below_the_cutoff_is_held_to_its_ranks_and_its_operator_cap() {
    // One party runs 30 validators ranked 54 to 83, just below 53 seated ones. With open pools it
    // took 13.8 of 20 Support Newcomers picks and 8 of 20 Diversity picks.
    for one_operator in [true, false] {
        let mut records = seated();
        records.extend(below_the_seats(30, |k| {
            if one_operator {
                "Party".to_owned()
            } else {
                format!("Party {k}")
            }
        }));
        let s = snapshot(records);
        let newcomers = selections(&s, Mode::SupportNewcomers);
        let (newcomer_mean, newcomer_deepest) = below_the_seats_picked(&s, &newcomers);
        let diverse = selections(&s, Mode::Diversity);
        let (diverse_mean, diverse_deepest) = below_the_seats_picked(&s, &diverse);
        let label = if one_operator {
            "one operator"
        } else {
            "different names"
        };
        println!(
            "a party of 30 under {label}: {newcomer_mean:.2} of 20 Support Newcomers picks, {diverse_mean:.2} of 20 Diversity picks"
        );
        assert!(newcomer_deepest <= 73 && diverse_deepest <= 63);
        assert!(diverse_mean < 4.0, "{label}: {diverse_mean:.2}");
        if one_operator {
            // Two picks, in every selection: the mode's pool gives only 12 (the last 10 seats and
            // two of the party), and the 8 top-ups from Diversity pass over the party's
            // validators ranked 54 to 63.
            for selection in &newcomers {
                assert_eq!(selection.topped_up, 8);
                let party: Vec<_> = selection
                    .entries
                    .iter()
                    .filter(|p| s.record(&p.validator).unwrap().rank.unwrap() > 53)
                    .collect();
                assert_eq!(party.len(), 2);
                for pick in party {
                    assert!(pick.reasons.iter().any(|r| matches!(
                        r,
                        Reason::OperatorPicks { operator: Some(o), maximum: 2, .. } if o == "Party"
                    )));
                }
            }
        } else {
            // Different names dodge the cap, which only a verified declaration could close: the
            // party fills 20 of the 30 ranks the mode draws from and takes about 13 of 20 picks.
            assert!(newcomer_mean < 13.5, "{newcomer_mean:.2}");
        }
    }
}
