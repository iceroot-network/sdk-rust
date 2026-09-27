//! Attempts to game the draw, with bounds on how often the gamed validators are picked.
//!
//! Declarations are statements, not verified facts. A validator that invents unique values
//! must not win near-certain picks, one that declares nothing must not be pushed out, the
//! validators of a small last rank band must not be favoured, and one very large payer must not
//! flatten the Maximum Rewards weights of everyone else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;

use iceroot_vote::{
    Declarations, Dimension, Mode, Payouts, Penalties, Production, Reason, SelectRequest,
    SnapshotSource, ValidatorRecord, ValidatorStatus, VoteSnapshot, evaluate, select,
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
    let s = snapshot(records);
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
    let s = snapshot(records);
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
fn a_small_last_rank_band_is_not_favoured() {
    // Without declarations only rank bands spread the picks. With bands of ten ranks, the
    // validator ranked 41st of 41 formed a band of its own and was picked far more often.
    for n in [21usize, 41, 42, 51, 53, 56, 61, 71] {
        let s = snapshot(
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
    // One validator pays 20,000 times the next best; 20 pay 1,000 and 39 pay 500, all seated.
    // As a share of the best payer's in basis points, the others all rounded to 0 and weighed
    // the same.
    let records: Vec<ValidatorRecord> = (0..60)
        .map(|i| {
            let mut record = validator(i, u32::try_from(i + 1).unwrap());
            record.seated = true;
            record.status = ValidatorStatus::Active;
            record.declarations = declared(&format!("Op {i}"), "Hostco", "DE");
            let paid = match i {
                0 => 20_000_000,
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
    // Candidates come in name order, which is index order here: 50 and 25 parts per million.
    assert_eq!(weights[0], 1_000_000 * 1_000_000);
    assert!(weights[1..=20].iter().all(|&w| w == 50 * 50));
    assert!(weights[21..].iter().all(|&w| w == 25 * 25));
    let rates = pick_rates(&s, Mode::MaximumRewards);
    let better = mean(rates[1..=20].iter().copied());
    let lesser = mean(rates[21..].iter().copied());
    println!(
        "huge payer {:.3}, pays 1,000 {better:.3}, pays 500 {lesser:.3}",
        rates[0]
    );
    assert!(rates[0] > 0.99);
    // 19 picks among 59 others: at four times the weight, the better payers take most of them.
    // Flattened, both would be picked by about 32 % of holders.
    assert!(better > 2.0 * lesser, "{better:.3} against {lesser:.3}");
    assert!(better > 0.5, "{better:.3}");
    assert!(lesser < 0.25, "{lesser:.3}");
}
