//! Selections keep within the network's vote rules: at most 1,024 bytes on the Solar-compatible
//! stage and 1,280 bytes from IceRoot's genesis, and only names and shares the rules accept.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_vote::{
    Mode, Problem, Production, SelectError, SelectRequest, Selection, SnapshotSource,
    ValidatorRecord, ValidatorStatus, VoteRules, VoteSnapshot, Voter, select, validate_vote,
    vote_bytes,
};

/// A 20-letter name for index `i`, the longest a validator name can be: 23 bytes in a vote.
fn long_name(i: usize) -> String {
    let a = char::from(b'a' + u8::try_from(i % 26).unwrap());
    let b = char::from(b'a' + u8::try_from(i / 26).unwrap());
    format!("{b}{a}{}", "x".repeat(18))
}

/// 60 healthy validators with names of `length(i)` letters.
fn snapshot(length: impl Fn(usize) -> usize) -> VoteSnapshot {
    let records = (0..60)
        .map(|i| {
            let name: String = long_name(i).chars().take(length(i)).collect();
            ValidatorRecord {
                address: format!("addr-{name}"),
                name,
                rank: Some(u32::try_from(i + 1).unwrap()),
                seated: i < 53,
                status: if i < 53 {
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
                penalties: None,
                declarations: None,
                payouts: None,
                self_funded_weight_bp: None,
            }
        })
        .collect();
    VoteSnapshot {
        height: 1_000_000,
        window_days: 30,
        seats: 53,
        block_time_seconds: 8,
        source: SnapshotSource::Indexer,
        records,
    }
}

fn request(count: u8, rules: VoteRules) -> SelectRequest<'static> {
    SelectRequest {
        count,
        rules,
        ..SelectRequest::new(Mode::Diversity, "holder-limits")
    }
}

fn in_draw_order(selection: &Selection) -> Vec<String> {
    let mut picks: Vec<_> = selection.entries.iter().collect();
    picks.sort_by_key(|p| p.step);
    picks.into_iter().map(|p| p.validator.clone()).collect()
}

#[test]
fn long_names_leave_fewer_picks_on_the_solar_compatible_stage() {
    let s = snapshot(|_| 20);
    // 53 names of 20 letters take 1 + 53 × 23 = 1,220 bytes: within IceRoot's 1,280.
    let iceroot = select(&s, &request(53, VoteRules::ICEROOT)).unwrap();
    assert_eq!(iceroot.entries.len(), 53);
    assert_eq!(vote_bytes(&iceroot.vote()), 1_220);
    assert!(iceroot.size_notice().is_none());
    // On the Solar-compatible stage 44 fit (1,013 bytes); a 45th would take 1,036.
    let solar = select(&s, &request(53, VoteRules::SOLAR_COMPATIBLE)).unwrap();
    assert_eq!(solar.entries.len(), 44);
    assert_eq!(solar.requested, 53);
    assert_eq!(vote_bytes(&solar.vote()), 1_013);
    assert!(validate_vote(&solar.vote(), &VoteRules::SOLAR_COMPATIBLE, Voter::Ordinary).is_empty());
    // 10,000 basis points over 44 picks: 12 of 228 and 32 of 227.
    assert_eq!(
        solar
            .entries
            .iter()
            .filter(|p| p.basis_points == 228)
            .count(),
        12
    );
    assert!(
        solar
            .entries
            .iter()
            .all(|p| p.basis_points == 228 || p.basis_points == 227)
    );
    assert_eq!(
        solar.size_notice().unwrap(),
        "Only 44 of the 53 requested picks fit in a vote of at most 1,024 bytes"
    );
    // The same draw, cut short: the first 44 picks of the longer selection, and the selection
    // that asks for 44.
    assert_eq!(in_draw_order(&solar), in_draw_order(&iceroot)[..44]);
    let asked = select(&s, &request(44, VoteRules::SOLAR_COMPATIBLE)).unwrap();
    assert_eq!(
        Selection {
            requested: 53,
            ..asked
        },
        solar
    );
    // The default 20 picks always fit: 20 × 23 + 1 = 461 bytes.
    let twenty = select(&s, &request(20, VoteRules::SOLAR_COMPATIBLE)).unwrap();
    assert_eq!(twenty.entries.len(), 20);
    assert!(twenty.size_notice().is_none());
}

#[test]
fn the_draw_is_cut_where_it_stops_fitting() {
    // Every other name has 20 letters, the rest 3: the draw is kept up to the first pick that
    // does not fit, never skipping ahead to a shorter name.
    let s = snapshot(|i| if i % 2 == 0 { 20 } else { 3 });
    let whole = select(&s, &request(53, VoteRules::ICEROOT)).unwrap();
    let limited = VoteRules {
        max_bytes: 700,
        ..VoteRules::ICEROOT
    };
    let cut = select(&s, &request(53, limited)).unwrap();
    let order = in_draw_order(&whole);
    let kept = cut.entries.len();
    assert!(kept < 53);
    assert_eq!(in_draw_order(&cut), order[..kept]);
    let bytes = |names: &[String]| 1 + names.iter().map(|n| 3 + n.len()).sum::<usize>();
    assert!(bytes(&order[..kept]) <= 700);
    assert!(bytes(&order[..=kept]) > 700);
}

#[test]
fn a_selection_that_cannot_fit_is_refused_clearly() {
    let s = snapshot(|_| 20);
    // 17 names of 20 letters fit in 400 bytes (392); a selection needs 20.
    let tight = VoteRules {
        max_bytes: 400,
        ..VoteRules::ICEROOT
    };
    let refused = select(&s, &request(20, tight)).unwrap_err();
    assert_eq!(
        refused,
        SelectError::DoesNotFit {
            fits: 17,
            minimum: 20,
            max_entries: 53,
            max_bytes: 400
        }
    );
    assert_eq!(
        refused.to_string(),
        "only 17 picks fit in a vote of at most 400 bytes, and a selection needs at least 20"
    );
    // Rules that name fewer validators than a selection needs.
    let few = VoteRules {
        max_entries: 10,
        ..VoteRules::ICEROOT
    };
    let refused = select(&s, &request(20, few)).unwrap_err();
    assert_eq!(
        refused.to_string(),
        "a vote names at most 10 validators, and a selection needs at least 20"
    );
}

#[test]
fn the_rules_entry_limits_bound_the_picks() {
    let s = snapshot(|_| 5);
    let thirty = VoteRules {
        max_entries: 30,
        ..VoteRules::ICEROOT
    };
    let selection = select(&s, &request(53, thirty)).unwrap();
    assert_eq!(selection.entries.len(), 30);
    assert_eq!(
        selection.size_notice().unwrap(),
        "A vote names at most 30 validators, so the selection has 30 picks, not the 53 requested"
    );
    // Rules that need more entries than requested refuse the count.
    let more = VoteRules {
        min_entries: 25,
        ..VoteRules::ICEROOT
    };
    let refused = select(&s, &request(20, more)).unwrap_err();
    assert_eq!(
        refused,
        SelectError::Count {
            count: 20,
            minimum: 25,
            maximum: 53
        }
    );
    assert_eq!(
        refused.to_string(),
        "a selection has 25 to 53 picks, not 20"
    );
}

#[test]
fn a_selection_that_breaks_the_name_rule_or_the_largest_share_is_refused() {
    // The draw does not depend on the name rule or the largest share, so select checks its result
    // against them: a selection is always a vote its rules accept.
    let s = snapshot(|_| 5);
    // A largest share of 4 %: 20 picks of 5 % are refused, 25 of 4 % are not.
    let four_percent = VoteRules {
        max_entry_basis_points: 400,
        ..VoteRules::ICEROOT
    };
    let refused = select(&s, &request(20, four_percent)).unwrap_err();
    let SelectError::BreaksRules { problems } = &refused else {
        panic!("{refused:?}");
    };
    assert_eq!(problems.len(), 20);
    assert!(problems.iter().all(|p| matches!(
        p,
        Problem::ShareTooLarge {
            basis_points: 500,
            maximum: 400,
            ..
        }
    )));
    assert!(
        refused
            .to_string()
            .starts_with("the selection breaks the vote rules: ")
    );
    assert!(
        refused
            .to_string()
            .contains("has 5.00 %; one validator can have at most 4.00 %; ")
    );
    let accepted = select(&s, &request(25, four_percent)).unwrap();
    assert!(accepted.entries.iter().all(|p| p.basis_points == 400));
    // The same picks as under IceRoot's rules: the check changes nothing about the draw.
    let iceroot = select(&s, &request(25, VoteRules::ICEROOT)).unwrap();
    assert_eq!(
        Selection {
            rules: VoteRules::ICEROOT,
            ..accepted
        },
        iceroot
    );
    // A tighter size limit can leave shares above the largest: 40 of 53 picks fit in 321 bytes
    // (5 letters each), 250 basis points each against a largest of 200.
    let tight = VoteRules {
        max_entry_basis_points: 200,
        max_bytes: 321,
        ..VoteRules::ICEROOT
    };
    let refused = select(&s, &request(53, tight)).unwrap_err();
    assert!(matches!(
        &refused,
        SelectError::BreaksRules { problems } if problems.len() == 40
    ));
}

#[test]
fn names_the_rules_refuse_are_never_signed() {
    // A snapshot with names IceRoot's rules refuse: digits and underscores, as on the
    // Solar-compatible devnet.
    let mut s = snapshot(|_| 20);
    for record in &mut s.records {
        record.name = format!("node_{}", &record.name[..2]);
        record.address = format!("addr-{}", record.name);
    }
    let refused = select(&s, &request(20, VoteRules::ICEROOT)).unwrap_err();
    let SelectError::BreaksRules { problems } = &refused else {
        panic!("{refused:?}");
    };
    assert_eq!(problems.len(), 20);
    assert!(
        problems
            .iter()
            .all(|p| matches!(p, Problem::InvalidName { .. }))
    );
    assert!(refused.to_string().contains(" is not a validator name"));
    // The Solar-compatible stage accepts them.
    let solar = select(&s, &request(20, VoteRules::SOLAR_COMPATIBLE)).unwrap();
    assert!(validate_vote(&solar.vote(), &VoteRules::SOLAR_COMPATIBLE, Voter::Ordinary).is_empty());
}

#[test]
fn a_huge_manual_vote_is_judged_in_bounded_time_without_overflow() {
    // 70,000 entries of 65,535 basis points: the total is beyond 32 bits, and a check that
    // compares every entry with every earlier one would take minutes.
    let names: Vec<String> = (0..70_000usize)
        .map(|i| {
            let letter = |shift: usize| char::from(b'a' + u8::try_from(i / shift % 26).unwrap());
            format!(
                "{}{}{}{}",
                letter(17_576),
                letter(676),
                letter(26),
                letter(1)
            )
        })
        .collect();
    let mut entries: Vec<iceroot_vote::VoteEntry> = names
        .iter()
        .map(|validator| iceroot_vote::VoteEntry {
            validator: validator.clone(),
            basis_points: u16::MAX,
        })
        .collect();
    entries.push(entries[0].clone());
    let started = std::time::Instant::now();
    let problems = validate_vote(&entries, &VoteRules::ICEROOT, Voter::Ordinary);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert!(problems.contains(&Problem::WrongTotal { total: u32::MAX }));
    assert_eq!(
        problems
            .iter()
            .filter(|p| matches!(p, Problem::DuplicateValidator { .. }))
            .count(),
        1
    );
}
