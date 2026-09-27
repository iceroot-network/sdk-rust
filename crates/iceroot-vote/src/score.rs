//! Each mode's criteria and weights.

use std::collections::BTreeMap;

use crate::mode::Mode;
use crate::reason::{Dimension, Reason, Shortfall, basis_points_of};
use crate::region::Region;
use crate::snapshot::{SnapshotError, SnapshotSource, ValidatorRecord, VoteSnapshot};

/// The least share of assigned slots a validator must forge, in basis points (95 %), wherever a
/// mode judges health from production.
pub const MIN_PRODUCTION_BP: u16 = 9_500;
/// The fewest days of seated history in the window before a validator counts for Reliability.
pub const MIN_SEATED_DAYS: u32 = 7;
/// The fewest days since registration before a validator counts for Support Newcomers.
pub const MIN_REGISTERED_DAYS: u32 = 7;
/// The width of a Diversity rank band: ranks 1 to 10, 11 to 20 and so on.
pub const RANK_BAND_WIDTH: u32 = 10;
/// How many of the last seats count as near the cutoff for Support Newcomers: with 53 seats,
/// ranks 44 to 53, besides every rank below the cutoff.
pub const NEAR_CUTOFF_SEATS: u32 = 10;
/// The most Maximum Rewards picks from one declared operator.
pub const MAX_PICKS_PER_OPERATOR: u32 = 2;

/// Every Diversity candidate's weight before the spread divisor: 2^64.
pub(crate) const DIVERSITY_WEIGHT: u128 = 1 << 64;
/// A Reliability weight with no slot missed.
const RELIABILITY_SCALE: u128 = 1_000_000;
/// The Support Newcomers weight at the cutoff.
const NEWCOMER_SCALE: u128 = 10_000;
/// The distance from the cutoff, in ranks, at which a newcomer's weight halves.
const NEWCOMER_HALF_DISTANCE: u128 = 10;

/// One validator judged by one mode: whether it is eligible, its weight in the draw, and why.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// The validator's name.
    pub validator: String,
    /// Whether it meets the mode's criteria.
    pub eligible: bool,
    /// Its weight in the draw when eligible, else 0. For Diversity this is the weight before the
    /// spread divisor, the same for every candidate.
    pub weight: u128,
    /// The criteria it meets, with their values.
    pub reasons: Vec<Reason>,
    /// The criteria it fails.
    pub shortfalls: Vec<Shortfall>,
}

/// Judge every validator of a snapshot by one mode, in name order. This is what a review screen
/// shows for validators that were not picked, and the pool a selection draws from.
///
/// The criteria (every mode also requires that the validator has not resigned):
///
/// - **Diversity:** no jailing or equivocation in the window, and at least 95 % of assigned slots
///   forged when there is a production record. Every candidate has the same weight, divided at
///   each draw by `(1 + a) × (1 + b) × (1 + c) × (1 + d)`, where `a` to `d` count the picks
///   already made that share its declared operator, hosting provider, region (from the declared
///   country) and rank band. Validators that declare no operator form one group, and so on for
///   each dimension.
/// - **Reliability:** at least 7 days seated in the window, a production record, at least 95 %
///   of assigned slots forged, and no jailing or equivocation in the window. Weight
///   `1,000,000 × assigned / (assigned + 100 × missed)`: missing 1 % of the slots halves it.
/// - **Maximum Rewards:** seated, measured payouts (at least one interval and a positive value)
///   and no jailing or equivocation in the window. Weight: the square of the payout as a share of
///   the best payer's in basis points, at least 1. At most two picks per declared operator;
///   validators that declare no operator form one group. Picks that top the selection up from
///   Diversity never give a declared operator a third pick either.
/// - **Support Newcomers:** ranked within the last 10 seats or below the cutoff, registered for
///   at least 7 days, complete declarations, no penalty ever, and at least 95 % of assigned slots
///   forged when there is a production record from earlier seated time. Weight
///   `100,000 / (10 + distance)`, where the distance counts the ranks between the validator and
///   the cutoff (0 for the last seat and the first rank below it).
///
/// A snapshot without penalty records (a node's relay data) counts no penalties.
pub fn evaluate(snapshot: &VoteSnapshot, mode: Mode) -> Result<Vec<Candidate>, SnapshotError> {
    snapshot.validate()?;
    Ok(candidates(snapshot, mode))
}

/// [`evaluate`] without the snapshot check, for callers that checked it already.
pub(crate) fn candidates(snapshot: &VoteSnapshot, mode: Mode) -> Vec<Candidate> {
    judged(snapshot, mode)
        .into_iter()
        .map(|(candidate, _)| candidate)
        .collect()
}

/// Every validator judged by `mode`, with its record, in name order.
pub(crate) fn judged(snapshot: &VoteSnapshot, mode: Mode) -> Vec<(Candidate, &ValidatorRecord)> {
    let best = best_payout(snapshot);
    let mut records: Vec<&ValidatorRecord> = snapshot.records.iter().collect();
    records.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    records
        .into_iter()
        .map(|record| (assess(snapshot, mode, record, best), record))
        .collect()
}

/// The best measured payout among validators that meet the Maximum Rewards criteria.
fn best_payout(snapshot: &VoteSnapshot) -> u128 {
    snapshot
        .records
        .iter()
        .filter(|record| {
            rewards_shortfalls(record).is_empty()
                && !record.penalties.is_some_and(|p| p.in_window())
        })
        .filter_map(|record| record.payouts.map(|p| p.per_unit_weight))
        .max()
        .unwrap_or(0)
}

/// Judge one validator by one mode.
pub(crate) fn assess(
    snapshot: &VoteSnapshot,
    mode: Mode,
    record: &ValidatorRecord,
    best_payout: u128,
) -> Candidate {
    let mut reasons = vec![Reason::Status {
        status: record.status,
        rank: record.rank,
        seated: record.seated,
    }];
    let mut shortfalls = Vec::new();
    if record.status.is_resigned() {
        shortfalls.push(Shortfall::Resigned {
            status: record.status,
        });
    }
    let approximate = snapshot.source == SnapshotSource::RelayApproximate;
    let weight = match mode {
        Mode::Diversity => {
            production_health(record, approximate, &mut reasons, &mut shortfalls);
            penalties_in_window(record, &mut reasons, &mut shortfalls);
            DIVERSITY_WEIGHT
        }
        Mode::Reliability => {
            match record.seated_days_in_window {
                Some(days) if days >= MIN_SEATED_DAYS => reasons.push(Reason::SeatedDays { days }),
                days => shortfalls.push(Shortfall::TooFewSeatedDays {
                    days,
                    minimum: MIN_SEATED_DAYS,
                }),
            }
            let weight = match record.production.filter(|p| p.assigned > 0) {
                Some(production) => {
                    production_health(record, approximate, &mut reasons, &mut shortfalls);
                    RELIABILITY_SCALE * u128::from(production.assigned)
                        / (u128::from(production.assigned) + 100 * u128::from(production.missed()))
                }
                None => {
                    shortfalls.push(Shortfall::NoProductionRecord);
                    0
                }
            };
            penalties_in_window(record, &mut reasons, &mut shortfalls);
            weight
        }
        Mode::MaximumRewards => {
            let own = rewards_shortfalls(record);
            let weight = match record.payouts {
                Some(payouts) if own.is_empty() => {
                    let of_best = basis_points_of(payouts.per_unit_weight, best_payout).min(10_000);
                    reasons.push(Reason::MeasuredPayouts {
                        per_unit_weight: payouts.per_unit_weight,
                        intervals: payouts.intervals,
                        of_best_bp: u16::try_from(of_best).unwrap_or(10_000),
                    });
                    (of_best * of_best).max(1)
                }
                _ => 0,
            };
            // The resignation is reported once, above.
            shortfalls.extend(
                own.into_iter()
                    .filter(|s| !matches!(s, Shortfall::Resigned { .. })),
            );
            penalties_in_window(record, &mut reasons, &mut shortfalls);
            weight
        }
        Mode::SupportNewcomers => {
            let weight = match record.rank {
                None => {
                    shortfalls.push(Shortfall::NoRank);
                    0
                }
                Some(rank) => {
                    let seats = snapshot.seats;
                    if rank <= seats.saturating_sub(NEAR_CUTOFF_SEATS) {
                        shortfalls.push(Shortfall::NotNearCutoff { rank, seats });
                        0
                    } else {
                        reasons.push(Reason::NearCutoff { rank, seats });
                        let distance = if rank <= seats {
                            seats - rank
                        } else {
                            rank - seats - 1
                        };
                        NEWCOMER_SCALE * NEWCOMER_HALF_DISTANCE
                            / (NEWCOMER_HALF_DISTANCE + u128::from(distance))
                    }
                }
            };
            match record.registered_days(snapshot) {
                Some(days) if days >= u64::from(MIN_REGISTERED_DAYS) => {
                    reasons.push(Reason::RegisteredDays { days });
                }
                days => shortfalls.push(Shortfall::RegisteredTooRecently {
                    days,
                    minimum: MIN_REGISTERED_DAYS,
                }),
            }
            match &record.declarations {
                Some(declarations) if declarations.complete => {
                    reasons.push(Reason::DeclarationsComplete);
                }
                _ => shortfalls.push(Shortfall::DeclarationsIncomplete),
            }
            match record.penalties {
                None => reasons.push(Reason::NoPenaltyRecord),
                Some(p) if p.in_window() => shortfalls.push(Shortfall::PenalizedInWindow {
                    jailed: p.jailed_in_window,
                    equivocation: p.equivocation_in_window,
                }),
                Some(p) if p.any() => shortfalls.push(Shortfall::PenalizedEver),
                Some(_) => reasons.push(Reason::NoPenaltiesEver),
            }
            production_health(record, approximate, &mut reasons, &mut shortfalls);
            weight
        }
    };
    if let Some(basis_points) = record.self_funded_weight_bp {
        reasons.push(Reason::SelfFundedWeight { basis_points });
    }
    let eligible = shortfalls.is_empty() && weight > 0;
    Candidate {
        validator: record.name.clone(),
        eligible,
        weight: if eligible { weight } else { 0 },
        reasons,
        shortfalls,
    }
}

/// The Maximum Rewards criteria other than penalties: not resigned, seated, payouts measured.
fn rewards_shortfalls(record: &ValidatorRecord) -> Vec<Shortfall> {
    let mut shortfalls = Vec::new();
    if record.status.is_resigned() {
        shortfalls.push(Shortfall::Resigned {
            status: record.status,
        });
    }
    if !record.seated {
        shortfalls.push(Shortfall::NotSeated);
    }
    if !record
        .payouts
        .is_some_and(|p| p.intervals > 0 && p.per_unit_weight > 0)
    {
        shortfalls.push(Shortfall::NoMeasuredPayouts);
    }
    shortfalls
}

/// At least 95 % of assigned slots forged, when there is a production record.
fn production_health(
    record: &ValidatorRecord,
    approximate: bool,
    reasons: &mut Vec<Reason>,
    shortfalls: &mut Vec<Shortfall>,
) {
    match record.production.filter(|p| p.assigned > 0) {
        None => reasons.push(Reason::NoProductionRecord),
        Some(p) if p.at_least(MIN_PRODUCTION_BP) => reasons.push(Reason::Production {
            forged: p.forged,
            assigned: p.assigned,
            approximate,
        }),
        Some(p) => shortfalls.push(Shortfall::LowProduction {
            forged: p.forged,
            assigned: p.assigned,
            minimum_bp: MIN_PRODUCTION_BP,
        }),
    }
}

/// No jailing or equivocation in the window; no record counts as none.
fn penalties_in_window(
    record: &ValidatorRecord,
    reasons: &mut Vec<Reason>,
    shortfalls: &mut Vec<Shortfall>,
) {
    match record.penalties {
        None => reasons.push(Reason::NoPenaltyRecord),
        Some(p) if p.in_window() => shortfalls.push(Shortfall::PenalizedInWindow {
            jailed: p.jailed_in_window,
            equivocation: p.equivocation_in_window,
        }),
        Some(_) => reasons.push(Reason::NoPenaltiesInWindow),
    }
}

/// A validator's group in each Diversity dimension, in the order of [`Dimension::ALL`]: an id
/// to compare (see [`Interner`]) and a label to show, `None` for the group of validators without
/// a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Groups {
    pub(crate) ids: [usize; 4],
    pub(crate) labels: [Option<String>; 4],
}

impl Groups {
    /// The operator group's id.
    pub(crate) fn operator_id(&self) -> usize {
        let [operator, ..] = self.ids;
        operator
    }

    /// The declared operator as shown, if any.
    pub(crate) fn operator_label(&self) -> Option<String> {
        let [operator, ..] = &self.labels;
        operator.clone()
    }

    /// Whether the validator declares an operator.
    pub(crate) fn operator_declared(&self) -> bool {
        let [operator, ..] = &self.labels;
        operator.is_some()
    }
}

/// A declared name as a group key: trimmed and in ASCII lowercase; empty is undeclared.
pub(crate) fn declared_key(value: Option<&String>) -> (Option<String>, Option<String>) {
    match value.map(|v| v.trim()).filter(|v| !v.is_empty()) {
        Some(label) => (Some(label.to_ascii_lowercase()), Some(label.to_owned())),
        None => (None, None),
    }
}

/// Numbers the groups of each dimension as it meets them, so that one selection compares
/// groups by number.
#[derive(Debug, Default)]
pub(crate) struct Interner {
    ids: [BTreeMap<Option<String>, usize>; 4],
}

impl Interner {
    /// The Diversity groups of a validator.
    pub(crate) fn groups(&mut self, record: &ValidatorRecord) -> Groups {
        let declarations = record.declarations.as_ref();
        let (operator_key, operator_label) =
            declared_key(declarations.and_then(|d| d.operator.as_ref()));
        let (hosting_key, hosting_label) =
            declared_key(declarations.and_then(|d| d.hosting.as_ref()));
        let region = declarations
            .and_then(|d| d.country.as_deref())
            .and_then(Region::of_country)
            .map(|region| region.name().to_owned());
        let band = record.rank.filter(|&rank| rank >= 1).map(|rank| {
            let first = (rank - 1) / RANK_BAND_WIDTH * RANK_BAND_WIDTH + 1;
            format!("{first} to {}", first.saturating_add(RANK_BAND_WIDTH - 1))
        });
        let keys = [operator_key, hosting_key, region.clone(), band.clone()];
        let mut ids = [0; 4];
        for ((id, map), key) in ids.iter_mut().zip(self.ids.iter_mut()).zip(keys) {
            let next = map.len();
            *id = *map.entry(key).or_insert(next);
        }
        Groups {
            ids,
            labels: [operator_label, hosting_label, region, band],
        }
    }
}

/// Group counts over the picks made so far, for Diversity's divisor.
#[derive(Debug, Default)]
pub(crate) struct Spread {
    counts: [Vec<u32>; 4],
}

impl Spread {
    /// Picks so far in each of `groups`' groups.
    pub(crate) fn shared(&self, groups: &Groups) -> [u32; 4] {
        let mut shared = [0; 4];
        for ((n, counts), &id) in shared.iter_mut().zip(&self.counts).zip(&groups.ids) {
            *n = counts.get(id).copied().unwrap_or(0);
        }
        shared
    }

    /// Count a pick.
    pub(crate) fn add(&mut self, groups: &Groups) {
        for (counts, &id) in self.counts.iter_mut().zip(&groups.ids) {
            if counts.len() <= id {
                counts.resize(id + 1, 0);
            }
            if let Some(n) = counts.get_mut(id) {
                *n += 1;
            }
        }
    }

    /// The Diversity weight of a candidate: [`DIVERSITY_WEIGHT`] divided by the product of one
    /// plus the picks sharing each of its groups.
    pub(crate) fn weight(&self, groups: &Groups) -> u128 {
        let divisor = self
            .shared(groups)
            .iter()
            .fold(1u128, |product, &n| product * (1 + u128::from(n)));
        DIVERSITY_WEIGHT / divisor
    }

    /// The group reasons of a pick, before it is counted.
    pub(crate) fn reasons(&self, groups: &Groups) -> Vec<Reason> {
        Dimension::ALL
            .into_iter()
            .zip(&groups.labels)
            .zip(self.shared(groups))
            .map(|((dimension, label), earlier_picks)| Reason::Group {
                dimension,
                value: label.clone(),
                earlier_picks,
            })
            .collect()
    }
}
