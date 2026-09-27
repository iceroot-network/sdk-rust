//! Each mode's criteria and weights.

use std::collections::BTreeMap;

use crate::mode::Mode;
use crate::reason::{Dimension, Reason, Shortfall, mul_div};
use crate::region::Region;
use crate::snapshot::{SnapshotError, SnapshotSource, ValidatorRecord, VoteSnapshot};

/// The least share of assigned slots a validator must forge, in basis points (95 %), wherever a
/// mode judges health from production.
pub const MIN_PRODUCTION_BP: u16 = 9_500;
/// The fewest days of seated history in the window before a validator counts for Reliability.
pub const MIN_SEATED_DAYS: u32 = 7;
/// The fewest days since registration before a validator counts for Support Newcomers.
pub const MIN_REGISTERED_DAYS: u32 = 7;
/// The most validators in one Diversity rank band. Diversity's pool, in rank order, is split into
/// `⌈n / 10⌉` bands whose sizes differ by at most one, so that no band is a small remainder whose
/// few members would be picked more often than the rest.
pub const RANK_BAND_SIZE: u32 = 10;
/// How many of the last seats count as near the cutoff for Support Newcomers: with 53 seats,
/// ranks 44 to 53, besides every rank below the cutoff.
pub const NEAR_CUTOFF_SEATS: u32 = 10;
/// The most Maximum Rewards picks from one declared operator.
pub const MAX_PICKS_PER_OPERATOR: u32 = 2;

/// Every Diversity candidate's weight before the spread: 2^64.
pub(crate) const DIVERSITY_WEIGHT: u128 = 1 << 64;
/// Maximum Rewards compares payouts in parts per million of the best payer's.
const PAYOUT_SCALE: u64 = 1_000_000;
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
    /// spread, the same for every candidate.
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
///   forged when there is a production record. Every candidate has the same weight, which each
///   draw spreads over rank bands first and declarations second (see [`select`](crate::select)):
///   it is divided by one plus the picks already made in the candidate's rank band, then raised
///   for each declared operator, hosting provider and region that fewer earlier picks share than
///   the most common one, to at most twice the weight of a candidate whose declared values are
///   all common or undeclared.
/// - **Reliability:** at least 7 days seated in the window, a production record, at least 95 %
///   of assigned slots forged, and no jailing or equivocation in the window. Weight
///   `1,000,000 × assigned / (assigned + 100 × missed)`: missing 1 % of the slots halves it.
/// - **Maximum Rewards:** seated, measured payouts (at least one interval and a positive value)
///   and no jailing or equivocation in the window. Weight: the square of the payout as a share of
///   the best payer's in parts per million, rounded down, at least 1, so that one very large
///   payer does not flatten the weights of the others. At most two picks per declared operator;
///   validators that declare no operator form one group. Picks that top the selection up from
///   Diversity never give a declared operator a third pick either.
/// - **Support Newcomers:** ranked within the last 10 seats or below the cutoff, registered for
///   at least 7 days, complete declarations, no penalty ever, and at least 95 % of assigned slots
///   forged when there is a production record from earlier seated time. Weight
///   `100,000 / (10 + distance)`, at least 1, where the distance counts the ranks between the
///   validator and the cutoff (0 for the last seat and the first rank below it).
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
                    // The best payout is the largest among eligible validators, so the share is
                    // at most one million.
                    let of_best = mul_div(payouts.per_unit_weight, PAYOUT_SCALE, best_payout)
                        .min(u128::from(PAYOUT_SCALE));
                    reasons.push(Reason::MeasuredPayouts {
                        per_unit_weight: payouts.per_unit_weight,
                        intervals: payouts.intervals,
                        of_best_ppm: u32::try_from(of_best).unwrap_or(u32::MAX),
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
                        // At least 1, so that a healthy validator far below the cutoff stays
                        // eligible (with the least weight) rather than dropping out unexplained.
                        (NEWCOMER_SCALE * NEWCOMER_HALF_DISTANCE
                            / (NEWCOMER_HALF_DISTANCE + u128::from(distance)))
                        .max(1)
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
/// to compare and a label to show. For the operator, hosting provider and region, id 0 is the
/// group of validators that declare no value, with the label `None`; a rank band's id is its
/// index (see [`Bands`]).
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

/// [`RANK_BAND_SIZE`] as a length.
const BAND_SIZE: usize = RANK_BAND_SIZE as usize;

/// Diversity's rank bands over one snapshot. The validators that meet Diversity's criteria, in
/// rank order (validators without a rank last, then by name), are split into
/// `⌈n / RANK_BAND_SIZE⌉` bands: the validator at position `i`, from 0, is in band
/// `⌊i × bands / n⌋`, so band sizes differ by at most one. A validator outside the pool is in the
/// band of the position it would take.
#[derive(Debug)]
pub(crate) struct Bands {
    /// The pool's ranks and names, in rank order.
    order: Vec<(Option<u32>, String)>,
    /// Each band's label.
    labels: Vec<Option<String>>,
}

/// The rank order of the bands: rank ascending, validators without a rank last, then names in
/// byte order.
fn rank_key(rank: Option<u32>, name: &str) -> (bool, u32, &[u8]) {
    (rank.is_none(), rank.unwrap_or(0), name.as_bytes())
}

/// A band's label from its members in rank order: `first to last` by rank, `first and below`
/// when it includes validators without a rank, `None` when none of them has one.
fn band_label(members: &[(Option<u32>, String)]) -> Option<String> {
    let first = members.first()?.0?;
    Some(match members.last()?.0 {
        Some(last) => format!("{first} to {last}"),
        None => format!("{first} and below"),
    })
}

impl Bands {
    /// The bands of Diversity's pool.
    pub(crate) fn new<'a>(pool: impl IntoIterator<Item = &'a ValidatorRecord>) -> Bands {
        let mut order: Vec<(Option<u32>, String)> = pool
            .into_iter()
            .map(|record| (record.rank, record.name.clone()))
            .collect();
        order.sort_by(|a, b| rank_key(a.0, &a.1).cmp(&rank_key(b.0, &b.1)));
        let n = order.len();
        let count = n.div_ceil(BAND_SIZE);
        let labels = (0..count)
            .map(|band| {
                let start = (band * n).div_ceil(count);
                let end = ((band + 1) * n).div_ceil(count);
                order.get(start..end).and_then(band_label)
            })
            .collect();
        Bands { order, labels }
    }

    /// The band of a validator.
    pub(crate) fn band(&self, record: &ValidatorRecord) -> usize {
        let n = self.order.len();
        if n == 0 {
            return 0;
        }
        let key = rank_key(record.rank, &record.name);
        let position = self
            .order
            .partition_point(|(rank, name)| rank_key(*rank, name) < key)
            .min(n - 1);
        position * self.labels.len() / n
    }

    /// A band's label, as [`Reason::Group`] shows it.
    pub(crate) fn label(&self, band: usize) -> Option<String> {
        self.labels.get(band).cloned().flatten()
    }
}

/// Numbers the declared values of each dimension as it meets them, so that one selection
/// compares groups by number, and places validators in their rank bands.
#[derive(Debug)]
pub(crate) struct Interner<'b> {
    ids: [BTreeMap<String, usize>; 3],
    bands: &'b Bands,
}

impl<'b> Interner<'b> {
    /// An interner over the snapshot's rank bands.
    pub(crate) fn new(bands: &'b Bands) -> Interner<'b> {
        Interner {
            ids: Default::default(),
            bands,
        }
    }

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
        let band = self.bands.band(record);
        let mut ids = [0, 0, 0, band];
        let keys = [operator_key, hosting_key, region.clone()];
        for ((id, map), key) in ids.iter_mut().zip(self.ids.iter_mut()).zip(keys) {
            if let Some(key) = key {
                let next = map.len() + 1;
                *id = *map.entry(key).or_insert(next);
            }
        }
        Groups {
            ids,
            labels: [
                operator_label,
                hosting_label,
                region,
                self.bands.label(band),
            ],
        }
    }
}

/// Group counts over the picks made so far, for Diversity's weights.
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

    /// The most picks so far that share one declared operator, one declared hosting provider and
    /// one region: the common value's picks in each of those dimensions.
    pub(crate) fn most(&self) -> [u32; 3] {
        let mut most = [0; 3];
        for (m, counts) in most.iter_mut().zip(&self.counts) {
            *m = counts.iter().skip(1).copied().max().unwrap_or(0);
        }
        most
    }

    /// The Diversity weight of a candidate, with `most` from [`Spread::most`]:
    ///
    /// ```text
    /// ⌊ ⌊2^64 / (1 + r)⌋ × (1 + (b_operator + b_hosting + b_region) / 3) ⌋
    /// ```
    ///
    /// where `r` counts the picks so far in the candidate's rank band, and each `b` is
    /// `(m - s) / m` for a declared value that `s` picks so far share while the common value of
    /// that dimension has `m > 0` picks, else 0. The sum is an exact fraction and the product is
    /// rounded down once, so a candidate whose values are all common, or undeclared, weighs
    /// exactly `⌊2^64 / (1 + r)⌋`, and none weighs more than twice that.
    pub(crate) fn weight(&self, groups: &Groups, most: [u32; 3]) -> u128 {
        let [operator, hosting, region, band] = self.shared(groups);
        let base = DIVERSITY_WEIGHT / (1 + u128::from(band));
        // 1 + Σ b / 3 as numerator / denominator; the denominator stays below (3 × 54)^3.
        let (mut numerator, mut denominator) = (1u128, 1u128);
        for ((shared, common), &id) in [operator, hosting, region]
            .into_iter()
            .zip(most)
            .zip(&groups.ids)
        {
            if id == 0 || common == 0 {
                continue;
            }
            let (shared, common) = (u128::from(shared), u128::from(common));
            numerator = numerator * 3 * common + common.saturating_sub(shared) * denominator;
            denominator *= 3 * common;
        }
        base * numerator / denominator
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Declarations, ValidatorStatus};

    fn record(name: &str, rank: Option<u32>) -> ValidatorRecord {
        ValidatorRecord {
            name: name.to_owned(),
            address: format!("addr-{name}"),
            rank,
            seated: true,
            status: ValidatorStatus::Active,
            registered_height: Some(1),
            seated_days_in_window: Some(30),
            vote_weight: 1,
            voters: 1,
            production: None,
            penalties: None,
            declarations: None,
            payouts: None,
            self_funded_weight_bp: None,
        }
    }

    fn declaring(name: &str, operator: &str, hosting: &str, country: &str) -> ValidatorRecord {
        ValidatorRecord {
            declarations: Some(Declarations {
                operator: Some(operator.to_owned()),
                hosting: Some(hosting.to_owned()),
                country: Some(country.to_owned()),
                complete: true,
            }),
            ..record(name, Some(1))
        }
    }

    #[test]
    fn bands_split_the_pool_evenly() {
        for n in 1..=160u32 {
            let records: Vec<ValidatorRecord> = (1..=n)
                .map(|rank| record(&format!("v{rank}"), Some(rank)))
                .collect();
            let bands = Bands::new(&records);
            let count = usize::try_from(n.div_ceil(RANK_BAND_SIZE)).unwrap();
            let mut sizes = vec![0u32; count];
            for r in &records {
                sizes[bands.band(r)] += 1;
            }
            let (small, large) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
            assert!(
                large - small <= 1 && *large <= RANK_BAND_SIZE,
                "{n}: {sizes:?}"
            );
        }
        // 41 validators: five bands of 9, 8, 8, 8 and 8, not four of 10 and one of 1.
        let records: Vec<ValidatorRecord> = (1..=41)
            .map(|rank| record(&format!("v{rank}"), Some(rank)))
            .collect();
        let bands = Bands::new(&records);
        let labels: Vec<Option<String>> = (0..5).map(|b| bands.label(b)).collect();
        assert_eq!(
            labels,
            ["1 to 9", "10 to 17", "18 to 25", "26 to 33", "34 to 41"].map(|l| Some(l.to_owned()))
        );
    }

    #[test]
    fn bands_place_outsiders_and_unranked_validators() {
        let mut records: Vec<ValidatorRecord> = (1..=20)
            .map(|rank| record(&format!("v{rank}"), Some(rank * 2)))
            .collect();
        records.push(record("zz", None));
        records.push(record("za", None));
        let bands = Bands::new(&records);
        // 22 validators: three bands of 8, 7 and 7; the unranked ones come last, by name.
        assert_eq!(bands.label(0), Some("2 to 16".to_owned()));
        assert_eq!(bands.label(1), Some("18 to 30".to_owned()));
        assert_eq!(bands.label(2), Some("32 and below".to_owned()));
        assert_eq!(bands.band(&record("za", None)), 2);
        // An outsider with an odd rank takes the band of the position it would have.
        assert_eq!(bands.band(&record("x", Some(17))), 1);
        assert_eq!(bands.band(&record("x", Some(1))), 0);
        assert_eq!(bands.band(&record("x", Some(u32::MAX))), 2);
        let unranked: Vec<ValidatorRecord> = vec![record("a", None), record("b", None)];
        let bands = Bands::new(&unranked);
        assert_eq!(bands.label(0), None);
        let empty = Bands::new(&[]);
        assert_eq!(empty.band(&record("a", Some(3))), 0);
        assert_eq!(empty.label(0), None);
    }

    #[test]
    fn declarations_raise_a_weight_at_most_twofold() {
        let pool = [
            declaring("a", "North", "Hostco", "DE"),
            declaring("b", "North", "Hostco", "FR"),
            declaring("c", "South", "Metalbox", "BR"),
            record("d", Some(1)),
        ];
        let bands = Bands::new(&pool);
        let mut interner = Interner::new(&bands);
        let groups: Vec<Groups> = pool.iter().map(|r| interner.groups(r)).collect();
        let mut spread = Spread::default();
        let base = DIVERSITY_WEIGHT;
        // Before any pick every value is common.
        for g in &groups {
            assert_eq!(spread.weight(g, spread.most()), base);
        }
        spread.add(&groups[0]);
        let most = spread.most();
        assert_eq!(most, [1, 1, 1]);
        // "b" shares operator, hosting provider and region (Germany and France are both in
        // Europe) with the pick, and its rank band: all common.
        assert_eq!(spread.weight(&groups[1], most), base / 2);
        // "c" shares nothing declared: twice the weight of a common one.
        assert_eq!(spread.weight(&groups[2], most), base);
        assert_eq!(
            spread.weight(&groups[2], most),
            2 * spread.weight(&groups[1], most)
        );
        // Undeclared values are common, never a bonus.
        assert_eq!(spread.weight(&groups[3], most), base / 2);
        // Graded: with Hostco at 2 picks, a hosting provider at 1 pick earns half its bonus.
        spread.add(&groups[1]);
        spread.add(&groups[2]);
        let most = spread.most();
        assert_eq!(most, [2, 2, 2]);
        let fresh = declaring("e", "West", "Metalbox", "US");
        let fresh = interner.groups(&fresh);
        // Three picks in its band: base / 4; bonuses 1, 1/2 and 1: a factor of 11/6.
        assert_eq!(spread.weight(&fresh, most), base / 4 * 11 / 6);
    }
}
