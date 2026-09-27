//! Drawing a selection.

use core::fmt;

use crate::mode::Mode;
use crate::reason::Reason;
use crate::rules::{TOTAL_BASIS_POINTS, VoteEntry, canonical_cmp, canonical_order};
use crate::sample::{Stream, seed};
use crate::score::{Candidate, Groups, Interner, MAX_PICKS_PER_OPERATOR, Spread, judged};
use crate::snapshot::{SnapshotError, SnapshotSource, ValidatorRecord, VoteSnapshot, Voter};

/// The version of the selection rules. A selection records it; the same version, snapshot,
/// account, mode and draw number always give the same selection.
pub const LIBRARY_VERSION: &str = "iceroot-vote/1";
/// The fewest picks of a selection, so that no pick exceeds 500 basis points.
pub const MIN_PICKS: u8 = 20;
/// The most picks of a selection, as many as a vote can name.
pub const MAX_PICKS: u8 = 53;
/// The default number of picks: 500 basis points each.
pub const DEFAULT_PICKS: u8 = MIN_PICKS;

/// What to select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelectRequest<'a> {
    /// The mode.
    pub mode: Mode,
    /// The voting account's address; part of the seed.
    pub account: &'a str,
    /// The number of picks, from [`MIN_PICKS`] to [`MAX_PICKS`].
    pub count: u8,
    /// The draw number: 0 first, one more for each "draw again".
    pub draw: u32,
}

impl<'a> SelectRequest<'a> {
    /// A first draw of [`DEFAULT_PICKS`] picks.
    pub const fn new(mode: Mode, account: &'a str) -> SelectRequest<'a> {
        SelectRequest {
            mode,
            account,
            count: DEFAULT_PICKS,
            draw: 0,
        }
    }
}

/// Where a pick came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickSource {
    /// Drawn from the mode's pool.
    Mode,
    /// Drawn from Diversity's pool because the mode's pool was too small.
    TopUp,
    /// Chosen by the holder on the review screen. The library never makes such picks; a wallet
    /// marks the picks the holder changed, so that [`check`](crate::check) judges them only by
    /// their registration.
    Holder,
}

/// One pick of a selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pick {
    /// The validator's name.
    pub validator: String,
    /// Its share, in basis points.
    pub basis_points: u16,
    /// Where it came from.
    pub source: PickSource,
    /// The step at which it was drawn, from 1.
    pub step: u32,
    /// Why it was picked, for the review screen: the criteria it meets, its groups and the draw.
    pub reasons: Vec<Reason>,
}

/// A selection: the picks of one draw, with everything needed to reproduce and explain it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    /// [`LIBRARY_VERSION`] at the time of the draw.
    pub library_version: String,
    /// The mode.
    pub mode: Mode,
    /// The voting account's address.
    pub account: String,
    /// The snapshot's height.
    pub snapshot_height: u64,
    /// The snapshot's source; [`SnapshotSource::RelayApproximate`] means production figures are
    /// lifetime counts.
    pub snapshot_source: SnapshotSource,
    /// The draw number.
    pub draw: u32,
    /// The seed (see [`seed`](crate::seed)).
    pub seed: [u8; 32],
    /// Validators that met the mode's criteria.
    pub pool: u32,
    /// Picks added from Diversity because the mode's pool was too small.
    pub topped_up: u32,
    /// The picks, in the protocol's canonical order.
    pub entries: Vec<Pick>,
}

impl Selection {
    /// The vote to sign: the picks' names and shares, in the canonical order.
    pub fn vote(&self) -> Vec<VoteEntry> {
        let mut entries: Vec<VoteEntry> = self
            .entries
            .iter()
            .map(|pick| VoteEntry {
                validator: pick.validator.clone(),
                basis_points: pick.basis_points,
            })
            .collect();
        entries.sort_by(canonical_order);
        entries
    }

    /// The seed in lowercase hexadecimal.
    pub fn seed_hex(&self) -> String {
        self.seed.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The sentence a wallet shows when the selection was topped up, else `None`.
    pub fn top_up_notice(&self) -> Option<String> {
        (self.topped_up > 0).then(|| {
            let topped_up = usize::try_from(self.topped_up).unwrap_or(usize::MAX);
            let from_mode = self.entries.len().saturating_sub(topped_up);
            let capped = if u32::try_from(from_mode).is_ok_and(|n| n < self.pool) {
                format!(", at most {MAX_PICKS_PER_OPERATOR} per operator")
            } else {
                String::new()
            };
            format!(
                "{} validators meet the {} criteria{capped}, so {from_mode} picks come from {} and {} from Diversity",
                self.pool, self.mode, self.mode, self.topped_up
            )
        })
    }
}

/// Why no selection could be made.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SelectError {
    /// The requested number of picks is outside [`MIN_PICKS`] to [`MAX_PICKS`].
    Count {
        /// The requested number.
        count: u8,
    },
    /// The account belongs to a validator, and validator accounts cannot vote.
    ValidatorAccount,
    /// The snapshot cannot be used.
    Snapshot(SnapshotError),
    /// The mode's pool and Diversity's together have fewer validators than requested.
    NotEnoughValidators {
        /// The requested number of picks.
        requested: u8,
        /// Validators available.
        available: u32,
    },
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectError::Count { count } => write!(
                f,
                "a selection has {MIN_PICKS} to {MAX_PICKS} picks, not {count}"
            ),
            SelectError::ValidatorAccount => f.write_str("a validator's account cannot vote"),
            SelectError::Snapshot(error) => error.fmt(f),
            SelectError::NotEnoughValidators {
                requested,
                available,
            } => write!(
                f,
                "only {available} validators can be picked, and {requested} were requested"
            ),
        }
    }
}

impl std::error::Error for SelectError {}

impl From<SnapshotError> for SelectError {
    fn from(error: SnapshotError) -> SelectError {
        SelectError::Snapshot(error)
    }
}

/// A validator the draw can pick.
struct Entrant<'a> {
    candidate: Candidate,
    record: &'a ValidatorRecord,
    groups: Groups,
}

/// Draw a selection.
///
/// The seed (see [`seed`](crate::seed)) starts a SHA-256 counter stream. Picks are drawn one at a
/// time without replacement from the mode's pool (see [`evaluate`](crate::evaluate)), candidates
/// in name order: a number `r` below the total weight is taken from the stream by rejection, and
/// the pick is the first candidate whose running sum of weights exceeds `r`. Diversity recomputes
/// every weight before each draw; Maximum Rewards drops an operator's validators once it has two
/// picks. When the mode's pool runs out before `count` picks, the rest is drawn the same way
/// from Diversity's pool, with its spread counting every pick so far, and each such pick says so.
///
/// Shares are 10,000 basis points split evenly in whole basis points, one extra to each of the
/// first picks drawn while the remainder lasts, and the entries come in the protocol's canonical
/// order. With 20 to 53 picks every share is at most 500 basis points.
///
/// Refused when `count` is outside 20 to 53, when the snapshot is invalid, when the account is a
/// validator's (one that has not resigned for good), and when fewer than `count` validators can
/// be picked at all.
pub fn select(
    snapshot: &VoteSnapshot,
    request: &SelectRequest<'_>,
) -> Result<Selection, SelectError> {
    if !(MIN_PICKS..=MAX_PICKS).contains(&request.count) {
        return Err(SelectError::Count {
            count: request.count,
        });
    }
    snapshot.validate()?;
    if snapshot.voter(request.account) == Voter::Validator {
        return Err(SelectError::ValidatorAccount);
    }
    let count = usize::from(request.count);
    let seed = seed(request.account, request.mode, snapshot.height, request.draw);
    let mut stream = Stream::new(seed);
    let mut spread = Spread::default();
    let mut picks: Vec<Pick> = Vec::with_capacity(count);

    let mut interner = Interner::default();
    let mut pool = entrants(snapshot, request.mode, &mut interner);
    let pool_size = u32::try_from(pool.len()).unwrap_or(u32::MAX);
    match request.mode {
        Mode::Diversity => {
            draw_diverse(&mut pool, count, &mut stream, &mut spread, &mut picks, None)
        }
        mode => draw_weighted(mode, &mut pool, count, &mut stream, &mut spread, &mut picks),
    }

    let mode_picks = picks.len();
    if picks.len() < count && request.mode != Mode::Diversity {
        let mut fill: Vec<Entrant<'_>> = entrants(snapshot, Mode::Diversity, &mut interner)
            .into_iter()
            .filter(|entrant| !picks.iter().any(|p| p.validator == entrant.record.name))
            .collect();
        let top_up = Reason::TopUp {
            mode: request.mode,
            mode_picks: u32::try_from(mode_picks).unwrap_or(u32::MAX),
        };
        draw_diverse(
            &mut fill,
            count,
            &mut stream,
            &mut spread,
            &mut picks,
            Some(top_up),
        );
    }
    if picks.len() < count {
        return Err(SelectError::NotEnoughValidators {
            requested: request.count,
            available: u32::try_from(picks.len()).unwrap_or(u32::MAX),
        });
    }

    // Even shares in draw order, one extra basis point to each of the first picks while the
    // remainder lasts (as `split` does), then the canonical order.
    let n = u16::try_from(picks.len()).unwrap_or(u16::from(MAX_PICKS));
    let share = TOTAL_BASIS_POINTS / n;
    let extra = usize::from(TOTAL_BASIS_POINTS % n);
    for (index, pick) in picks.iter_mut().enumerate() {
        pick.basis_points = share + u16::from(index < extra);
    }
    picks.sort_by(|a, b| {
        canonical_cmp(
            (a.basis_points, &a.validator),
            (b.basis_points, &b.validator),
        )
    });
    Ok(Selection {
        library_version: LIBRARY_VERSION.to_owned(),
        mode: request.mode,
        account: request.account.to_owned(),
        snapshot_height: snapshot.height,
        snapshot_source: snapshot.source,
        draw: request.draw,
        seed,
        pool: pool_size,
        topped_up: u32::try_from(picks.len() - mode_picks).unwrap_or(u32::MAX),
        entries: picks,
    })
}

/// The eligible validators of a mode, in name order.
fn entrants<'a>(
    snapshot: &'a VoteSnapshot,
    mode: Mode,
    interner: &mut Interner,
) -> Vec<Entrant<'a>> {
    judged(snapshot, mode)
        .into_iter()
        .filter(|(candidate, _)| candidate.eligible)
        .map(|(candidate, record)| Entrant {
            groups: interner.groups(record),
            candidate,
            record,
        })
        .collect()
}

/// Draw from `pool` by static weights until `count` picks or the pool is empty. Maximum Rewards
/// skips operators with [`MAX_PICKS_PER_OPERATOR`] picks.
fn draw_weighted(
    mode: Mode,
    pool: &mut Vec<Entrant<'_>>,
    count: usize,
    stream: &mut Stream,
    spread: &mut Spread,
    picks: &mut Vec<Pick>,
) {
    // Picks per operator group id.
    let mut operator_picks: Vec<u32> = Vec::new();
    let picks_of = |operator_picks: &[u32], entrant: &Entrant<'_>| {
        operator_picks
            .get(entrant.groups.operator_id())
            .copied()
            .unwrap_or(0)
    };
    while picks.len() < count {
        if mode == Mode::MaximumRewards {
            pool.retain(|entrant| picks_of(&operator_picks, entrant) < MAX_PICKS_PER_OPERATOR);
        }
        let weights: Vec<u128> = pool.iter().map(|e| e.candidate.weight).collect();
        let Some(drawn) = draw(stream, &weights) else {
            return;
        };
        let entrant = pool.remove(drawn.index);
        let step = u32::try_from(picks.len() + 1).unwrap_or(u32::MAX);
        let mut reasons = entrant.candidate.reasons;
        if mode == Mode::MaximumRewards {
            let id = entrant.groups.operator_id();
            if operator_picks.len() <= id {
                operator_picks.resize(id + 1, 0);
            }
            let picked = operator_picks.get_mut(id).map_or(1, |n| {
                *n += 1;
                *n
            });
            reasons.push(Reason::OperatorPicks {
                operator: entrant.groups.operator_label(),
                picks: picked,
                maximum: MAX_PICKS_PER_OPERATOR,
            });
        }
        reasons.push(Reason::Drawn {
            pool: mode,
            step,
            candidates: u32::try_from(weights.len()).unwrap_or(u32::MAX),
            weight: drawn.weight,
            total_weight: drawn.total,
        });
        spread.add(&entrant.groups);
        picks.push(Pick {
            validator: entrant.record.name.clone(),
            basis_points: 0,
            source: PickSource::Mode,
            step,
            reasons,
        });
    }
}

/// Draw from `pool` by Diversity weights, recomputed before each draw, until `count` picks or
/// the pool is empty. `top_up` marks picks that fill another mode's selection.
fn draw_diverse(
    pool: &mut Vec<Entrant<'_>>,
    count: usize,
    stream: &mut Stream,
    spread: &mut Spread,
    picks: &mut Vec<Pick>,
    top_up: Option<Reason>,
) {
    while picks.len() < count {
        let weights: Vec<u128> = pool.iter().map(|e| spread.weight(&e.groups)).collect();
        let Some(drawn) = draw(stream, &weights) else {
            return;
        };
        let entrant = pool.remove(drawn.index);
        let step = u32::try_from(picks.len() + 1).unwrap_or(u32::MAX);
        let mut reasons = Vec::new();
        if let Some(top_up) = &top_up {
            reasons.push(top_up.clone());
        }
        reasons.extend(entrant.candidate.reasons);
        reasons.extend(spread.reasons(&entrant.groups));
        reasons.push(Reason::Drawn {
            pool: Mode::Diversity,
            step,
            candidates: u32::try_from(weights.len()).unwrap_or(u32::MAX),
            weight: drawn.weight,
            total_weight: drawn.total,
        });
        spread.add(&entrant.groups);
        picks.push(Pick {
            validator: entrant.record.name.clone(),
            basis_points: 0,
            source: if top_up.is_some() {
                PickSource::TopUp
            } else {
                PickSource::Mode
            },
            step,
            reasons,
        });
    }
}

/// The outcome of one weighted draw.
struct Drawn {
    /// The index of the pick.
    index: usize,
    /// Its weight.
    weight: u128,
    /// The total weight of the candidates.
    total: u128,
}

/// One weighted draw, or `None` when no candidate has weight.
fn draw(stream: &mut Stream, weights: &[u128]) -> Option<Drawn> {
    let total = weights
        .iter()
        .try_fold(0u128, |sum, &w| sum.checked_add(w))
        .unwrap_or(u128::MAX);
    if total == 0 {
        return None;
    }
    let target = stream.below(total);
    let mut running = 0u128;
    for (index, &weight) in weights.iter().enumerate() {
        running = running.saturating_add(weight);
        if running > target {
            return Some(Drawn {
                index,
                weight,
                total,
            });
        }
    }
    None
}
