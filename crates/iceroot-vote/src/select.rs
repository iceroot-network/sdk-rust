//! Drawing a selection.

use core::fmt;

use crate::mode::Mode;
use crate::reason::{Count, Grouped, Reason};
use crate::rules::{
    EMPTY_VOTE_BYTES, TOTAL_BASIS_POINTS, VoteEntry, VoteRules, canonical_cmp, canonical_order,
    entry_bytes,
};
use crate::sample::{Stream, seed};
use crate::score::{Bands, Candidate, Groups, Interner, MAX_PICKS_PER_OPERATOR, Spread, judged};
use crate::snapshot::{SnapshotError, SnapshotSource, ValidatorRecord, VoteSnapshot, Voter};

/// The version of the selection rules. A selection records it; the same version, snapshot,
/// account, mode, number of picks, vote rules and draw number always give the same selection.
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
    /// The number of picks, from [`MIN_PICKS`] to [`MAX_PICKS`]; the selection has fewer when
    /// that many do not fit the vote rules' limits (see [`select`]).
    pub count: u8,
    /// The draw number: 0 first, one more for each "draw again".
    pub draw: u32,
    /// The network's vote rules, whose limits on entries and bytes the selection keeps within.
    pub rules: VoteRules,
}

impl<'a> SelectRequest<'a> {
    /// A first draw of [`DEFAULT_PICKS`] picks under [`VoteRules::ICEROOT`].
    pub const fn new(mode: Mode, account: &'a str) -> SelectRequest<'a> {
        SelectRequest {
            mode,
            account,
            count: DEFAULT_PICKS,
            draw: 0,
            rules: VoteRules::ICEROOT,
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
    /// The number of picks requested; more than the entries when that many did not fit the vote
    /// rules' limits.
    pub requested: u8,
    /// The vote rules the selection keeps within.
    pub rules: VoteRules,
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

    /// The sentence a wallet shows when fewer picks than requested fit the vote rules' limits,
    /// else `None`.
    pub fn size_notice(&self) -> Option<String> {
        let picks = self.entries.len();
        (picks < usize::from(self.requested)).then(|| {
            if picks >= usize::from(self.rules.max_entries) {
                format!(
                    "A vote names at most {} validators, so the selection has {picks} picks, not the {} requested",
                    self.rules.max_entries, self.requested
                )
            } else {
                format!(
                    "Only {picks} of the {} requested picks fit in a vote of at most {} bytes",
                    self.requested,
                    Grouped(u128::from(self.rules.max_bytes))
                )
            }
        })
    }

    /// The sentence a wallet shows when the selection was topped up, else `None`.
    pub fn top_up_notice(&self) -> Option<String> {
        (self.topped_up > 0).then(|| {
            let mode = self.mode;
            if self.pool == 0 {
                return format!(
                    "No validator meets the {mode} criteria, so all {} picks come from Diversity",
                    self.entries.len()
                );
            }
            let topped_up = usize::try_from(self.topped_up).unwrap_or(usize::MAX);
            let from_mode = self.entries.len().saturating_sub(topped_up);
            let capped = if u32::try_from(from_mode).is_ok_and(|n| n < self.pool) {
                format!(", at most {MAX_PICKS_PER_OPERATOR} per operator")
            } else {
                String::new()
            };
            let meet = if self.pool == 1 { "meets" } else { "meet" };
            let come = if from_mode == 1 { "comes" } else { "come" };
            format!(
                "{} {meet} the {mode} criteria{capped}, so {} {come} from {mode} and {} from Diversity",
                Count(u128::from(self.pool), "validator", "validators"),
                Count(u128::try_from(from_mode).unwrap_or(u128::MAX), "pick", "picks"),
                self.topped_up
            )
        })
    }
}

/// Why no selection could be made.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SelectError {
    /// The requested number of picks is outside [`MIN_PICKS`] to [`MAX_PICKS`], or below the vote
    /// rules' fewest entries.
    Count {
        /// The requested number.
        count: u8,
        /// The fewest picks: [`MIN_PICKS`], or the rules' fewest entries when that is more.
        minimum: u8,
        /// The most picks: [`MAX_PICKS`].
        maximum: u8,
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
    /// Fewer picks than the minimum fit within the vote rules' limits on entries and bytes.
    DoesNotFit {
        /// The picks that fit, in draw order.
        fits: u32,
        /// The fewest picks: [`MIN_PICKS`], or the rules' fewest entries when that is more.
        minimum: u8,
        /// The rules' most entries.
        max_entries: u8,
        /// The rules' most bytes.
        max_bytes: u16,
    },
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectError::Count {
                count,
                minimum,
                maximum,
            } => write!(
                f,
                "a selection has {minimum} to {maximum} picks, not {count}"
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
            SelectError::DoesNotFit {
                fits,
                minimum,
                max_entries,
                max_bytes,
            } => {
                if *fits >= u32::from(*max_entries) {
                    write!(
                        f,
                        "a vote names at most {max_entries} validators, and a selection needs at least {minimum}"
                    )
                } else {
                    write!(
                        f,
                        "only {fits} picks fit in a vote of at most {} bytes, and a selection needs at least {minimum}",
                        Grouped(u128::from(*max_bytes))
                    )
                }
            }
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

/// Picks per operator group so far, for the Maximum Rewards cap.
#[derive(Debug, Default)]
struct OperatorPicks(Vec<u32>);

impl OperatorPicks {
    /// Whether the entrant's operator group already has [`MAX_PICKS_PER_OPERATOR`] picks.
    fn full(&self, entrant: &Entrant<'_>) -> bool {
        self.0
            .get(entrant.groups.operator_id())
            .is_some_and(|&n| n >= MAX_PICKS_PER_OPERATOR)
    }

    /// Count a pick of the entrant's operator group; the group's picks so far, this one included.
    fn add(&mut self, entrant: &Entrant<'_>) -> u32 {
        let id = entrant.groups.operator_id();
        if self.0.len() <= id {
            self.0.resize(id + 1, 0);
        }
        self.0.get_mut(id).map_or(1, |n| {
            *n += 1;
            *n
        })
    }

    /// The reason that states the entrant's place under the cap, after [`OperatorPicks::add`].
    fn reason(entrant: &Entrant<'_>, picks: u32) -> Reason {
        Reason::OperatorPicks {
            operator: entrant.groups.operator_label(),
            picks,
            maximum: MAX_PICKS_PER_OPERATOR,
        }
    }
}

/// Draw a selection.
///
/// The seed (see [`seed`](crate::seed)) starts a SHA-256 counter stream. Picks are drawn one at a
/// time without replacement from the mode's pool (see [`evaluate`](crate::evaluate)), candidates
/// in name order: a number `r` below the total weight is taken from the stream by rejection, and
/// the pick is the first candidate whose running sum of weights exceeds `r`. Maximum Rewards
/// drops an operator's validators once it has two picks. When the mode's pool runs out before
/// `count` picks, the rest is drawn the same way from Diversity's pool, with its spread counting
/// every pick so far, and each such pick says so. A Maximum Rewards top-up still gives no declared
/// operator more than two picks in all.
///
/// Diversity recomputes every weight before each draw, spreading picks over rank bands first and
/// declarations second:
///
/// ```text
/// weight = ⌊ ⌊2^64 / (1 + r)⌋ × (1 + (o + h + g) / 3) ⌋
/// ```
///
/// - **Rank bands.** `r` counts the picks so far in the candidate's rank band. Diversity's pool,
///   in rank order (validators without a rank last, then by name), is split into
///   `⌈n / 10⌉` bands whose sizes differ by at most one: the validator at position `i`, from 0,
///   is in band `⌊i × bands / n⌋`. A pick from outside that pool (a Maximum Rewards pick, before a
///   top-up) counts in the band of the position it would take. Ranks are chain data, so this part
///   cannot be declared falsely, and it has no bound.
/// - **Declarations.** `o`, `h` and `g` are the candidate's bonuses for its declared operator,
///   hosting provider and region (from its declared country). In each of these dimensions the
///   common value is the declared value that the most picks so far share, `m` of them; a
///   candidate whose value `s` picks so far share has a bonus of `(m - s) / m`, from 0 for a
///   common value to 1 for a value no pick shares yet. An undeclared value counts as common, and
///   before any pick declares a value every value is common. The sum is an exact fraction and
///   the product is rounded down once, so a candidate weighs from `⌊2^64 / (1 + r)⌋`, when its
///   values are all common or undeclared, to twice that, when no pick shares any of them yet.
///   Declarations are statements, not verified facts: a validator that invents unique values
///   gains at most that factor of two, and one that declares nothing loses at most the same.
///
/// Shares are 10,000 basis points split evenly in whole basis points, one extra to each of the
/// first picks drawn while the remainder lasts, and the entries come in the protocol's canonical
/// order. With 20 to 53 picks every share is at most 500 basis points.
///
/// **Vote rules.** A vote may take at most `rules.max_entries` entries and `rules.max_bytes`
/// bytes (see [`vote_bytes`](crate::vote_bytes)): 1,024 bytes on the Solar-compatible stage,
/// 1,280 from IceRoot's genesis. The selection keeps the longest start of the draw that fits
/// both, so fewer than `count` picks when the names are long; it is then the same selection as
/// one requested with that smaller count, and [`Selection::size_notice`] says so. The draw itself
/// does not depend on the rules, so names of any length have the same chance.
///
/// Refused when `count` is outside 20 to 53 or below the rules' fewest entries, when the snapshot
/// is invalid, when the account is a validator's (one that has not resigned for good), when fewer
/// than `count` validators can be picked at all, and when fewer than 20 picks (or the rules'
/// fewest entries) fit the rules' limits.
pub fn select(
    snapshot: &VoteSnapshot,
    request: &SelectRequest<'_>,
) -> Result<Selection, SelectError> {
    let minimum = MIN_PICKS.max(request.rules.min_entries);
    if !(minimum..=MAX_PICKS).contains(&request.count) {
        return Err(SelectError::Count {
            count: request.count,
            minimum,
            maximum: MAX_PICKS,
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

    // Diversity's pool sets the rank bands, and tops up the other modes.
    let diverse = eligible(snapshot, Mode::Diversity);
    let bands = Bands::new(diverse.iter().map(|(_, record)| *record));
    let mut interner = Interner::new(&bands);
    let (mut pool, fill) = if request.mode == Mode::Diversity {
        (entrants(diverse, &mut interner), Vec::new())
    } else {
        (
            entrants(eligible(snapshot, request.mode), &mut interner),
            diverse,
        )
    };
    let pool_size = u32::try_from(pool.len()).unwrap_or(u32::MAX);
    let mut operators = OperatorPicks::default();
    match request.mode {
        Mode::Diversity => draw_diverse(
            &mut pool,
            count,
            &mut stream,
            &mut spread,
            &mut picks,
            None,
            None,
        ),
        mode => draw_weighted(
            mode,
            &mut pool,
            count,
            &mut stream,
            &mut spread,
            &mut operators,
            &mut picks,
        ),
    }

    let mode_picks = picks.len();
    if picks.len() < count && request.mode != Mode::Diversity {
        let unpicked = fill
            .into_iter()
            .filter(|(_, record)| !picks.iter().any(|p| p.validator == record.name))
            .collect();
        let mut fill = entrants(unpicked, &mut interner);
        let top_up = Reason::TopUp {
            mode: request.mode,
            mode_picks: u32::try_from(mode_picks).unwrap_or(u32::MAX),
        };
        // Top-up picks never take a declared operator past the Maximum Rewards cap.
        let cap = (request.mode == Mode::MaximumRewards).then_some(&mut operators);
        draw_diverse(
            &mut fill,
            count,
            &mut stream,
            &mut spread,
            &mut picks,
            Some(top_up),
            cap,
        );
    }
    if picks.len() < count {
        return Err(SelectError::NotEnoughValidators {
            requested: request.count,
            available: u32::try_from(picks.len()).unwrap_or(u32::MAX),
        });
    }

    // The longest start of the draw that fits the rules' limits.
    let fits = fitting(&picks, &request.rules);
    if fits < usize::from(minimum) {
        return Err(SelectError::DoesNotFit {
            fits: u32::try_from(fits).unwrap_or(u32::MAX),
            minimum,
            max_entries: request.rules.max_entries,
            max_bytes: request.rules.max_bytes,
        });
    }
    picks.truncate(fits);
    let mode_picks = mode_picks.min(fits);

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
        requested: request.count,
        rules: request.rules,
        seed,
        pool: pool_size,
        topped_up: u32::try_from(picks.len() - mode_picks).unwrap_or(u32::MAX),
        entries: picks,
    })
}

/// How many picks, in draw order, fit within the rules' limits on entries and bytes.
fn fitting(picks: &[Pick], rules: &VoteRules) -> usize {
    let mut bytes = EMPTY_VOTE_BYTES;
    for (index, pick) in picks.iter().enumerate() {
        bytes = bytes.saturating_add(entry_bytes(&pick.validator));
        if index >= usize::from(rules.max_entries) || bytes > usize::from(rules.max_bytes) {
            return index;
        }
    }
    picks.len()
}

/// The validators that meet a mode's criteria, with their records, in name order.
fn eligible(snapshot: &VoteSnapshot, mode: Mode) -> Vec<(Candidate, &ValidatorRecord)> {
    judged(snapshot, mode)
        .into_iter()
        .filter(|(candidate, _)| candidate.eligible)
        .collect()
}

/// Eligible validators as entrants of a draw, with their Diversity groups.
fn entrants<'a>(
    eligible: Vec<(Candidate, &'a ValidatorRecord)>,
    interner: &mut Interner<'_>,
) -> Vec<Entrant<'a>> {
    eligible
        .into_iter()
        .map(|(candidate, record)| Entrant {
            groups: interner.groups(record),
            candidate,
            record,
        })
        .collect()
}

/// Draw from `pool` by static weights until `count` picks or the pool is empty. Maximum Rewards
/// skips operator groups with [`MAX_PICKS_PER_OPERATOR`] picks, the group of validators that
/// declare no operator included, and counts its picks in `operators`.
fn draw_weighted(
    mode: Mode,
    pool: &mut Vec<Entrant<'_>>,
    count: usize,
    stream: &mut Stream,
    spread: &mut Spread,
    operators: &mut OperatorPicks,
    picks: &mut Vec<Pick>,
) {
    while picks.len() < count {
        if mode == Mode::MaximumRewards {
            pool.retain(|entrant| !operators.full(entrant));
        }
        let weights: Vec<u128> = pool.iter().map(|e| e.candidate.weight).collect();
        let Some(drawn) = draw(stream, &weights) else {
            return;
        };
        let entrant = pool.remove(drawn.index);
        let step = u32::try_from(picks.len() + 1).unwrap_or(u32::MAX);
        let capped = (mode == Mode::MaximumRewards).then(|| {
            let picked = operators.add(&entrant);
            OperatorPicks::reason(&entrant, picked)
        });
        let mut reasons = entrant.candidate.reasons;
        reasons.extend(capped);
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
/// the pool is empty. `top_up` marks picks that fill another mode's selection. With `cap` (a
/// Maximum Rewards top-up), validators whose declared operator has [`MAX_PICKS_PER_OPERATOR`]
/// picks are skipped; validators that declare no operator are not limited here, as Diversity
/// already spreads them.
fn draw_diverse(
    pool: &mut Vec<Entrant<'_>>,
    count: usize,
    stream: &mut Stream,
    spread: &mut Spread,
    picks: &mut Vec<Pick>,
    top_up: Option<Reason>,
    mut cap: Option<&mut OperatorPicks>,
) {
    while picks.len() < count {
        if let Some(operators) = cap.as_deref() {
            pool.retain(|entrant| !(entrant.groups.operator_declared() && operators.full(entrant)));
        }
        let most = spread.most();
        let weights: Vec<u128> = pool
            .iter()
            .map(|e| spread.weight(&e.groups, most))
            .collect();
        let Some(drawn) = draw(stream, &weights) else {
            return;
        };
        let entrant = pool.remove(drawn.index);
        let step = u32::try_from(picks.len() + 1).unwrap_or(u32::MAX);
        let capped = cap
            .as_deref_mut()
            .filter(|_| entrant.groups.operator_declared())
            .map(|operators| {
                let picked = operators.add(&entrant);
                OperatorPicks::reason(&entrant, picked)
            });
        let mut reasons = Vec::new();
        if let Some(top_up) = &top_up {
            reasons.push(top_up.clone());
        }
        reasons.extend(entrant.candidate.reasons);
        reasons.extend(spread.reasons(&entrant.groups));
        reasons.extend(capped);
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
