//! The validator data a selection is computed from.

use core::fmt;

use serde_json::{Value, json};

use crate::rules::is_solar_compatible_name;

/// The length of the rolling window, in days, that windowed data covers.
pub const WINDOW_DAYS: u32 = 30;

/// The election interval in rounds: the network checks its election every 24 rounds, and a round
/// has one block per seat, so the interval is 24 × 53 = 1,272 blocks on IceRoot. Selections are
/// seeded with the snapshot's height rounded down to a multiple of it (see
/// [`VoteSnapshot::election_height`]).
pub const ELECTION_INTERVAL_ROUNDS: u32 = 24;

/// Seconds in a day.
const SECONDS_PER_DAY: u64 = 86_400;

/// Where a snapshot's data comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotSource {
    /// An indexer that keeps windowed production, penalties, declarations and measured payouts.
    Indexer,
    /// A node's relay API, which has only lifetime counters: production comes from the lifetime
    /// produced and missed block counts and, for a validator seated now, seated days from the
    /// first forged block (unknown for any other validator that forged), and there are no
    /// declarations, payouts or penalties. Every selection made from it records this.
    RelayApproximate,
}

impl SnapshotSource {
    /// The stable identifier: `indexer` or `relay-approximate`.
    pub const fn id(self) -> &'static str {
        match self {
            SnapshotSource::Indexer => "indexer",
            SnapshotSource::RelayApproximate => "relay-approximate",
        }
    }

    /// The source for a stable identifier (see [`SnapshotSource::id`]).
    pub fn from_id(id: &str) -> Option<SnapshotSource> {
        [SnapshotSource::Indexer, SnapshotSource::RelayApproximate]
            .into_iter()
            .find(|source| source.id() == id)
    }
}

/// A validator's registration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorStatus {
    /// Registered and holding a seat.
    Active,
    /// Registered, not resigned, without a seat.
    Standby,
    /// Resigned for now; the validator can come back, and its account still cannot vote.
    ResignedTemporary,
    /// Resigned for good; the account is an ordinary account again and may vote.
    ResignedPermanent,
}

impl ValidatorStatus {
    /// The stable identifier: `active`, `standby`, `resigned-temporary` or `resigned-permanent`.
    pub const fn id(self) -> &'static str {
        match self {
            ValidatorStatus::Active => "active",
            ValidatorStatus::Standby => "standby",
            ValidatorStatus::ResignedTemporary => "resigned-temporary",
            ValidatorStatus::ResignedPermanent => "resigned-permanent",
        }
    }

    /// The status for a stable identifier (see [`ValidatorStatus::id`]).
    pub fn from_id(id: &str) -> Option<ValidatorStatus> {
        [
            ValidatorStatus::Active,
            ValidatorStatus::Standby,
            ValidatorStatus::ResignedTemporary,
            ValidatorStatus::ResignedPermanent,
        ]
        .into_iter()
        .find(|status| status.id() == id)
    }

    /// Whether the validator has resigned, for now or for good.
    pub const fn is_resigned(self) -> bool {
        matches!(
            self,
            ValidatorStatus::ResignedTemporary | ValidatorStatus::ResignedPermanent
        )
    }
}

impl fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ValidatorStatus::Active => "active",
            ValidatorStatus::Standby => "standby",
            ValidatorStatus::ResignedTemporary => "resigned for now",
            ValidatorStatus::ResignedPermanent => "resigned for good",
        })
    }
}

/// Block production over the window: slots forged against slots assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Production {
    /// Slots in which the validator forged a block.
    pub forged: u64,
    /// Slots assigned to the validator.
    pub assigned: u64,
}

impl Production {
    /// Whether the validator forged at least `basis_points` / 10,000 of its assigned slots. Exact
    /// integer comparison, no rounding.
    pub fn at_least(self, basis_points: u16) -> bool {
        u128::from(self.forged) * 10_000 >= u128::from(self.assigned) * u128::from(basis_points)
    }

    /// Slots assigned and not forged.
    pub fn missed(self) -> u64 {
        self.assigned.saturating_sub(self.forged)
    }
}

/// Penalties from the chain's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Penalties {
    /// Jailed at some point in the window.
    pub jailed_in_window: bool,
    /// Proven to have equivocated at some point in the window.
    pub equivocation_in_window: bool,
    /// Jailed or proven to have equivocated at any time, window included.
    pub ever: bool,
}

impl Penalties {
    /// Whether any penalty falls in the window.
    pub const fn in_window(self) -> bool {
        self.jailed_in_window || self.equivocation_in_window
    }

    /// Whether any penalty was ever recorded.
    pub const fn any(self) -> bool {
        self.ever || self.in_window()
    }
}

/// A validator's own declarations, parsed from its declaration memo. They are statements, not
/// verified facts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Declarations {
    /// The declared operator: the person or organisation running the validator.
    pub operator: Option<String>,
    /// The declared hosting provider.
    pub hosting: Option<String>,
    /// The declared country, an ISO 3166-1 alpha-2 code; it gives the region.
    pub country: Option<String>,
    /// Whether every required declaration is present.
    pub complete: bool,
}

/// Payouts to voters as the indexer measures them, never as declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payouts {
    /// Measured payouts per unit of vote weight over the window, in a fixed unit that is the same
    /// for every validator of a snapshot. The library only compares these values.
    pub per_unit_weight: u128,
    /// Payout intervals measured in the window.
    pub intervals: u32,
}

/// One validator's data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatorRecord {
    /// The validator's name, which a vote names.
    pub name: String,
    /// The validator's account address.
    pub address: String,
    /// The validator's rank by vote weight (1 is first), or `None` when it has none, as for a
    /// resigned validator.
    pub rank: Option<u32>,
    /// Whether the validator holds a seat.
    pub seated: bool,
    /// Registration status.
    pub status: ValidatorStatus,
    /// The height of the registration, or `None` when the source does not report it.
    pub registered_height: Option<u64>,
    /// Days with a seat in the window, or `None` when unknown.
    pub seated_days_in_window: Option<u32>,
    /// Vote weight in base units.
    pub vote_weight: u128,
    /// Number of accounts voting for the validator.
    pub voters: u32,
    /// Production over the window, or `None` when unknown.
    pub production: Option<Production>,
    /// Penalties, or `None` when the source keeps no penalty record.
    pub penalties: Option<Penalties>,
    /// Declarations, or `None` when the validator declared nothing or the source has none.
    pub declarations: Option<Declarations>,
    /// Measured payouts, or `None` when none were measured.
    pub payouts: Option<Payouts>,
    /// The share of the vote weight, in basis points, from accounts funded directly by the
    /// validator's account, or `None` when unknown. Shown on the review screen.
    pub self_funded_weight_bp: Option<u16>,
}

impl ValidatorRecord {
    /// Whole days from `registered_height` to the snapshot's height, or `None` when unknown.
    pub fn registered_days(&self, snapshot: &VoteSnapshot) -> Option<u64> {
        let registered = self.registered_height?;
        Some(snapshot.days_between(registered, snapshot.height))
    }
}

/// The input of every selection: validator data at one height.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteSnapshot {
    /// The height the data describes. Rounded down to its election interval, it is part of the
    /// selection seed (see [`VoteSnapshot::election_height`]).
    pub height: u64,
    /// The window of the windowed data, in days; must be [`WINDOW_DAYS`].
    pub window_days: u32,
    /// The number of seats: the active set, which also sets the length of a round.
    pub seats: u32,
    /// The target block time, in seconds, to turn heights into days.
    pub block_time_seconds: u32,
    /// Where the data comes from.
    pub source: SnapshotSource,
    /// One record per registered validator, in any order.
    pub records: Vec<ValidatorRecord>,
}

/// Why a snapshot cannot be used. Its code is `InvalidSnapshot` ([`SnapshotError::code`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SnapshotError {
    /// The window is not [`WINDOW_DAYS`] days.
    Window {
        /// The snapshot's window.
        days: u32,
    },
    /// The snapshot has no seats.
    NoSeats,
    /// The block time is zero.
    NoBlockTime,
    /// A name is not a validator name.
    InvalidName {
        /// The name.
        name: String,
    },
    /// Two records have the same name.
    DuplicateName {
        /// The name.
        name: String,
    },
    /// Two records have the same address.
    DuplicateAddress {
        /// The address.
        address: String,
    },
    /// A record's values contradict each other or the snapshot.
    Inconsistent {
        /// The validator.
        name: String,
        /// What is wrong.
        field: &'static str,
    },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Window { days } => {
                write!(f, "the snapshot covers {days} days, not {WINDOW_DAYS}")
            }
            SnapshotError::NoSeats => f.write_str("the snapshot has no seats"),
            SnapshotError::NoBlockTime => f.write_str("the snapshot has no block time"),
            SnapshotError::InvalidName { name } => write!(f, "{name:?} is not a validator name"),
            SnapshotError::DuplicateName { name } => {
                write!(f, "the snapshot names {name} twice")
            }
            SnapshotError::DuplicateAddress { address } => {
                write!(f, "the snapshot lists address {address} twice")
            }
            SnapshotError::Inconsistent { name, field } => {
                write!(f, "the record of {name} has an inconsistent {field}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

impl SnapshotError {
    /// The stable code of the error, as the TypeScript and Go SDKs report it: `InvalidSnapshot`
    /// for every problem, which [`SnapshotError::as_str`] names.
    pub const fn code(&self) -> &'static str {
        "InvalidSnapshot"
    }

    /// A stable string for the problem: `window`, `no-seats`, `no-block-time`, `name`,
    /// `duplicate-name`, `duplicate-address` or `inconsistent`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            SnapshotError::Window { .. } => "window",
            SnapshotError::NoSeats => "no-seats",
            SnapshotError::NoBlockTime => "no-block-time",
            SnapshotError::InvalidName { .. } => "name",
            SnapshotError::DuplicateName { .. } => "duplicate-name",
            SnapshotError::DuplicateAddress { .. } => "duplicate-address",
            SnapshotError::Inconsistent { .. } => "inconsistent",
        }
    }

    /// The structured details of the error, as a JSON object: `reason` ([`SnapshotError::as_str`])
    /// and the problem's values, `days`, `name`, `address`, or `name` and `field` for an
    /// inconsistent record, where `field` is the record's field as the TypeScript SDK names it
    /// (`production`, `seatedDaysInWindow`, `registeredHeight`, `selfFundedWeightBp` or
    /// `status`). The keys of each reason are part of the API.
    pub fn details(&self) -> Value {
        let reason = self.as_str();
        match self {
            SnapshotError::Window { days } => json!({ "reason": reason, "days": days }),
            SnapshotError::NoSeats | SnapshotError::NoBlockTime => json!({ "reason": reason }),
            SnapshotError::InvalidName { name } | SnapshotError::DuplicateName { name } => {
                json!({ "reason": reason, "name": name })
            }
            SnapshotError::DuplicateAddress { address } => {
                json!({ "reason": reason, "address": address })
            }
            SnapshotError::Inconsistent { name, field } => {
                let field = match *field {
                    "seated days" => "seatedDaysInWindow",
                    "registration height" => "registeredHeight",
                    "self-funded share" => "selfFundedWeightBp",
                    other => other,
                };
                json!({ "reason": reason, "name": name, "field": field })
            }
        }
    }
}

impl VoteSnapshot {
    /// Check that the snapshot can be used: a 30-day window, seats and a block time, unique valid
    /// names and unique addresses, and consistent records (forged at most assigned, seated days
    /// within the window, registration not after the snapshot, shares at most 10,000 basis
    /// points, resigned validators without a seat).
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.window_days != WINDOW_DAYS {
            return Err(SnapshotError::Window {
                days: self.window_days,
            });
        }
        if self.seats == 0 {
            return Err(SnapshotError::NoSeats);
        }
        if self.block_time_seconds == 0 {
            return Err(SnapshotError::NoBlockTime);
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.records.len());
        let mut addresses: Vec<&str> = Vec::with_capacity(self.records.len());
        for record in &self.records {
            if !is_solar_compatible_name(&record.name) {
                return Err(SnapshotError::InvalidName {
                    name: record.name.clone(),
                });
            }
            let inconsistent = |field| SnapshotError::Inconsistent {
                name: record.name.clone(),
                field,
            };
            if record.production.is_some_and(|p| p.forged > p.assigned) {
                return Err(inconsistent("production"));
            }
            if record
                .seated_days_in_window
                .is_some_and(|days| days > self.window_days)
            {
                return Err(inconsistent("seated days"));
            }
            if record
                .registered_height
                .is_some_and(|height| height > self.height)
            {
                return Err(inconsistent("registration height"));
            }
            if record.self_funded_weight_bp.is_some_and(|bp| bp > 10_000) {
                return Err(inconsistent("self-funded share"));
            }
            if record.status.is_resigned() && record.seated {
                return Err(inconsistent("status"));
            }
            names.push(&record.name);
            addresses.push(&record.address);
        }
        names.sort_unstable();
        if let Some(name) = first_repeat(&names) {
            return Err(SnapshotError::DuplicateName {
                name: name.to_owned(),
            });
        }
        addresses.sort_unstable();
        if let Some(address) = first_repeat(&addresses) {
            return Err(SnapshotError::DuplicateAddress {
                address: address.to_owned(),
            });
        }
        Ok(())
    }

    /// The record with this name.
    pub fn record(&self, name: &str) -> Option<&ValidatorRecord> {
        self.records.iter().find(|record| record.name == name)
    }

    /// Whether an account may vote: [`Voter::Validator`] when the address belongs to a validator
    /// that has not resigned for good, else [`Voter::Ordinary`].
    pub fn voter(&self, address: &str) -> Voter {
        let is_validator = self.records.iter().any(|record| {
            record.address == address && record.status != ValidatorStatus::ResignedPermanent
        });
        if is_validator {
            Voter::Validator
        } else {
            Voter::Ordinary
        }
    }

    /// The height a selection's seed uses: the snapshot's height rounded down to a multiple of the
    /// election interval, [`ELECTION_INTERVAL_ROUNDS`] rounds of `seats` blocks (1,272 blocks with
    /// 53 seats). Every snapshot within one interval seeds the same draw, so whoever supplies the
    /// snapshot can choose between whole intervals only, not among every recent height. The
    /// supplier is still trusted for the height and the seats, as for the rest of the snapshot's
    /// data. The height itself when the snapshot has no seats.
    pub fn election_height(&self) -> u64 {
        let interval = u64::from(ELECTION_INTERVAL_ROUNDS) * u64::from(self.seats);
        self.height - self.height.checked_rem(interval).unwrap_or(0)
    }

    /// Whole days between two heights at the snapshot's block time (zero when `to` is not after
    /// `from`).
    pub fn days_between(&self, from: u64, to: u64) -> u64 {
        let seconds = u128::from(to.saturating_sub(from)) * u128::from(self.block_time_seconds);
        u64::try_from(seconds / u128::from(SECONDS_PER_DAY)).unwrap_or(u64::MAX)
    }

    /// Build a snapshot from a node's relay data, marked [`SnapshotSource::RelayApproximate`].
    ///
    /// Production is the lifetime produced blocks against produced plus missed; the status follows
    /// the resignation and the rank against the seats. Seated days are known only for a validator
    /// seated now, as the days since its first forged block, at most the window, and zero for a
    /// validator that never forged. A validator not seated now that forged at some time has
    /// unknown seated days, since relay data keeps no seat history: one seat held for a single
    /// election interval would otherwise count as a whole window of seated days, and its perfect
    /// lifetime counters would lead Reliability. There are no declarations, payouts, penalties or
    /// self-funded shares.
    pub fn from_relay(relay: RelaySnapshot) -> VoteSnapshot {
        let RelaySnapshot {
            height,
            seats,
            block_time_seconds,
            validators,
        } = relay;
        let mut snapshot = VoteSnapshot {
            height,
            window_days: WINDOW_DAYS,
            seats,
            block_time_seconds,
            source: SnapshotSource::RelayApproximate,
            records: Vec::with_capacity(validators.len()),
        };
        for validator in validators {
            let status = match validator.resignation {
                Some(Resignation::Temporary) => ValidatorStatus::ResignedTemporary,
                Some(Resignation::Permanent) => ValidatorStatus::ResignedPermanent,
                None if validator
                    .rank
                    .is_some_and(|rank| rank >= 1 && rank <= seats) =>
                {
                    ValidatorStatus::Active
                }
                None => ValidatorStatus::Standby,
            };
            let production = validator.missed_blocks.and_then(|missed| {
                let assigned = validator.produced_blocks.saturating_add(missed);
                (assigned > 0).then_some(Production {
                    forged: validator.produced_blocks,
                    assigned,
                })
            });
            let never_forged =
                validator.produced_blocks == 0 && validator.first_forged_height.is_none();
            let seated_days_in_window = match validator.first_forged_height {
                _ if never_forged => Some(0),
                // No seat history: the days since a first forged block count only for a
                // validator that holds a seat now.
                _ if status != ValidatorStatus::Active => None,
                Some(first) => {
                    let days = snapshot.days_between(first, height);
                    Some(u32::try_from(days).unwrap_or(u32::MAX).min(WINDOW_DAYS))
                }
                None => None,
            };
            snapshot.records.push(ValidatorRecord {
                name: validator.name,
                address: validator.address,
                rank: validator.rank,
                seated: status == ValidatorStatus::Active,
                status,
                registered_height: validator.registered_height,
                seated_days_in_window,
                vote_weight: validator.vote_weight,
                voters: validator.voters,
                production,
                penalties: None,
                declarations: None,
                payouts: None,
                self_funded_weight_bp: None,
            });
        }
        snapshot
    }
}

/// The first value of a sorted list that equals the next one.
fn first_repeat<'a>(sorted: &[&'a str]) -> Option<&'a str> {
    sorted.windows(2).find_map(|pair| match pair {
        [a, b] if a == b => Some(*a),
        _ => None,
    })
}

/// Whether an account may cast a vote under the rules that forbid validator accounts to vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Voter {
    /// An ordinary account, or a validator's account after it resigned for good.
    Ordinary,
    /// A validator's account, including one resigned for now.
    Validator,
}

/// A resignation, as a node's relay API reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resignation {
    /// Resigned for now.
    Temporary,
    /// Resigned for good.
    Permanent,
}

/// One validator as a node's relay API reports it (its validator list), plus the first forged
/// block and the registration height where the caller looked them up.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayValidator {
    /// The validator's name.
    pub name: String,
    /// The validator's account address.
    pub address: String,
    /// The rank, or `None` when the node reports none.
    pub rank: Option<u32>,
    /// The resignation, if any.
    pub resignation: Option<Resignation>,
    /// Vote weight in base units.
    pub vote_weight: u128,
    /// Number of voters.
    pub voters: u32,
    /// Blocks produced over the validator's lifetime.
    pub produced_blocks: u64,
    /// Blocks missed over the validator's lifetime, or `None` when the node does not report it.
    pub missed_blocks: Option<u64>,
    /// The registration height, or `None` when not looked up.
    pub registered_height: Option<u64>,
    /// The height of the first block the validator forged, or `None` when not looked up or
    /// when it never forged.
    pub first_forged_height: Option<u64>,
}

/// A node's relay data at one height.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelaySnapshot {
    /// The height the data was read at.
    pub height: u64,
    /// The number of seats.
    pub seats: u32,
    /// The target block time in seconds.
    pub block_time_seconds: u32,
    /// Every registered validator.
    pub validators: Vec<RelayValidator>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str) -> ValidatorRecord {
        ValidatorRecord {
            name: name.to_owned(),
            address: format!("addr-{name}"),
            rank: Some(1),
            seated: true,
            status: ValidatorStatus::Active,
            registered_height: Some(1),
            seated_days_in_window: Some(30),
            vote_weight: 1,
            voters: 1,
            production: Some(Production {
                forged: 10,
                assigned: 10,
            }),
            penalties: None,
            declarations: None,
            payouts: None,
            self_funded_weight_bp: None,
        }
    }

    fn snapshot(records: Vec<ValidatorRecord>) -> VoteSnapshot {
        VoteSnapshot {
            height: 100,
            window_days: WINDOW_DAYS,
            seats: 53,
            block_time_seconds: 8,
            source: SnapshotSource::Indexer,
            records,
        }
    }

    #[test]
    fn validation() {
        assert_eq!(snapshot(vec![record("a"), record("b")]).validate(), Ok(()));
        let mut bad = snapshot(vec![record("a"), record("a")]);
        assert!(matches!(
            bad.validate(),
            Err(SnapshotError::DuplicateName { .. })
        ));
        bad.records[1].name = "b".to_owned();
        bad.records[1].address = "addr-a".to_owned();
        assert!(matches!(
            bad.validate(),
            Err(SnapshotError::DuplicateAddress { .. })
        ));
        let mut bad = snapshot(vec![record("a")]);
        bad.window_days = 90;
        assert_eq!(bad.validate(), Err(SnapshotError::Window { days: 90 }));
        let mut bad = snapshot(vec![record("A")]);
        assert!(matches!(
            bad.validate(),
            Err(SnapshotError::InvalidName { .. })
        ));
        bad.records[0].name = "a".to_owned();
        bad.records[0].production = Some(Production {
            forged: 11,
            assigned: 10,
        });
        assert!(matches!(
            bad.validate(),
            Err(SnapshotError::Inconsistent { .. })
        ));
    }

    #[test]
    fn production_threshold_is_exact() {
        let p = Production {
            forged: 95,
            assigned: 100,
        };
        assert!(p.at_least(9_500));
        assert!(!p.at_least(9_501));
        let p = Production {
            forged: 9_499,
            assigned: 10_000,
        };
        assert!(!p.at_least(9_500));
        assert!(
            Production {
                forged: 0,
                assigned: 0
            }
            .at_least(9_500)
        );
    }

    #[test]
    fn election_height_rounds_down_to_the_interval() {
        let mut s = snapshot(Vec::new());
        for (height, start) in [
            (0, 0),
            (1_271, 0),
            (1_272, 1_272),
            (2_543, 1_272),
            (5_000_000, 4_998_960),
            (u64::MAX, u64::MAX - u64::MAX % 1_272),
        ] {
            s.height = height;
            assert_eq!(s.election_height(), start, "{height}");
        }
        // The interval follows the snapshot's seats: 24 rounds of 21 blocks.
        s.seats = 21;
        s.height = 1_000;
        assert_eq!(s.election_height(), 504);
        s.seats = 0;
        assert_eq!(s.election_height(), 1_000);
    }

    #[test]
    fn days() {
        let s = snapshot(Vec::new());
        assert_eq!(s.days_between(0, 10_800), 1);
        assert_eq!(s.days_between(0, 10_799), 0);
        assert_eq!(s.days_between(50, 10), 0);
    }
}
