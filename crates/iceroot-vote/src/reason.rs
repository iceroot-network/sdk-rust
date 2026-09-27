//! Why a validator was picked, and why one does not meet a mode's criteria.

use core::fmt;

use crate::mode::Mode;
use crate::snapshot::ValidatorStatus;

/// A grouping that Diversity spreads a vote across.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    /// The declared operator.
    Operator,
    /// The declared hosting provider.
    Hosting,
    /// The region of the declared country.
    Region,
    /// The rank band: ranks 1 to 10, 11 to 20 and so on.
    RankBand,
}

impl Dimension {
    /// Every dimension, in the order reasons list them.
    pub const ALL: [Dimension; 4] = [
        Dimension::Operator,
        Dimension::Hosting,
        Dimension::Region,
        Dimension::RankBand,
    ];

    const fn noun(self) -> &'static str {
        match self {
            Dimension::Operator => "operator",
            Dimension::Hosting => "hosting provider",
            Dimension::Region => "region",
            Dimension::RankBand => "rank band",
        }
    }
}

/// One reason a validator was picked or meets a mode's criteria, with the values the review
/// screen shows. [`fmt::Display`] gives a plain English sentence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reason {
    /// How the pick was drawn: at which step, among how many candidates, and with which weight
    /// against the total weight at that step.
    Drawn {
        /// The mode whose pool the pick came from (Diversity for a top-up pick).
        pool: Mode,
        /// The step, from 1.
        step: u32,
        /// Candidates left at that step.
        candidates: u32,
        /// The validator's weight at that step.
        weight: u128,
        /// The total weight of the candidates at that step.
        total_weight: u128,
    },
    /// The pick tops up a selection whose mode gave too few picks.
    TopUp {
        /// The selection's mode.
        mode: Mode,
        /// Picks the mode gave: every eligible validator, or fewer when the Maximum Rewards
        /// operator cap held some back.
        mode_picks: u32,
    },
    /// The validator's status and rank.
    Status {
        /// Registration status.
        status: ValidatorStatus,
        /// Rank, if any.
        rank: Option<u32>,
        /// Whether it holds a seat.
        seated: bool,
    },
    /// Slots forged against slots assigned.
    Production {
        /// Slots forged.
        forged: u64,
        /// Slots assigned.
        assigned: u64,
        /// Whether the counts are lifetime counts from a node's relay API instead of the window.
        approximate: bool,
    },
    /// No production record yet.
    NoProductionRecord,
    /// No jailing or equivocation in the window.
    NoPenaltiesInWindow,
    /// No jailing or equivocation ever.
    NoPenaltiesEver,
    /// The data source keeps no penalty record.
    NoPenaltyRecord,
    /// Days with a seat in the window.
    SeatedDays {
        /// Days seated.
        days: u32,
    },
    /// Days since registration.
    RegisteredDays {
        /// Days registered.
        days: u64,
    },
    /// Every required declaration is present.
    DeclarationsComplete,
    /// A Diversity grouping: the validator's value and how many earlier picks share it.
    Group {
        /// The grouping.
        dimension: Dimension,
        /// The declared operator, hosting provider or region, or the rank band (for example
        /// `41 to 50`); `None` for the one group of validators that declared nothing, or that
        /// have no rank.
        value: Option<String>,
        /// Earlier picks in the same group.
        earlier_picks: u32,
    },
    /// Measured payouts per unit of vote weight.
    MeasuredPayouts {
        /// The measured value.
        per_unit_weight: u128,
        /// Payout intervals measured.
        intervals: u32,
        /// The value as a share of the best payer's, in basis points.
        of_best_bp: u16,
    },
    /// Picks from the same declared operator, against the cap.
    OperatorPicks {
        /// The declared operator, or `None` for the group of undeclared operators.
        operator: Option<String>,
        /// Picks from this operator including this one.
        picks: u32,
        /// The cap.
        maximum: u32,
    },
    /// Distance from the seat cutoff.
    NearCutoff {
        /// The validator's rank.
        rank: u32,
        /// The number of seats.
        seats: u32,
    },
    /// The share of the vote weight from accounts the validator's account funded directly.
    SelfFundedWeight {
        /// The share in basis points.
        basis_points: u16,
    },
    /// The holder chose this validator.
    ChosenByHolder,
}

/// One criterion a validator fails. [`fmt::Display`] gives a plain English sentence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Shortfall {
    /// The validator is not in the snapshot any more.
    NotInSnapshot,
    /// The validator resigned.
    Resigned {
        /// How.
        status: ValidatorStatus,
    },
    /// Jailed or equivocated in the window.
    PenalizedInWindow {
        /// Jailed in the window.
        jailed: bool,
        /// Equivocated in the window.
        equivocation: bool,
    },
    /// Jailed or equivocated at some time.
    PenalizedEver,
    /// Forged less than the minimum share of its assigned slots.
    LowProduction {
        /// Slots forged.
        forged: u64,
        /// Slots assigned.
        assigned: u64,
        /// The minimum, in basis points.
        minimum_bp: u16,
    },
    /// No production record, which the mode needs.
    NoProductionRecord,
    /// Too few days with a seat in the window.
    TooFewSeatedDays {
        /// Days seated, if known.
        days: Option<u32>,
        /// The minimum.
        minimum: u32,
    },
    /// Registered too recently, or the registration height is unknown.
    RegisteredTooRecently {
        /// Days registered, if known.
        days: Option<u64>,
        /// The minimum.
        minimum: u32,
    },
    /// Declarations missing or incomplete.
    DeclarationsIncomplete,
    /// No payouts measured.
    NoMeasuredPayouts,
    /// Holds no seat, so it earns nothing to share.
    NotSeated,
    /// Has no rank.
    NoRank,
    /// Seated well above the cutoff.
    NotNearCutoff {
        /// The rank.
        rank: u32,
        /// The number of seats.
        seats: u32,
    },
    /// More picks from this operator than the cap.
    OperatorCap {
        /// The declared operator, or `None` for the group of undeclared operators.
        operator: Option<String>,
        /// The cap.
        maximum: u32,
    },
}

/// A share in basis points, shown as a percentage with two decimals, for example `99.50 %`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Percent(pub(crate) u128);

impl fmt::Display for Percent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02} %", Grouped(self.0 / 100), self.0 % 100)
    }
}

/// An integer with thousands separators, for example `12,345`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Grouped(pub(crate) u128);

impl fmt::Display for Grouped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.0.to_string();
        let mut out = String::with_capacity(digits.len() + digits.len() / 3);
        for (index, digit) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index).is_multiple_of(3) {
                out.push(',');
            }
            out.push(digit);
        }
        f.write_str(&out)
    }
}

/// `part / whole` in basis points, rounded down; zero when `whole` is zero.
pub(crate) fn basis_points_of(part: u128, whole: u128) -> u128 {
    if whole == 0 {
        return 0;
    }
    match part.checked_mul(10_000) {
        Some(scaled) => scaled / whole,
        None => part / (whole / 10_000).max(1),
    }
}

fn ordinal_rank(rank: Option<u32>) -> String {
    match rank {
        Some(rank) => format!("rank {rank}"),
        None => "no rank".to_owned(),
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Drawn {
                pool,
                step,
                candidates,
                weight,
                total_weight,
            } => write!(
                f,
                "Drawn at step {step} from the {pool} pool of {candidates} candidates, with a {} chance",
                Percent(basis_points_of(*weight, *total_weight)),
            ),
            Reason::TopUp { mode, mode_picks } => write!(
                f,
                "Added from Diversity because the {mode} criteria give only {mode_picks} picks"
            ),
            Reason::Status {
                status,
                rank,
                seated,
            } => {
                let seat = if *seated { "seated" } else { "not seated" };
                write!(f, "Status {status}, {}, {seat}", ordinal_rank(*rank))
            }
            Reason::Production {
                forged,
                assigned,
                approximate,
            } => {
                let share = Percent(basis_points_of(u128::from(*forged), u128::from(*assigned)));
                if *approximate {
                    write!(
                        f,
                        "Forged {share} of its slots over its lifetime ({} of {}); the node reports no 30-day figures",
                        Grouped(u128::from(*forged)),
                        Grouped(u128::from(*assigned))
                    )
                } else {
                    write!(
                        f,
                        "Forged {share} of its assigned slots in the last 30 days ({} of {})",
                        Grouped(u128::from(*forged)),
                        Grouped(u128::from(*assigned))
                    )
                }
            }
            Reason::NoProductionRecord => f.write_str("No production record yet"),
            Reason::NoPenaltiesInWindow => {
                f.write_str("Not jailed and no equivocation in the last 30 days")
            }
            Reason::NoPenaltiesEver => f.write_str("Never jailed and never equivocated"),
            Reason::NoPenaltyRecord => {
                f.write_str("This network keeps no penalty record, so none is counted")
            }
            Reason::SeatedDays { days } => {
                write!(f, "Seated on {days} of the last 30 days")
            }
            Reason::RegisteredDays { days } => {
                write!(f, "Registered {} days ago", Grouped(u128::from(*days)))
            }
            Reason::DeclarationsComplete => f.write_str("Declarations complete"),
            Reason::Group {
                dimension,
                value,
                earlier_picks,
            } => {
                let noun = dimension.noun();
                let what = match (dimension, value) {
                    (Dimension::RankBand, Some(band)) => format!("rank band {band}"),
                    (Dimension::RankBand, None) => "no rank".to_owned(),
                    (_, Some(value)) => format!("{noun} {value}"),
                    (_, None) => format!("{noun} not declared"),
                };
                match earlier_picks {
                    0 => write!(f, "First pick with {what}"),
                    1 => write!(f, "Shares {what} with 1 earlier pick"),
                    n => write!(f, "Shares {what} with {n} earlier picks"),
                }
            }
            Reason::MeasuredPayouts {
                per_unit_weight,
                intervals,
                of_best_bp,
            } => write!(
                f,
                "Measured payouts of {} per unit of vote weight over {intervals} intervals, {} of the best payer's; past payouts are not a promise",
                Grouped(*per_unit_weight),
                Percent(u128::from(*of_best_bp))
            ),
            Reason::OperatorPicks {
                operator,
                picks,
                maximum,
            } => match operator {
                Some(operator) => write!(
                    f,
                    "Pick {picks} of at most {maximum} from operator {operator}"
                ),
                None => write!(
                    f,
                    "Pick {picks} of at most {maximum} from validators that declare no operator"
                ),
            },
            Reason::NearCutoff { rank, seats } => {
                if rank <= seats {
                    write!(
                        f,
                        "Rank {rank}, within {} of the last seat ({seats})",
                        seats - rank
                    )
                } else {
                    write!(
                        f,
                        "Rank {rank}, {} below the last seat ({seats})",
                        rank - seats
                    )
                }
            }
            Reason::SelfFundedWeight { basis_points } => write!(
                f,
                "{} of its vote weight comes from accounts its own account funded",
                Percent(u128::from(*basis_points))
            ),
            Reason::ChosenByHolder => f.write_str("Chosen by the holder"),
        }
    }
}

impl fmt::Display for Shortfall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shortfall::NotInSnapshot => f.write_str("No longer a registered validator"),
            Shortfall::Resigned { status } => write!(f, "Validator {status}"),
            Shortfall::PenalizedInWindow {
                jailed,
                equivocation,
            } => match (jailed, equivocation) {
                (true, true) => f.write_str("Jailed and equivocated in the last 30 days"),
                (true, false) => f.write_str("Jailed in the last 30 days"),
                _ => f.write_str("Equivocated in the last 30 days"),
            },
            Shortfall::PenalizedEver => f.write_str("Jailed or equivocated in the past"),
            Shortfall::LowProduction {
                forged,
                assigned,
                minimum_bp,
            } => write!(
                f,
                "Forged {} of its assigned slots ({} of {}); at least {} is needed",
                Percent(basis_points_of(u128::from(*forged), u128::from(*assigned))),
                Grouped(u128::from(*forged)),
                Grouped(u128::from(*assigned)),
                Percent(u128::from(*minimum_bp))
            ),
            Shortfall::NoProductionRecord => f.write_str("No production record"),
            Shortfall::TooFewSeatedDays { days, minimum } => match days {
                Some(days) => write!(
                    f,
                    "Seated on {days} of the last 30 days; at least {minimum} are needed"
                ),
                None => write!(f, "Seated days unknown; at least {minimum} are needed"),
            },
            Shortfall::RegisteredTooRecently { days, minimum } => match days {
                Some(days) => write!(
                    f,
                    "Registered {days} days ago; at least {minimum} days are needed"
                ),
                None => write!(
                    f,
                    "Registration date unknown; at least {minimum} days are needed"
                ),
            },
            Shortfall::DeclarationsIncomplete => f.write_str("Declarations missing or incomplete"),
            Shortfall::NoMeasuredPayouts => f.write_str("No payouts measured"),
            Shortfall::NotSeated => f.write_str("Holds no seat, so it earns nothing to share"),
            Shortfall::NoRank => f.write_str("Has no rank"),
            Shortfall::NotNearCutoff { rank, seats } => {
                write!(f, "Rank {rank} is not near the last seat ({seats})")
            }
            Shortfall::OperatorCap { operator, maximum } => match operator {
                Some(operator) => write!(f, "More than {maximum} picks from operator {operator}"),
                None => write!(
                    f,
                    "More than {maximum} picks from validators that declare no operator"
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(Grouped(0).to_string(), "0");
        assert_eq!(Grouped(999).to_string(), "999");
        assert_eq!(Grouped(1_000).to_string(), "1,000");
        assert_eq!(Grouped(12_345_678).to_string(), "12,345,678");
        assert_eq!(Percent(9_950).to_string(), "99.50 %");
        assert_eq!(Percent(5).to_string(), "0.05 %");
        assert_eq!(Percent(10_000).to_string(), "100.00 %");
        assert_eq!(basis_points_of(1, 3), 3_333);
        assert_eq!(basis_points_of(1, 0), 0);
        assert_eq!(basis_points_of(u128::MAX, u128::MAX), 10_000);
    }

    #[test]
    fn sentences() {
        let reason = Reason::Group {
            dimension: Dimension::RankBand,
            value: Some("41 to 50".to_owned()),
            earlier_picks: 2,
        };
        assert_eq!(
            reason.to_string(),
            "Shares rank band 41 to 50 with 2 earlier picks"
        );
        let reason = Reason::Group {
            dimension: Dimension::Hosting,
            value: None,
            earlier_picks: 0,
        };
        assert_eq!(
            reason.to_string(),
            "First pick with hosting provider not declared"
        );
        assert_eq!(
            Reason::NearCutoff {
                rank: 50,
                seats: 53
            }
            .to_string(),
            "Rank 50, within 3 of the last seat (53)"
        );
        assert_eq!(
            Shortfall::LowProduction {
                forged: 94,
                assigned: 100,
                minimum_bp: 9_500
            }
            .to_string(),
            "Forged 94.00 % of its assigned slots (94 of 100); at least 95.00 % is needed"
        );
    }
}
