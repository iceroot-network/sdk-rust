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
    /// The rank band: Diversity's pool in rank order, split into bands of equal size, give or
    /// take one validator (see [`RANK_BAND_SIZE`](crate::RANK_BAND_SIZE)).
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
        /// The declared operator, hosting provider or region, or the rank band by its first and
        /// last rank (for example `37 to 45`, or `73 and below` for a band that includes
        /// validators without a rank); `None` for the one group of validators that declared
        /// nothing, or for a band of validators without a rank.
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
        /// The value as a share of the best payer's, in parts per million, rounded down.
        of_best_ppm: u32,
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

/// A number and its noun, singular for one: `1 pick`, `2 picks`, `1,000 days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Count(
    pub(crate) u128,
    pub(crate) &'static str,
    pub(crate) &'static str,
);

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Count(n, one, many) = *self;
        write!(f, "{} {}", Grouped(n), if n == 1 { one } else { many })
    }
}

/// The chance of a draw, `weight / total`: a percentage with two decimals, or `under 0.01 %`
/// for a chance that is not zero but rounds down to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Chance(u128, u128);

impl fmt::Display for Chance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Chance(weight, total) = *self;
        match basis_points_of(weight, total) {
            0 if weight > 0 => f.write_str("under 0.01 %"),
            basis_points => Percent(basis_points).fmt(f),
        }
    }
}

/// A share in parts per million, shown as a percentage with two decimals, or `under 0.01 %` for
/// a share that is not zero but rounds down to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartsPerMillion(u32);

impl fmt::Display for PartsPerMillion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 / 100 {
            0 if self.0 > 0 => f.write_str("under 0.01 %"),
            basis_points => Percent(u128::from(basis_points)).fmt(f),
        }
    }
}

/// A value a validator declared, shown in quotes with control, invisible and direction
/// characters escaped, so that it reads as the validator's statement and cannot rearrange the
/// sentence around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Declared<'a>(&'a str);

impl fmt::Display for Declared<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// `part / whole` in basis points, rounded down; zero when `whole` is zero.
pub(crate) fn basis_points_of(part: u128, whole: u128) -> u128 {
    mul_div(part, 10_000, whole)
}

/// `⌊a × b / c⌋`, exact for every input: the product is formed in 256 bits. Zero when `c` is
/// zero; `u128::MAX` when the quotient does not fit.
pub(crate) fn mul_div(a: u128, b: u64, c: u128) -> u128 {
    if c == 0 {
        return 0;
    }
    let b = u128::from(b);
    if let Some(product) = a.checked_mul(b) {
        return product / c;
    }
    // a × b = high × 2^128 + low, from a = a1 × 2^64 + a0.
    let (a1, a0) = (a >> 64, a & u128::from(u64::MAX));
    let (middle, low) = (a1 * b, a0 * b);
    let (low, carry) = low.overflowing_add(middle << 64);
    let high = (middle >> 64) + u128::from(carry);
    if high >= c {
        return u128::MAX;
    }
    // Long division, one bit at a time; the remainder stays below c.
    let (mut remainder, mut quotient) = (high, 0u128);
    for bit in (0..128).rev() {
        let overflow = remainder >> 127 == 1;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        quotient <<= 1;
        if overflow || remainder >= c {
            remainder = remainder.wrapping_sub(c);
            quotient |= 1;
        }
    }
    quotient
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
                "Drawn at step {step} from the {pool} pool of {}, with a chance of {}",
                Count(u128::from(*candidates), "candidate", "candidates"),
                Chance(*weight, *total_weight),
            ),
            Reason::TopUp {
                mode,
                mode_picks: 0,
            } => write!(
                f,
                "Added from Diversity because no validator meets the {mode} criteria"
            ),
            Reason::TopUp { mode, mode_picks } => write!(
                f,
                "Added from Diversity because the {mode} criteria give only {}",
                Count(u128::from(*mode_picks), "pick", "picks")
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
                write!(
                    f,
                    "Registered {} ago",
                    Count(u128::from(*days), "day", "days")
                )
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
                    // The region comes from the library's table; the others are declared.
                    (Dimension::Region, Some(region)) => format!("{noun} {region}"),
                    (_, Some(value)) => format!("{noun} {}", Declared(value)),
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
                of_best_ppm,
            } => write!(
                f,
                "Measured payouts of {} per unit of vote weight over {}, {} of the best payer's; past payouts are not a promise",
                Grouped(*per_unit_weight),
                Count(u128::from(*intervals), "interval", "intervals"),
                PartsPerMillion(*of_best_ppm)
            ),
            Reason::OperatorPicks {
                operator,
                picks,
                maximum,
            } => match operator {
                Some(operator) => write!(
                    f,
                    "Pick {picks} of at most {maximum} from operator {}",
                    Declared(operator)
                ),
                None => write!(
                    f,
                    "Pick {picks} of at most {maximum} from validators that declare no operator"
                ),
            },
            Reason::NearCutoff { rank, seats } => {
                if rank == seats {
                    write!(f, "Rank {rank}, the last seat")
                } else if rank < seats {
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
                Some(0) => write!(
                    f,
                    "Registered less than a day ago; at least {minimum} days are needed"
                ),
                Some(days) => write!(
                    f,
                    "Registered {} ago; at least {minimum} days are needed",
                    Count(u128::from(*days), "day", "days")
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
                Some(operator) => write!(
                    f,
                    "More than {maximum} picks from operator {}",
                    Declared(operator)
                ),
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
    fn exact_ratios() {
        // Small values against plain arithmetic.
        for (a, b, c) in [
            (1u128, 3u64, 7u128),
            (999, 1_000_000, 1_000),
            (0, 5, 9),
            (7, 0, 3),
        ] {
            assert_eq!(mul_div(a, b, c), a * u128::from(b) / c);
        }
        assert_eq!(mul_div(5, 5, 0), 0);
        // Products beyond 128 bits.
        assert_eq!(mul_div(u128::MAX, 1_000_000, u128::MAX), 1_000_000);
        assert_eq!(mul_div(u128::MAX - 1, 1_000_000, u128::MAX), 999_999);
        // (2^128 - 1) / 2 rounds down to 2^127 - 1, just under a half.
        assert_eq!(mul_div(u128::MAX / 2, 1_000_000, u128::MAX), 499_999);
        assert_eq!(mul_div(1 << 127, 1_000_000, 1 << 127), 1_000_000);
        assert_eq!(mul_div(1 << 127, 4, 1 << 126), 8);
        assert_eq!(
            mul_div(u128::MAX, u64::MAX, u128::from(u64::MAX)),
            u128::MAX
        );
        assert_eq!(mul_div(u128::MAX, 2, 1), u128::MAX);
        // The ratio of two values an order of magnitude apart, at every size.
        for shift in 0..124 {
            let whole = 10u128 << shift;
            assert_eq!(mul_div(1 << shift, 1_000_000, whole), 100_000, "{shift}");
        }
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

    #[test]
    fn one_zero_and_tiny_values() {
        let drawn = |candidates, weight, total_weight| {
            Reason::Drawn {
                pool: Mode::MaximumRewards,
                step: 20,
                candidates,
                weight,
                total_weight,
            }
            .to_string()
        };
        assert_eq!(
            drawn(1, 7, 7),
            "Drawn at step 20 from the Maximum Rewards pool of 1 candidate, with a chance of 100.00 %"
        );
        // A chance that rounds down to zero is not shown as zero.
        assert_eq!(
            drawn(40, 1, 3_000_000_000),
            "Drawn at step 20 from the Maximum Rewards pool of 40 candidates, with a chance of under 0.01 %"
        );
        assert_eq!(
            Reason::TopUp {
                mode: Mode::Reliability,
                mode_picks: 0
            }
            .to_string(),
            "Added from Diversity because no validator meets the Reliability criteria"
        );
        assert_eq!(
            Reason::TopUp {
                mode: Mode::Reliability,
                mode_picks: 1
            }
            .to_string(),
            "Added from Diversity because the Reliability criteria give only 1 pick"
        );
        assert_eq!(
            Reason::NearCutoff {
                rank: 53,
                seats: 53
            }
            .to_string(),
            "Rank 53, the last seat"
        );
        assert_eq!(
            Reason::MeasuredPayouts {
                per_unit_weight: 4_800,
                intervals: 1,
                of_best_ppm: 960_000
            }
            .to_string(),
            "Measured payouts of 4,800 per unit of vote weight over 1 interval, 96.00 % of the best payer's; past payouts are not a promise"
        );
        // A payer far below the best is not shown as paying nothing.
        assert_eq!(
            Reason::MeasuredPayouts {
                per_unit_weight: 5,
                intervals: 30,
                of_best_ppm: 50
            }
            .to_string(),
            "Measured payouts of 5 per unit of vote weight over 30 intervals, under 0.01 % of the best payer's; past payouts are not a promise"
        );
        assert_eq!(
            Reason::RegisteredDays { days: 1_000 }.to_string(),
            "Registered 1,000 days ago"
        );
        for (days, text) in [
            (
                Some(0),
                "Registered less than a day ago; at least 7 days are needed",
            ),
            (Some(1), "Registered 1 day ago; at least 7 days are needed"),
            (Some(6), "Registered 6 days ago; at least 7 days are needed"),
            (
                None,
                "Registration date unknown; at least 7 days are needed",
            ),
        ] {
            let shortfall = Shortfall::RegisteredTooRecently { days, minimum: 7 };
            assert_eq!(shortfall.to_string(), text);
        }
    }

    #[test]
    fn declared_values_are_quoted_and_cannot_rearrange_a_sentence() {
        let group = |dimension, value: &str| {
            Reason::Group {
                dimension,
                value: Some(value.to_owned()),
                earlier_picks: 1,
            }
            .to_string()
        };
        assert_eq!(
            group(Dimension::Operator, "Polar Systems"),
            "Shares operator \"Polar Systems\" with 1 earlier pick"
        );
        assert_eq!(
            group(Dimension::Hosting, "Fjordhost"),
            "Shares hosting provider \"Fjordhost\" with 1 earlier pick"
        );
        // The region and the rank band come from the library, not from the validator.
        assert_eq!(
            group(Dimension::Region, "Europe"),
            "Shares region Europe with 1 earlier pick"
        );
        // Line breaks, direction overrides and invisible characters are shown escaped.
        let text = group(
            Dimension::Operator,
            "Nodes\nForged 100.00 % \u{202e}evil\u{200b}",
        );
        assert_eq!(
            text,
            "Shares operator \"Nodes\\nForged 100.00 % \\u{202e}evil\\u{200b}\" with 1 earlier pick"
        );
        assert!(!text.contains('\n') && !text.contains('\u{202e}') && !text.contains('\u{200b}'));
        assert_eq!(
            Reason::OperatorPicks {
                operator: Some("Frostline".to_owned()),
                picks: 2,
                maximum: 2
            }
            .to_string(),
            "Pick 2 of at most 2 from operator \"Frostline\""
        );
        assert_eq!(
            Shortfall::OperatorCap {
                operator: Some("Frostline".to_owned()),
                maximum: 2
            }
            .to_string(),
            "More than 2 picks from operator \"Frostline\""
        );
        // Non-ASCII letters stay as they are.
        assert_eq!(
            group(Dimension::Operator, "Ñandú Nodes"),
            "Shares operator \"Ñandú Nodes\" with 1 earlier pick"
        );
    }
}
