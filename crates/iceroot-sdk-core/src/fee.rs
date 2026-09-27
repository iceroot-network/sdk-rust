//! Fees: the caller's choice, the node's statistics and the resolved fee of a draft.
//!
//! A draft always carries an explicit fee, never a milestone's static default. Its source is
//! recorded ([`FeeSource`]) so that a review screen can say where the number comes from:
//!
//! - [`FeeChoice::Exact`]: the caller's fee, as given.
//! - [`FeeChoice::Minimum`] (the default): the exact fee floor of the milestone in force for the
//!   transaction's type and size, when the SDK can compute it. Until it can, the fee comes from
//!   the node's fee statistics for the operation (the largest fee paid recently), and without
//!   statistics the choice fails with [`Error::FeeUnavailable`]; an exact fee still works.
//! - [`FeeChoice::Multiplier`]: the minimum scaled up, in basis points (15,000 is 1.5 times).

use heartwood_crypto::managers::Params;
use heartwood_crypto::validation::MAX_AMOUNT;

use crate::amount::Amount;
use crate::error::Error;
use crate::transaction::OperationKind;

/// Whether this build computes the exact fee floor ([`floor`]).
pub(crate) const FLOOR_AVAILABLE: bool = false;

/// The exact fee floor of a transaction of `kind` that is `size` bytes long, signatures included,
/// under `params`; `None` while this build cannot compute it.
///
/// This is the one place the floor is computed. It is to call the floor function of
/// `heartwood-crypto`, which is the node's own rule; the SDK never keeps a copy of the formula.
pub(crate) fn floor(kind: OperationKind, size: usize, params: &Params) -> Option<u64> {
    let _ = (kind, size, params);
    None
}

/// How the fee of a draft is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FeeChoice {
    /// The lowest fee the network accepts (see the module documentation).
    #[default]
    Minimum,
    /// This fee.
    Exact(Amount),
    /// The minimum times `basis_points / 10000`, rounded up; at least 10,000 basis points.
    Multiplier {
        /// The factor in basis points: 10,000 is the minimum itself.
        basis_points: u32,
    },
}

/// The fees a node saw for one operation recently, in base units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeeFigures {
    /// The smallest fee.
    pub minimum: Amount,
    /// The average fee.
    pub average: Amount,
    /// The largest fee.
    pub maximum: Amount,
}

/// A node's fee statistics, per operation (the relay API's `/node/fees`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeeStatistics {
    entries: Vec<(OperationKind, FeeFigures)>,
}

impl FeeStatistics {
    /// No statistics.
    pub fn new() -> FeeStatistics {
        FeeStatistics::default()
    }

    /// Set the figures of `kind`.
    pub fn insert(&mut self, kind: OperationKind, figures: FeeFigures) {
        match self.entries.iter_mut().find(|(entry, _)| *entry == kind) {
            Some((_, existing)) => *existing = figures,
            None => self.entries.push((kind, figures)),
        }
    }

    /// The figures of `kind`, if the node reported any.
    pub fn get(&self, kind: OperationKind) -> Option<&FeeFigures> {
        self.entries
            .iter()
            .find(|(entry, _)| *entry == kind)
            .map(|(_, figures)| figures)
    }
}

/// Where a draft's fee comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeeSource {
    /// The exact fee floor of the milestone in force.
    Floor,
    /// The node's fee statistics.
    NodeStatistics,
    /// The caller's exact fee.
    Explicit,
}

impl FeeSource {
    /// The stable string form: `floor`, `node-statistics` or `explicit`.
    pub const fn as_str(self) -> &'static str {
        match self {
            FeeSource::Floor => "floor",
            FeeSource::NodeStatistics => "node-statistics",
            FeeSource::Explicit => "explicit",
        }
    }

    /// The source with the string form `text`.
    pub fn parse(text: &str) -> Option<FeeSource> {
        [
            FeeSource::Floor,
            FeeSource::NodeStatistics,
            FeeSource::Explicit,
        ]
        .into_iter()
        .find(|source| source.as_str() == text)
    }
}

/// A draft's fee and where it comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedFee {
    /// The fee.
    pub amount: Amount,
    /// Where it comes from.
    pub source: FeeSource,
    /// The exact fee floor, when the SDK computes it.
    pub floor: Option<Amount>,
}

/// The fee of a transaction of `kind` that is `size` bytes long, signatures included, under
/// `params`.
pub(crate) fn resolve(
    choice: FeeChoice,
    kind: OperationKind,
    size: usize,
    params: &Params,
    statistics: Option<&FeeStatistics>,
) -> Result<ResolvedFee, Error> {
    let floor = floor(kind, size, params);
    let minimum = || match floor {
        Some(floor) => Ok((floor, FeeSource::Floor)),
        None => statistics
            .and_then(|statistics| statistics.get(kind))
            .and_then(|figures| figures.maximum.to_u64())
            .map(|fee| (fee, FeeSource::NodeStatistics))
            .ok_or(Error::FeeUnavailable { operation: kind }),
    };
    let (amount, source) = match choice {
        FeeChoice::Exact(amount) => {
            let fee = amount.to_u64().ok_or(Error::InvalidFee {
                reason: "above the largest fee",
            })?;
            (fee, FeeSource::Explicit)
        }
        FeeChoice::Minimum => minimum()?,
        FeeChoice::Multiplier { basis_points } => {
            if basis_points < 10_000 {
                return Err(Error::InvalidFee {
                    reason: "a multiplier is at least 10000 basis points",
                });
            }
            let (base, source) = minimum()?;
            let scaled = (u128::from(base) * u128::from(basis_points)).div_ceil(10_000);
            let fee = u64::try_from(scaled).map_err(|_| Error::InvalidFee {
                reason: "above the largest fee",
            })?;
            (fee, source)
        }
    };
    if amount > MAX_AMOUNT {
        return Err(Error::InvalidFee {
            reason: "above the largest fee",
        });
    }
    Ok(ResolvedFee {
        amount: Amount::from(amount),
        source,
        floor: floor.map(Amount::from),
    })
}

#[cfg(test)]
mod tests {
    use crate::chain::tests::devnet_chain;

    use super::*;

    fn figures(maximum: u64) -> FeeFigures {
        FeeFigures {
            minimum: Amount::from(1u64),
            average: Amount::from(maximum / 2),
            maximum: Amount::from(maximum),
        }
    }

    #[test]
    fn resolution() {
        let chain = devnet_chain();
        let params = chain.params(2);
        let mut statistics = FeeStatistics::new();
        statistics.insert(OperationKind::Transfer, figures(900));
        statistics.insert(OperationKind::Transfer, figures(1_000_026));
        let resolved = resolve(
            FeeChoice::Minimum,
            OperationKind::Transfer,
            154,
            params,
            Some(&statistics),
        )
        .unwrap();
        assert_eq!(resolved.amount, Amount::from(1_000_026u64));
        assert_eq!(resolved.source, FeeSource::NodeStatistics);
        assert_eq!(resolved.floor, None);

        let scaled = resolve(
            FeeChoice::Multiplier {
                basis_points: 15_000,
            },
            OperationKind::Transfer,
            154,
            params,
            Some(&statistics),
        )
        .unwrap();
        assert_eq!(scaled.amount, Amount::from(1_500_039u64));

        assert_eq!(
            resolve(
                FeeChoice::Minimum,
                OperationKind::Vote,
                154,
                params,
                Some(&statistics)
            ),
            Err(Error::FeeUnavailable {
                operation: OperationKind::Vote
            })
        );
        let exact = resolve(
            FeeChoice::Exact(Amount::from(7u64)),
            OperationKind::Vote,
            154,
            params,
            None,
        )
        .unwrap();
        assert_eq!(
            (exact.amount, exact.source),
            (Amount::from(7u64), FeeSource::Explicit)
        );
        assert!(matches!(
            resolve(
                FeeChoice::Exact(Amount::from(u64::MAX)),
                OperationKind::Vote,
                154,
                params,
                None
            ),
            Err(Error::InvalidFee { .. })
        ));
        assert!(matches!(
            resolve(
                FeeChoice::Multiplier {
                    basis_points: 9_999
                },
                OperationKind::Transfer,
                154,
                params,
                Some(&statistics)
            ),
            Err(Error::InvalidFee { .. })
        ));
        assert_eq!(
            FeeSource::parse("node-statistics"),
            Some(FeeSource::NodeStatistics)
        );
    }
}
