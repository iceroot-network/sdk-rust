//! Fees: the caller's choice, the exact fee floor, the node's statistics and the resolved fee of a
//! draft.
//!
//! A draft always carries an explicit fee, never a milestone's static default. Its source is
//! recorded ([`FeeSource`]) so that a review screen can say where the number comes from:
//!
//! - [`FeeChoice::Exact`]: the caller's fee, as given.
//! - [`FeeChoice::Minimum`] (the default): the exact fee floor of the milestone in force for the
//!   transaction's type and size ([`Chain::fee_floor`](crate::chain::Chain::fee_floor)), the
//!   node's own rule.
//! - [`FeeChoice::Multiplier`]: the minimum scaled up, in basis points (15,000 is 1.5 times).
//!
//! The floor comes from `heartwood-crypto`, the function the node checks every fee with; the SDK
//! keeps no copy of the formula. A node's pool admits a transaction by the same rule whenever the
//! milestone enables dynamic fees. Where the milestone has none, the floor is zero while a node's
//! pool applies its own settings (the node configuration's pool fees) or a fixed fee, so such a
//! network needs an exact fee. Where a network's formats have no floor function, the minimum
//! falls back to the node's fee statistics for the operation (the largest fee paid recently), and
//! without statistics the choice fails with [`Error::FeeUnavailable`]; an exact fee still works.

use heartwood_crypto::managers::Params;
use heartwood_crypto::utils::fee_floor::minimum_fee;
use heartwood_crypto::validation::MAX_AMOUNT;

use crate::amount::Amount;
use crate::error::Error;
use crate::transaction::OperationKind;

/// Whether this build computes the exact fee floor ([`floor`]).
pub(crate) const FLOOR_AVAILABLE: bool = true;

/// The exact fee floor of a transaction of `kind` that is `size` bytes long, signatures included,
/// under `params`; `None` where the formats have no floor function.
///
/// This is the one place the floor is computed: `heartwood-crypto`'s `minimum_fee`, which is the
/// node's own rule, `(addonBytes[type] + ceil(size / 2)) × max(minFee, 1)`, and zero for burns
/// and resignations or without an enabled fee table. Its result is a signed 128-bit integer. A
/// negative floor (a fee table with negative add-on bytes) is met by every fee, so it counts as
/// zero; every other value fits an [`Amount`] exactly. Whether a floor above the largest fee can
/// be paid is for [`resolve`] to decide.
pub(crate) fn floor(kind: OperationKind, size: usize, params: &Params) -> Option<Amount> {
    let floor = minimum_fee(kind.wire_type(), size, params);
    let units = u128::try_from(floor).unwrap_or(0);
    Some(Amount::from_base_units(units))
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
    /// The fee equals the exact fee floor of the milestone in force.
    Floor,
    /// The node's fee statistics, where the formats have no floor function.
    NodeStatistics,
    /// A fee the caller set: an exact amount, or a multiple of the minimum that comes out above
    /// the floor. A deserialized draft also reads as explicit whenever its fee is not the floor
    /// computed again (see [`crate::transaction::Draft::deserialize`]).
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
    /// The exact fee floor of the milestone in force, for the transaction's type and size; `None`
    /// where the formats have no floor function.
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
        // A floor above the largest fee cannot be paid: no fee resolves.
        Some(floor) => floor
            .to_u64()
            .filter(|fee| *fee <= MAX_AMOUNT)
            .map(|fee| (fee, FeeSource::Floor))
            .ok_or(Error::FeeUnavailable { operation: kind }),
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
            // Only a fee that equals the floor is labelled as the floor.
            let source = match source {
                FeeSource::Floor if fee != base => FeeSource::Explicit,
                source => source,
            };
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
        floor,
    })
}

#[cfg(test)]
mod tests {
    use crate::chain::Chain;
    use crate::chain::tests::{devnet_chain, devnet_parts};
    use crate::profile::{DevnetOptions, Profile};

    use super::*;

    fn figures(maximum: u64) -> FeeFigures {
        FeeFigures {
            minimum: Amount::from(1u64),
            average: Amount::from(maximum / 2),
            maximum: Amount::from(maximum),
        }
    }

    /// The devnet chain with the dynamic fee table `table` (JSON text) in place of its own.
    fn chain_with_fees(table: &str) -> Chain {
        let (network, milestones) = devnet_parts();
        let mut milestones: serde_json::Value = serde_json::from_str(&milestones).unwrap();
        milestones[0]["dynamicFees"] = serde_json::from_str(table).unwrap();
        Chain::from_parts(
            &Profile::devnet(DevnetOptions::default()),
            &network,
            &milestones.to_string(),
        )
        .unwrap()
    }

    #[test]
    fn the_floor_is_the_nodes() {
        let chain = devnet_chain();
        let params = chain.params(2);
        // (85 + 77) × 6173 for a transfer of 153 or 154 bytes, as the reference computes it.
        for size in [153, 154] {
            assert_eq!(
                floor(OperationKind::Transfer, size, params),
                Some(Amount::from(1_000_026u64))
            );
        }
        assert_eq!(
            floor(OperationKind::RegisterValidator, 154, params),
            Some(Amount::from((1_214_968u64 + 77) * 6173))
        );
        for kind in [OperationKind::Burn, OperationKind::ResignValidator] {
            assert_eq!(floor(kind, 154, params), Some(Amount::ZERO), "{kind}");
        }
        for kind in OperationKind::ALL {
            let expected = minimum_fee(kind.wire_type(), 200, params);
            assert_eq!(
                floor(kind, 200, params).map(Amount::base_units),
                Some(u128::try_from(expected).unwrap()),
                "{kind}"
            );
        }

        // Without an enabled table there is no floor to pay.
        let disabled = chain_with_fees(r#"{"enabled":false,"minFee":100,"addonBytes":{}}"#);
        assert_eq!(
            floor(OperationKind::Transfer, 154, disabled.params(2)),
            Some(Amount::ZERO)
        );
        // A negative floor is met by every fee.
        let negative =
            chain_with_fees(r#"{"enabled":true,"minFee":7,"addonBytes":{"transfer":-1000}}"#);
        let params = negative.params(2);
        assert!(minimum_fee(OperationKind::Transfer.wire_type(), 154, params) < 0);
        assert_eq!(
            floor(OperationKind::Transfer, 154, params),
            Some(Amount::ZERO)
        );
        // A floor above the largest fee is kept exactly, and no minimum fee resolves.
        let huge = chain_with_fees(
            r#"{"enabled":true,"minFee":9007199254740991,"addonBytes":{"transfer":9007199254740991}}"#,
        );
        let params = huge.params(2);
        let big = 9_007_199_254_740_991_u128;
        assert_eq!(
            floor(OperationKind::Transfer, 154, params),
            Some(Amount::from_base_units((big + 77) * big))
        );
        for choice in [
            FeeChoice::Minimum,
            FeeChoice::Multiplier {
                basis_points: 10_000,
            },
        ] {
            assert_eq!(
                resolve(choice, OperationKind::Transfer, 154, params, None),
                Err(Error::FeeUnavailable {
                    operation: OperationKind::Transfer
                })
            );
        }
        let exact = resolve(
            FeeChoice::Exact(Amount::from(5u64)),
            OperationKind::Transfer,
            154,
            params,
            None,
        )
        .unwrap();
        assert_eq!(exact.floor, Some(Amount::from_base_units((big + 77) * big)));
    }

    #[test]
    fn resolution() {
        let chain = devnet_chain();
        let params = chain.params(2);
        let floor = Some(Amount::from(1_000_026u64));
        let mut statistics = FeeStatistics::new();
        statistics.insert(OperationKind::Transfer, figures(900));
        statistics.insert(OperationKind::Transfer, figures(2_000_000));

        // The minimum is the floor, whatever the node's statistics say.
        for statistics in [None, Some(&statistics)] {
            let resolved = resolve(
                FeeChoice::Minimum,
                OperationKind::Transfer,
                154,
                params,
                statistics,
            )
            .unwrap();
            assert_eq!(
                resolved,
                ResolvedFee {
                    amount: Amount::from(1_000_026u64),
                    source: FeeSource::Floor,
                    floor,
                }
            );
        }

        // A multiple of the floor is the caller's choice; 10,000 basis points is the floor.
        let scaled = resolve(
            FeeChoice::Multiplier {
                basis_points: 15_000,
            },
            OperationKind::Transfer,
            154,
            params,
            None,
        )
        .unwrap();
        assert_eq!(
            (scaled.amount, scaled.source, scaled.floor),
            (Amount::from(1_500_039u64), FeeSource::Explicit, floor)
        );
        let same = resolve(
            FeeChoice::Multiplier {
                basis_points: 10_000,
            },
            OperationKind::Transfer,
            154,
            params,
            None,
        )
        .unwrap();
        assert_eq!(
            (same.amount, same.source),
            (Amount::from(1_000_026u64), FeeSource::Floor)
        );
        // A burn's floor is zero, and so is any multiple of it.
        let burn = resolve(
            FeeChoice::Multiplier {
                basis_points: 20_000,
            },
            OperationKind::Burn,
            154,
            params,
            None,
        )
        .unwrap();
        assert_eq!((burn.amount, burn.source), (Amount::ZERO, FeeSource::Floor));

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
                None
            ),
            Err(Error::InvalidFee { .. })
        ));
        assert_eq!(
            FeeSource::parse("node-statistics"),
            Some(FeeSource::NodeStatistics)
        );
        assert_eq!(FeeSource::parse("floors"), None);
        assert_eq!(
            statistics.get(OperationKind::Transfer).map(|f| f.maximum),
            Some(Amount::from(2_000_000u64))
        );
    }
}
