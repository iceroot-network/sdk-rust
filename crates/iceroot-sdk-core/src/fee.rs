//! Fees: the caller's choice, the exact fee floor and the resolved fee of a draft.
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
//! milestone enables dynamic fees. Where the milestone has no enabled dynamic fee table, there is
//! no floor: a node's pool then applies its own settings (the node configuration's pool fees) or
//! a fixed fee, which the SDK cannot know, so the minimum and its multiples fail with
//! [`Error::FeeUnavailable`] and such a network needs an exact fee. The SDK never falls back to
//! a guess, such as a zero fee or the fees other transactions paid.

use heartwood_crypto::managers::Params;
use heartwood_crypto::utils::fee_floor::minimum_fee;
use heartwood_crypto::validation::MAX_AMOUNT;

use crate::amount::Amount;
use crate::error::Error;
use crate::transaction::OperationKind;

/// Whether the exact fee floor is in force under `params`: the milestone has a dynamic fee table
/// and it is enabled.
pub(crate) fn floor_in_force(params: &Params) -> bool {
    params.dynamic_fees().is_some_and(|table| table.enabled())
}

/// The exact fee floor of a transaction of `kind` that is `size` bytes long, signatures included,
/// under `params`; `None` where no floor is in force ([`floor_in_force`]).
///
/// This is the one place the floor is computed: `heartwood-crypto`'s `minimum_fee`, which is the
/// node's own rule, `(addonBytes[type] + ceil(size / 2)) × max(minFee, 1)`, and zero for burns
/// and resignations. Its result is a signed 128-bit integer. A negative floor (a fee table with
/// negative add-on bytes) is met by every fee, so it counts as zero; every other value fits an
/// [`Amount`] exactly. Whether a floor above the largest fee can be paid is for [`resolve`] to
/// decide.
pub(crate) fn floor(kind: OperationKind, size: usize, params: &Params) -> Option<Amount> {
    if !floor_in_force(params) {
        return None;
    }
    let floor = minimum_fee(kind.wire_type(), size, params);
    let units = u128::try_from(floor).unwrap_or(0);
    Some(Amount::from_base_units(units))
}

/// How the fee of a draft is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FeeChoice {
    /// The lowest fee the network accepts: the exact fee floor (see the module documentation).
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

/// Where a draft's fee comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeeSource {
    /// The fee equals the exact fee floor of the milestone in force.
    Floor,
    /// A fee the caller set: an exact amount, or a multiple of the minimum that comes out above
    /// the floor. A deserialized draft also reads as explicit whenever its fee is not the floor
    /// computed again, and whatever other source its serialized form claims (see
    /// [`crate::transaction::Draft::deserialize`]).
    Explicit,
}

impl FeeSource {
    /// The stable string form: `floor` or `explicit`.
    pub const fn as_str(self) -> &'static str {
        match self {
            FeeSource::Floor => "floor",
            FeeSource::Explicit => "explicit",
        }
    }

    /// The source with the string form `text`.
    pub fn parse(text: &str) -> Option<FeeSource> {
        [FeeSource::Floor, FeeSource::Explicit]
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
    /// where no floor is in force (the milestone has no enabled dynamic fee table).
    pub floor: Option<Amount>,
}

/// The fee of a transaction of `kind` that is `size` bytes long, signatures included, under
/// `params`.
pub(crate) fn resolve(
    choice: FeeChoice,
    kind: OperationKind,
    size: usize,
    params: &Params,
) -> Result<ResolvedFee, Error> {
    let floor = floor(kind, size, params);
    // Without a floor in force, or with a floor above the largest fee, no minimum resolves.
    let minimum = || {
        floor
            .and_then(|floor| floor.to_u64())
            .filter(|fee| *fee <= MAX_AMOUNT)
            .ok_or(Error::FeeUnavailable { operation: kind })
    };
    let (amount, source) = match choice {
        FeeChoice::Exact(amount) => {
            let fee = amount.to_u64().ok_or(Error::InvalidFee {
                reason: "above the largest fee",
            })?;
            (fee, FeeSource::Explicit)
        }
        FeeChoice::Minimum => (minimum()?, FeeSource::Floor),
        FeeChoice::Multiplier { basis_points } => {
            if basis_points < 10_000 {
                return Err(Error::InvalidFee {
                    reason: "a multiplier is at least 10000 basis points",
                });
            }
            let base = minimum()?;
            let scaled = (u128::from(base) * u128::from(basis_points)).div_ceil(10_000);
            let fee = u64::try_from(scaled).map_err(|_| Error::InvalidFee {
                reason: "above the largest fee",
            })?;
            // Only a fee that equals the floor is labelled as the floor.
            let source = if fee == base {
                FeeSource::Floor
            } else {
                FeeSource::Explicit
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

    /// The devnet chain with the dynamic fee table `table` (JSON text) in place of its own, or
    /// with none.
    fn chain_with_fees(table: Option<&str>) -> Chain {
        let (network, milestones) = devnet_parts();
        let mut milestones: serde_json::Value = serde_json::from_str(&milestones).unwrap();
        match table {
            Some(table) => milestones[0]["dynamicFees"] = serde_json::from_str(table).unwrap(),
            None => {
                milestones[0].as_object_mut().unwrap().remove("dynamicFees");
            }
        }
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
        assert!(floor_in_force(params));
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

        // A negative floor is met by every fee.
        let negative = chain_with_fees(Some(
            r#"{"enabled":true,"minFee":7,"addonBytes":{"transfer":-1000}}"#,
        ));
        let params = negative.params(2);
        assert!(minimum_fee(OperationKind::Transfer.wire_type(), 154, params) < 0);
        assert_eq!(
            floor(OperationKind::Transfer, 154, params),
            Some(Amount::ZERO)
        );
        // A floor above the largest fee is kept exactly, and no minimum fee resolves.
        let huge = chain_with_fees(Some(
            r#"{"enabled":true,"minFee":9007199254740991,"addonBytes":{"transfer":9007199254740991}}"#,
        ));
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
                resolve(choice, OperationKind::Transfer, 154, params),
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
        )
        .unwrap();
        assert_eq!(exact.floor, Some(Amount::from_base_units((big + 77) * big)));
    }

    #[test]
    fn no_floor_without_an_enabled_table() {
        // A disabled table, or none: the pool applies settings the SDK cannot know, so there is
        // no floor, never a zero one, and only an exact fee resolves.
        for table in [
            Some(r#"{"enabled":false,"minFee":100,"addonBytes":{}}"#),
            None,
        ] {
            let chain = chain_with_fees(table);
            let params = chain.params(2);
            assert!(!floor_in_force(params), "{table:?}");
            for kind in OperationKind::ALL {
                assert_eq!(floor(kind, 154, params), None, "{kind} {table:?}");
                for choice in [
                    FeeChoice::Minimum,
                    FeeChoice::Multiplier {
                        basis_points: 15_000,
                    },
                ] {
                    assert_eq!(
                        resolve(choice, kind, 154, params),
                        Err(Error::FeeUnavailable { operation: kind }),
                        "{kind} {table:?}"
                    );
                }
            }
            let exact = resolve(
                FeeChoice::Exact(Amount::from(7u64)),
                OperationKind::Transfer,
                154,
                params,
            )
            .unwrap();
            assert_eq!(
                exact,
                ResolvedFee {
                    amount: Amount::from(7u64),
                    source: FeeSource::Explicit,
                    floor: None,
                }
            );
        }
    }

    #[test]
    fn resolution() {
        let chain = devnet_chain();
        let params = chain.params(2);
        let floor = Some(Amount::from(1_000_026u64));

        // The minimum is the floor.
        let resolved = resolve(FeeChoice::Minimum, OperationKind::Transfer, 154, params).unwrap();
        assert_eq!(
            resolved,
            ResolvedFee {
                amount: Amount::from(1_000_026u64),
                source: FeeSource::Floor,
                floor,
            }
        );

        // A multiple of the floor is the caller's choice; 10,000 basis points is the floor.
        let scaled = resolve(
            FeeChoice::Multiplier {
                basis_points: 15_000,
            },
            OperationKind::Transfer,
            154,
            params,
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
        )
        .unwrap();
        assert_eq!((burn.amount, burn.source), (Amount::ZERO, FeeSource::Floor));

        let exact = resolve(
            FeeChoice::Exact(Amount::from(7u64)),
            OperationKind::Vote,
            154,
            params,
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
            ),
            Err(Error::InvalidFee { .. })
        ));
        for source in [FeeSource::Floor, FeeSource::Explicit] {
            assert_eq!(FeeSource::parse(source.as_str()), Some(source));
        }
        for text in ["node-statistics", "floors", ""] {
            assert_eq!(FeeSource::parse(text), None, "{text}");
        }
    }
}
