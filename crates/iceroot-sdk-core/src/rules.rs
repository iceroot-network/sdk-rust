//! The rules in force at a height: what a transaction may contain.
//!
//! Applications show and check these values instead of constants of their own. They come from the
//! milestone in force (`heartwood-crypto`'s `Params`) and the transaction rules of today's formats.
//! The builders enforce the same rules before anything is signed.

use heartwood_crypto::transactions::serialiser::size_limit;
use heartwood_crypto::transactions::types::Memo;
use heartwood_crypto::transactions::types::group2::MAX_VOTE_ASSET_BYTES;
use heartwood_crypto::validation::{MAX_AMOUNT, VOTE_TOTAL_BASIS_POINTS, is_delegate_name};

use crate::amount::Amount;
use crate::chain::Chain;
use crate::fee;
use crate::profile::Stage;
use crate::transaction::OperationKind;

/// The rules in force at one height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// The height the rules are for.
    pub height: u32,
    /// The format stage at that height.
    pub stage: Stage,
    /// Transfers.
    pub transfer: TransferRules,
    /// Memos.
    pub memo: MemoRules,
    /// Votes.
    pub vote: VoteRules,
    /// Validator names.
    pub name: NameRules,
    /// Burns.
    pub burn: BurnRules,
    /// Fees.
    pub fees: FeeRules,
    /// Validator resignations.
    pub resignation: ResignationRules,
    /// The largest transaction in bytes.
    pub max_transaction_bytes: usize,
    /// The largest amount any amount field carries (`2^63 − 1` base units).
    pub max_amount: Amount,
}

/// Transfer rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferRules {
    /// The fewest recipients.
    pub min_recipients: usize,
    /// The most recipients.
    pub max_recipients: usize,
    /// The smallest amount per recipient.
    pub min_amount: Amount,
}

/// Memo rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoRules {
    /// The longest memo, in UTF-8 bytes.
    pub max_bytes: usize,
}

/// Vote rules. A vote with no entries withdraws the account's vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoteRules {
    /// The fewest entries of a vote that is not a withdrawal.
    pub min_entries: usize,
    /// The most entries.
    pub max_entries: usize,
    /// The sum every non-empty vote's shares must have, in basis points.
    pub total_basis_points: u32,
    /// The largest share of one entry, in basis points.
    pub max_basis_points_per_entry: u32,
    /// The largest encoded vote, in bytes.
    pub max_bytes: usize,
}

/// Validator name rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameRules {
    /// The shortest name, in characters.
    pub min_length: usize,
    /// The longest name, in characters.
    pub max_length: usize,
    /// The characters a name may use.
    pub characters: &'static str,
}

impl NameRules {
    /// Whether `name` is a valid validator name: 1 to 20 of `a-z`, `0-9` and `!@$&_.`, not
    /// starting with `_`, and not only digits.
    pub fn is_valid(&self, name: &str) -> bool {
        is_delegate_name(name)
    }
}

/// Burn rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BurnRules {
    /// The smallest amount a burn may burn.
    pub min_amount: Amount,
}

/// Fee rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeRules {
    /// The dynamic fee table, when the milestone has one.
    pub dynamic: Option<DynamicFeeRules>,
    /// Whether this SDK build computes the exact fee floor for the network's formats; it does for
    /// today's formats. Where it does not, a draft's minimum fee comes from the node's fee
    /// statistics.
    pub floor_available: bool,
}

/// The milestone's dynamic fee table. Its floor is
/// `(addonBytes[type] + ceil(size / 2)) × max(minFee, 1)` while it is enabled, and zero for burns
/// and resignations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicFeeRules {
    /// Whether the floor is in force.
    pub enabled: bool,
    /// The price of a byte.
    pub min_fee: i64,
    /// The extra bytes each operation is charged for.
    pub addon_bytes: Vec<(OperationKind, i64)>,
}

/// Resignation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResignationRules {
    /// The blocks a temporary resignation must last before it may be revoked; `None` for no wait.
    pub blocks_before_revoke: Option<u64>,
}

impl Rules {
    /// The rules of `chain` at `height`.
    pub(crate) fn at(chain: &Chain, height: u32) -> Rules {
        let params = chain.params(height);
        let transfer_limit = |value: u32, default: usize| match value {
            0 => default,
            value => usize::try_from(value).unwrap_or(usize::MAX),
        };
        Rules {
            height,
            stage: chain.stage_at(height),
            transfer: TransferRules {
                min_recipients: transfer_limit(params.transfer_minimum(), 1),
                max_recipients: transfer_limit(params.transfer_maximum(), 256),
                min_amount: Amount::from_base_units(1),
            },
            memo: MemoRules {
                max_bytes: Memo::MAX_BYTES,
            },
            vote: VoteRules {
                min_entries: 1,
                max_entries: usize::try_from(params.active_delegates()).unwrap_or(usize::MAX),
                total_basis_points: VOTE_TOTAL_BASIS_POINTS,
                max_basis_points_per_entry: VOTE_TOTAL_BASIS_POINTS,
                max_bytes: MAX_VOTE_ASSET_BYTES,
            },
            name: NameRules {
                min_length: 1,
                max_length: 20,
                characters: "a-z 0-9 ! @ $ & _ .",
            },
            burn: BurnRules {
                min_amount: Amount::from(params.burn_tx_amount()),
            },
            fees: FeeRules {
                dynamic: params.dynamic_fees().map(|table| DynamicFeeRules {
                    enabled: table.enabled(),
                    min_fee: table.min_fee(),
                    addon_bytes: OperationKind::ALL
                        .into_iter()
                        .map(|kind| (kind, table.addon(kind.wire_type().key())))
                        .collect(),
                }),
                floor_available: fee::FLOOR_AVAILABLE,
            },
            resignation: ResignationRules {
                blocks_before_revoke: params.blocks_to_revoke_delegate_resignation(),
            },
            max_transaction_bytes: size_limit(params),
            max_amount: Amount::from(MAX_AMOUNT),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::tests::devnet_chain;

    use super::*;

    #[test]
    fn devnet_rules() {
        let rules = devnet_chain().rules(2);
        assert_eq!(rules.height, 2);
        assert_eq!(rules.transfer.max_recipients, 256);
        assert_eq!(rules.transfer.min_recipients, 1);
        assert_eq!(rules.memo.max_bytes, 255);
        assert_eq!(rules.vote.max_entries, 53);
        assert_eq!(rules.vote.max_bytes, 1024);
        assert_eq!(rules.vote.total_basis_points, 10_000);
        assert_eq!(rules.burn.min_amount, Amount::from_base_units(2_000_000));
        assert_eq!(rules.resignation.blocks_before_revoke, Some(106));
        assert_eq!(rules.max_transaction_bytes, 2_097_152 / 150 * 2);
        let dynamic = rules.fees.dynamic.unwrap();
        assert!(dynamic.enabled);
        assert_eq!(dynamic.min_fee, 6173);
        assert!(
            dynamic
                .addon_bytes
                .contains(&(OperationKind::RegisterValidator, 1_214_968))
        );
        assert!(rules.name.is_valid("genesis_1"));
        assert!(!rules.name.is_valid("Genesis"));
        assert!(!rules.name.is_valid("_x"));
        assert!(!rules.name.is_valid("123"));
    }
}
