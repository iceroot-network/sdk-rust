//! The network's economics at a height: seats, block time, rewards, donations and the fee burn.
//!
//! These values serve display and estimates, such as a rewards calculator; nothing here is signed.
//! The arithmetic is `heartwood-crypto`'s, the same the node applies to every block.

use heartwood_crypto::utils::burn::burned_fee;
use heartwood_crypto::utils::donations::calculate_donations;
use heartwood_crypto::utils::reward_calculator::calculate_reward;

use crate::address::Address;
use crate::amount::Amount;
use crate::chain::Chain;

/// The supply figures a node reports (the node API client's [`iceroot_sdk_api::Supply`]).
pub use iceroot_sdk_api::Supply;

/// A donation recipient: a share of every block reward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Donation {
    /// The recipient.
    pub address: Address,
    /// Its share of the block reward, in basis points.
    pub basis_points: u16,
    /// The stated purpose, if any.
    pub purpose: Option<String>,
}

/// The economics in force at one height.
#[derive(Debug, Clone)]
pub struct Economics {
    chain: Chain,
    height: u32,
    supply: Option<Supply>,
}

impl Economics {
    pub(crate) fn at(chain: Chain, height: u32) -> Economics {
        Economics {
            chain,
            height,
            supply: None,
        }
    }

    /// The same economics with the supply figures a node reported.
    pub fn with_supply(mut self, supply: Supply) -> Economics {
        self.supply = Some(supply);
        self
    }

    /// The height these economics are for.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The number of validator seats: the validators that forge in each round.
    pub fn seats(&self) -> u64 {
        self.chain.params(self.height).active_delegates()
    }

    /// The block time in seconds.
    pub fn block_time_seconds(&self) -> u64 {
        self.chain.params(self.height).block_time()
    }

    /// The block reward of the validator at `rank` (1 for the first seat), or `None` when the
    /// reward table has no entry for that rank.
    pub fn reward_for_rank(&self, rank: u32) -> Option<Amount> {
        calculate_reward(self.chain.params(self.height), rank)
            .ok()
            .map(Amount::from)
    }

    /// The block reward of every seat, first seat first.
    pub fn rewards_by_rank(&self) -> Vec<(u32, Option<Amount>)> {
        let seats = u32::try_from(self.seats()).unwrap_or(u32::MAX);
        (1..=seats)
            .map(|rank| (rank, self.reward_for_rank(rank)))
            .collect()
    }

    /// The rank table's secondary reward (`secondaryReward`), when the table is in force.
    pub fn secondary_reward(&self) -> Option<Amount> {
        self.chain
            .params(self.height)
            .dynamic_reward()
            .filter(|table| table.enabled())
            .map(|table| Amount::from(table.secondary_reward()))
    }

    /// The donation recipients, in the order of the milestone.
    pub fn donations(&self) -> Vec<Donation> {
        self.chain
            .params(self.height)
            .donations()
            .iter()
            .map(|donation| Donation {
                address: Address::from_inner(*donation.address()),
                basis_points: donation.basis_points(),
                purpose: donation.purpose().map(str::to_owned),
            })
            .collect()
    }

    /// The donation each recipient receives out of a block reward of `reward`, in the order of
    /// the milestone. The remainder stays with the validator. `None` when `reward` is above the
    /// 64-bit amounts of today's formats.
    pub fn donations_of(&self, reward: Amount) -> Option<Vec<(Address, Amount)>> {
        let reward = reward.to_u64()?;
        Some(
            calculate_donations(reward, self.chain.params(self.height))
                .into_iter()
                .map(|(address, amount)| (Address::from_inner(address), Amount::from(amount)))
                .collect(),
        )
    }

    /// The share of every fee that is burned, in basis points.
    pub fn fee_burn_basis_points(&self) -> u16 {
        self.chain.params(self.height).fee_basis_points()
    }

    /// The part of `fee` that is burned. `None` when `fee` is above the 64-bit amounts of today's
    /// formats.
    pub fn burned_fee(&self, fee: Amount) -> Option<Amount> {
        let fee = fee.to_u64()?;
        Some(Amount::from(burned_fee(
            fee,
            self.chain.params(self.height),
        )))
    }

    /// The smallest amount a burn may burn.
    pub fn min_burn(&self) -> Amount {
        Amount::from(self.chain.params(self.height).burn_tx_amount())
    }

    /// The supply figures, when a node reported them.
    pub fn supply(&self) -> Option<&Supply> {
        self.supply.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::tests::devnet_chain;

    use super::*;

    #[test]
    fn devnet_economics() {
        let economics = devnet_chain().economics(1);
        assert_eq!(economics.seats(), 53);
        assert_eq!(economics.block_time_seconds(), 8);
        assert_eq!(
            economics.reward_for_rank(1),
            Some(Amount::from_base_units(200_000_000))
        );
        assert_eq!(economics.reward_for_rank(54), None);
        assert_eq!(economics.rewards_by_rank().len(), 53);
        assert_eq!(
            economics.secondary_reward(),
            Some(Amount::from_base_units(180_000_000))
        );
        assert_eq!(economics.fee_burn_basis_points(), 9000);
        assert_eq!(
            economics.burned_fee(Amount::from_base_units(1_000_026)),
            Some(Amount::from_base_units(900_023))
        );
        assert!(economics.donations().is_empty());
        assert_eq!(
            economics.donations_of(Amount::from_base_units(200_000_000)),
            Some(Vec::new())
        );
        assert_eq!(
            economics.burned_fee(Amount::from_base_units(u128::MAX)),
            None
        );
        let supply = Supply {
            height: 80,
            block_id: "a".repeat(64),
            supply: 10,
            burned: iceroot_sdk_api::Burned {
                fees: 0,
                transactions: 0,
                total: 0,
            },
        };
        assert_eq!(
            economics.with_supply(supply.clone()).supply(),
            Some(&supply)
        );
    }
}
