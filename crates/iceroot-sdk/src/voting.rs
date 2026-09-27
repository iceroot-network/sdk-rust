//! What the vote library needs from the rest of the SDK: the vote rules in force, and a snapshot of
//! a node's validator list.
//!
//! The vote library ([`vote`](crate::vote)) takes plain data. These functions give it the
//! network's own values, so that an app never writes the rules or the snapshot by hand:
//! [`vote_rules`] turns the core's rules at a height into the library's [`VoteRules`], and
//! [`relay_snapshot`] turns the node API client's validator list into a snapshot marked
//! [`SnapshotSource::RelayApproximate`](crate::vote::SnapshotSource::RelayApproximate).
//!
//! A relay snapshot holds only the validators a vote may name now. A node refuses a vote that names
//! a validator which has not resigned and whose node it has not seen running in the last rounds
//! (`ERR_OFFLINE`, "... is not operating a node on the network"): a validator registered without a
//! node, one whose node stopped, and on a new devnet every validator until its node is seen. The
//! validator list shows such a validator without a node version, and [`relay_validator`] leaves it
//! out, so no selection names it. A later [`check`](crate::vote::check) reports a pick left out
//! this way as no longer among the validators a vote can name.

use iceroot_sdk_api::{ValidatorInfo, ValidatorStatus};
use iceroot_sdk_core::Chain;
use iceroot_sdk_core::profile::Stage;
use iceroot_sdk_core::rules::Rules;
use iceroot_vote::{NameRule, RelaySnapshot, RelayValidator, Resignation, VoteRules, VoteSnapshot};

/// The vote rules of `rules` (the core's rules at a height, [`Chain::rules`]), for
/// [`select`](crate::vote::select) and [`validate_vote`](crate::vote::validate_vote).
///
/// The limits come from `rules.vote`. The name rule and whether a validator's account may vote
/// follow the format stage: today's formats (and the post-quantum ones, which keep them) accept
/// the names `rules.name` describes and let validators vote; the IceRoot formats accept
/// lowercase letters only and refuse a vote from a validator's account. On today's devnet this is
/// [`VoteRules::SOLAR_COMPATIBLE`] with the devnet's seats as the most entries.
pub fn vote_rules(rules: &Rules) -> VoteRules {
    let solar = matches!(rules.stage, Stage::S1 | Stage::Pq);
    VoteRules {
        min_entries: u8::try_from(rules.vote.min_entries).unwrap_or(u8::MAX),
        max_entries: u8::try_from(rules.vote.max_entries).unwrap_or(u8::MAX),
        max_entry_basis_points: u16::try_from(rules.vote.max_basis_points_per_entry)
            .unwrap_or(u16::MAX),
        max_bytes: u16::try_from(rules.vote.max_bytes).unwrap_or(u16::MAX),
        names: if solar {
            NameRule::SolarCompatible
        } else {
            NameRule::LowercaseLetters
        },
        validators_may_vote: solar,
    }
}

/// One validator of the node API client's validator list, as the vote library reads a relay's, or
/// `None` when a vote may not name it now (see [`votable`]): a relay snapshot leaves it out.
///
/// The list has no registration height and no first forged block: they stay `None` unless the
/// caller looks them up and sets them. Without a first forged block, the seated days of a
/// validator that has produced blocks are unknown, so Reliability does not pick it.
pub fn relay_validator(info: &ValidatorInfo) -> Option<RelayValidator> {
    votable(info).then(|| RelayValidator {
        name: info.name.clone(),
        address: info.address.clone(),
        rank: info.rank,
        resignation: match info.status {
            ValidatorStatus::ResignedTemporary => Some(Resignation::Temporary),
            ValidatorStatus::ResignedPermanent => Some(Resignation::Permanent),
            ValidatorStatus::Active | ValidatorStatus::Standby => None,
        },
        vote_weight: info.vote_weight,
        voters: u32::try_from(info.voters).unwrap_or(u32::MAX),
        produced_blocks: info.production.produced,
        missed_blocks: Some(info.production.missed),
        registered_height: None,
        first_forged_height: None,
    })
}

/// Whether a node accepts a vote that names this validator: it has resigned (and every mode
/// passes it over for that), or the node has seen its node running, which the validator list
/// shows as its node version. A node refuses a vote naming any other validator with
/// `ERR_OFFLINE`: one registered without a node, one whose node stopped some rounds ago, and on
/// a new devnet every validator until its node is seen.
pub fn votable(info: &ValidatorInfo) -> bool {
    matches!(
        info.status,
        ValidatorStatus::ResignedTemporary | ValidatorStatus::ResignedPermanent
    ) || info.version.is_some()
}

/// A snapshot of a node's validator list at `height`, with the seats and block time of `chain`'s
/// milestone at that height, marked
/// [`SnapshotSource::RelayApproximate`](crate::vote::SnapshotSource::RelayApproximate).
///
/// `validators` is every registered validator a vote may name (every page of
/// [`validators`](iceroot_sdk_api::SolarCompat::validators), through [`relay_validator`]), with
/// any registration heights and first forged blocks the caller looked up. See
/// [`VoteSnapshot::from_relay`] for what a relay snapshot holds.
pub fn relay_snapshot(chain: &Chain, height: u32, validators: Vec<RelayValidator>) -> VoteSnapshot {
    let economics = chain.economics(height);
    VoteSnapshot::from_relay(RelaySnapshot {
        height: u64::from(height),
        seats: u32::try_from(economics.seats()).unwrap_or(u32::MAX),
        block_time_seconds: u32::try_from(economics.block_time_seconds()).unwrap_or(u32::MAX),
        validators,
    })
}
