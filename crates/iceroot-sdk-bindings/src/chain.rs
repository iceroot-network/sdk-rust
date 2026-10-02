//! A network's loaded configuration: the chain a profile is bound to, its rules and economics.

use iceroot_sdk::api::SolarCompat;
use iceroot_sdk::rules::Rules;
use iceroot_sdk::{Chain, Error, Profile};
use serde_json::{Map, Value, json};

use crate::api::{response, to_text};
use crate::error::Result;
use crate::json::amount_value;

/// The chain of the crypto configuration a node reports (the `data` object of
/// `/node/configuration/crypto`: `network`, `milestones` and optionally `genesisBlock`), for
/// `profile`. The network byte must be the profile's, and so must the network hash when the
/// profile has one pinned; otherwise the chain pins it ([`Chain::profile`]).
pub fn load(profile: &Profile, configuration: &str) -> Result<Chain> {
    Ok(Chain::load(profile, configuration)?)
}

/// The chain a node serves, for `profile`, from the node's answer to the `cryptoConfiguration`
/// call of [`crate::api::PreparedCall`]: its HTTP status, headers (as
/// [`crate::api::PreparedCall::decode`] takes them) and body. The network and milestones are
/// loaded and checked as [`load`] does, and the genesis block's payload hash must be the network
/// hash.
pub fn from_node(profile: &Profile, status: u16, headers: &str, body: &[u8]) -> Result<Chain> {
    let response = response(status, headers, body)?;
    let configuration = SolarCompat::new(0)
        .crypto_configuration()
        .decode(&response)
        .map_err(Error::from)?;
    Ok(Chain::from_node(profile, &configuration)?)
}

/// Decodes the node's answer to the `nodeConfiguration` call of [`crate::api::PreparedCall`] and
/// refuses a node of another chain than `chain`: another network hash or address network byte
/// gives `NetworkMismatch`. Returns the configuration in JSON, as
/// [`crate::api::PreparedCall::decode`] does.
pub fn check_node(chain: &Chain, status: u16, headers: &str, body: &[u8]) -> Result<String> {
    let response = response(status, headers, body)?;
    let configuration = SolarCompat::new(0)
        .node_configuration()
        .decode(&response)
        .map_err(Error::from)?;
    chain.check_node(&configuration)?;
    to_text(&configuration)
}

/// The network's own asset. JSON: `{ assetId, name, symbol, decimals }`.
pub fn token(chain: &Chain) -> String {
    let token = chain.token();
    json!({
        "assetId": token.asset.to_string(),
        "name": token.name,
        "symbol": token.symbol,
        "decimals": token.decimals,
    })
    .to_string()
}

/// The format stage at `height`: `s1`, `pq` or `id`.
pub fn stage_at(chain: &Chain, height: u32) -> String {
    chain.stage_at(height).as_str().to_owned()
}

/// The rules in force at `height`, in JSON.
pub fn rules(chain: &Chain, height: u32) -> String {
    rules_json(&chain.rules(height)).to_string()
}

/// The economics in force at `height`, in JSON.
pub fn economics(chain: &Chain, height: u32) -> String {
    let economics = chain.economics(height);
    json!({
        "height": economics.height(),
        "seats": economics.seats(),
        "blockTimeSeconds": economics.block_time_seconds(),
        "rewardsByRank": economics
            .rewards_by_rank()
            .into_iter()
            .map(|(rank, reward)| json!({ "rank": rank, "reward": reward.map(amount_value) }))
            .collect::<Vec<_>>(),
        "secondaryReward": economics.secondary_reward().map(amount_value),
        "donations": economics
            .donations()
            .into_iter()
            .map(|donation| json!({
                "address": donation.address.to_string(),
                "basisPoints": donation.basis_points,
                "purpose": donation.purpose,
            }))
            .collect::<Vec<_>>(),
        "feeBurnBasisPoints": economics.fee_burn_basis_points(),
        "minBurn": amount_value(economics.min_burn()),
    })
    .to_string()
}

fn rules_json(rules: &Rules) -> Value {
    let dynamic = rules.fees.dynamic.as_ref().map(|dynamic| {
        let addon_bytes: Map<String, Value> = dynamic
            .addon_bytes
            .iter()
            .map(|(kind, bytes)| (kind.as_str().to_owned(), json!(bytes)))
            .collect();
        json!({
            "enabled": dynamic.enabled,
            "minFee": dynamic.min_fee,
            "addonBytes": addon_bytes,
        })
    });
    json!({
        "height": rules.height,
        "stage": rules.stage.as_str(),
        "transfer": {
            "minRecipients": rules.transfer.min_recipients,
            "maxRecipients": rules.transfer.max_recipients,
            "minAmount": amount_value(rules.transfer.min_amount),
        },
        "memo": { "maxBytes": rules.memo.max_bytes },
        "vote": {
            "minEntries": rules.vote.min_entries,
            "maxEntries": rules.vote.max_entries,
            "totalBasisPoints": rules.vote.total_basis_points,
            "maxBasisPointsPerEntry": rules.vote.max_basis_points_per_entry,
            "maxBytes": rules.vote.max_bytes,
        },
        "name": {
            "minLength": rules.name.min_length,
            "maxLength": rules.name.max_length,
            "characters": rules.name.characters,
        },
        "burn": { "minAmount": amount_value(rules.burn.min_amount) },
        "fees": {
            "dynamic": dynamic,
            "floorAvailable": rules.fees.floor_available,
        },
        "resignation": {
            "blocksBeforeRevoke": rules.resignation.blocks_before_revoke,
        },
        "maxTransactionBytes": rules.max_transaction_bytes,
        "maxAmount": amount_value(rules.max_amount),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const CONFIGURATION: &str = include_str!("../tests/data/devnet-configuration.json");

    pub(crate) fn devnet_profile() -> Profile {
        crate::profile::from_json(
            r#"{"id":"devnet","backend":"solar-compat","api":{"relays":["http://127.0.0.1:4003/api"]},"chain":{"networkByte":90},"keyScheme":"bip32-secp256k1"}"#,
        )
        .unwrap()
    }

    pub(crate) fn devnet() -> Chain {
        load(&devnet_profile(), CONFIGURATION).unwrap()
    }

    #[test]
    fn load_and_describe() {
        let chain = devnet();
        assert_eq!(chain.network_byte(), 90);
        assert_eq!(chain.nethash().len(), 64);
        let pinned: Value =
            serde_json::from_str(&crate::profile::to_json(chain.profile())).unwrap();
        assert_eq!(pinned["chain"]["nethash"], chain.nethash());
        let token: Value = serde_json::from_str(&token(&chain)).unwrap();
        assert_eq!(token["decimals"], 8);
        assert_eq!(token["assetId"], "ROOT");
        let rules: Value = serde_json::from_str(&rules(&chain, 2)).unwrap();
        assert_eq!(rules["memo"]["maxBytes"], 255);
        assert_eq!(rules["transfer"]["maxRecipients"], 256);
        let economics: Value = serde_json::from_str(&economics(&chain, 2)).unwrap();
        assert_eq!(economics["seats"], 53);
        assert_eq!(stage_at(&chain, 2), "s1");

        let other = crate::profile::from_json(
            r#"{"id":"devnet","backend":"solar-compat","api":{"relays":[]},"chain":{"networkByte":30},"keyScheme":"bip32-secp256k1"}"#,
        )
        .unwrap();
        assert_eq!(
            load(&other, CONFIGURATION).unwrap_err().code(),
            "NetworkMismatch"
        );
    }

    #[test]
    fn from_the_node_client() {
        let mut data: Value = serde_json::from_str(CONFIGURATION).unwrap();
        let nethash = data["network"]["nethash"].clone();
        data["genesisBlock"] = json!({ "height": 1, "payloadHash": nethash });
        let body = json!({ "data": data }).to_string();
        let profile = devnet_profile();
        let chain = from_node(&profile, 200, "[]", body.as_bytes()).unwrap();
        assert_eq!(chain.nethash(), devnet().nethash());
        assert_eq!(
            from_node(&profile, 200, "", b"{}").unwrap_err().code(),
            "BadResponse"
        );
        assert_eq!(
            from_node(&profile, 503, "", b"{}").unwrap_err().code(),
            "Refused"
        );

        let node = |nethash: &str| {
            json!({ "data": {
                "core": { "version": "4.3.1" }, "nethash": nethash, "slip44": 1, "wif": 252,
                "token": "dROOT", "symbol": "dRT", "explorer": "", "version": 90,
                "constants": { "activeDelegates": 53, "blockTime": 8 },
                "pool": { "maxTransactionsInPool": 15000, "maxTransactionsPerSender": 150,
                          "maxTransactionsPerRequest": 40, "maxTransactionAge": 2700,
                          "maxTransactionBytes": 2000000 }
            } })
            .to_string()
        };
        let configuration: Value = serde_json::from_str(
            &check_node(&chain, 200, "", node(chain.nethash()).as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(configuration["pool"]["maxTransactionsPerRequest"], 40);
        assert_eq!(configuration["seats"], 53);
        assert_eq!(
            check_node(&chain, 200, "", node(&"ab".repeat(32)).as_bytes())
                .unwrap_err()
                .code(),
            "NetworkMismatch"
        );
    }
}
