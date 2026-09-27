//! A network's loaded configuration: the chain a profile is bound to.
//!
//! [`Chain::load`] reads the crypto configuration a node reports (`/node/configuration/crypto` on
//! the relay API: the network description, the milestones and the genesis block), loads it with
//! `heartwood-crypto`, and checks it against the profile: the network byte always, the network
//! hash when the profile has one pinned. A devnet profile without a pinned hash is pinned by the
//! first load ([`Chain::profile`] returns the pinned profile, for the application to keep); a
//! later load of another chain is refused with [`Error::NetworkMismatch`].
//!
//! A chain answers the questions that depend on the milestone in force: the rules
//! ([`Chain::rules`]) and the economics ([`Chain::economics`]) at a height, and the format stage.
//! Drafts are built against a chain ([`crate::transaction::Draft::build`]).

use std::sync::Arc;

use heartwood_crypto::managers::{Milestones, Network, Params};
use serde_json::Value;

use crate::amount::{Amount, AssetId};
use crate::economics::Economics;
use crate::error::{Error, MismatchProblem};
use crate::fee;
use crate::profile::{Capability, Profile, Stage};
use crate::rules::Rules;
use crate::transaction::OperationKind;

/// The decimals of ROOT in today's formats.
pub const S1_DECIMALS: u8 = 8;

/// The network's own asset, as clients show it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token {
    /// The asset: ROOT.
    pub asset: AssetId,
    /// The name the network's configuration gives it.
    pub name: String,
    /// The symbol the network's configuration gives it.
    pub symbol: String,
    /// Decimals of its amounts: 8 in today's formats.
    pub decimals: u8,
}

/// A network's loaded configuration, bound to a profile. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Chain {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    profile: Profile,
    network: Network,
    milestones: Milestones,
    /// The network description and milestones as JSON text, for serialized drafts.
    network_json: String,
    milestones_json: String,
}

impl PartialEq for Chain {
    fn eq(&self, other: &Chain) -> bool {
        self.inner.profile == other.inner.profile
            && self.inner.network_json == other.inner.network_json
            && self.inner.milestones_json == other.inner.milestones_json
    }
}

impl Chain {
    /// Load the crypto configuration `json` a node reports for `profile`: a JSON object with
    /// `network` (the network description), `milestones` (the milestone list) and optionally
    /// `genesisBlock`, whose `payloadHash` must then be the network hash. This is the `data`
    /// object of the relay API's `/node/configuration/crypto`.
    pub fn load(profile: &Profile, json: &str) -> Result<Chain, Error> {
        let value: Value = serde_json::from_str(json).map_err(|error| Error::BadResponse {
            reason: format!("the crypto configuration is not JSON: {error}"),
        })?;
        let object = value.as_object().ok_or_else(|| Error::BadResponse {
            reason: "the crypto configuration is not an object".to_owned(),
        })?;
        let part = |key: &str| {
            object.get(key).ok_or_else(|| Error::BadResponse {
                reason: format!("the crypto configuration has no {key}"),
            })
        };
        let network = part("network")?;
        let milestones = part("milestones")?;
        let chain = Chain::from_parts(profile, &network.to_string(), &milestones.to_string())?;
        if let Some(genesis) = object.get("genesisBlock") {
            let payload_hash = genesis.get("payloadHash").and_then(Value::as_str);
            if payload_hash.is_none_or(|hash| !hash.eq_ignore_ascii_case(chain.nethash())) {
                return Err(Error::BadResponse {
                    reason: "the genesis block's payload hash is not the network hash".to_owned(),
                });
            }
        }
        Ok(chain)
    }

    /// Load the network description `network_json` (`network.json`) and the milestones
    /// `milestones_json` (`milestones.json`) for `profile`.
    pub fn from_parts(
        profile: &Profile,
        network_json: &str,
        milestones_json: &str,
    ) -> Result<Chain, Error> {
        profile.require(Capability::Connect)?;
        let expected_byte = profile.network_byte()?;
        let bad = |what: &str, error: &dyn std::fmt::Display| Error::BadResponse {
            reason: format!("the {what} do not load: {error}"),
        };
        let network =
            Network::load(network_json).map_err(|error| bad("network settings", &error))?;
        if network.pub_key_hash != expected_byte {
            return Err(Error::NetworkMismatch {
                problem: MismatchProblem::NetworkByte {
                    expected: expected_byte,
                    actual: network.pub_key_hash,
                },
            });
        }
        let nethash = network.nethash.to_ascii_lowercase();
        if !Profile::is_nethash(&nethash) {
            return Err(Error::BadResponse {
                reason: "the network hash is not 64 hex digits".to_owned(),
            });
        }
        if !profile.accepts_nethash(&nethash) {
            return Err(Error::NetworkMismatch {
                problem: MismatchProblem::Nethash {
                    expected: profile.chain().nethash.clone().unwrap_or_default(),
                    actual: nethash,
                },
            });
        }
        let milestones = Milestones::load(milestones_json, &network)
            .map_err(|error| bad("milestones", &error))?;
        Ok(Chain {
            inner: Arc::new(Inner {
                profile: profile.pinned(&nethash),
                network,
                milestones,
                network_json: network_json.to_owned(),
                milestones_json: milestones_json.to_owned(),
            }),
        })
    }

    /// The profile, with the network hash pinned.
    pub fn profile(&self) -> &Profile {
        &self.inner.profile
    }

    /// The network hash (64 lowercase hex digits).
    pub fn nethash(&self) -> &str {
        self.inner
            .profile
            .chain()
            .nethash
            .as_deref()
            .unwrap_or_default()
    }

    /// The address network byte.
    pub fn network_byte(&self) -> u8 {
        self.inner.network.pub_key_hash
    }

    /// The network's own asset.
    pub fn token(&self) -> Token {
        Token {
            asset: AssetId::ROOT,
            name: self.inner.network.token.clone(),
            symbol: self.inner.network.symbol.clone(),
            decimals: S1_DECIMALS,
        }
    }

    /// The format stage of blocks at `height`. Every height of a network in today's formats is at
    /// [`Stage::S1`]; the post-quantum switch comes with its milestone.
    pub fn stage_at(&self, height: u32) -> Stage {
        let _ = height;
        Stage::S1
    }

    /// The rules in force at `height`.
    pub fn rules(&self, height: u32) -> Rules {
        Rules::at(self, height)
    }

    /// The economics in force at `height`.
    pub fn economics(&self, height: u32) -> Economics {
        Economics::at(self.clone(), height)
    }

    /// The exact fee floor at `height` of a transaction of `kind` that is `size` bytes long,
    /// signatures included: the node's own rule, from `heartwood-crypto` (see [`crate::fee`]).
    /// `None` where the formats have no floor function.
    pub fn fee_floor(&self, kind: OperationKind, size: usize, height: u32) -> Option<Amount> {
        fee::floor(kind, size, self.params(height))
    }

    /// The merged milestone in force at `height`, as `heartwood-crypto` holds it.
    pub fn params(&self, height: u32) -> &Params {
        self.inner.milestones.at(height)
    }

    /// Every merged milestone, as `heartwood-crypto` holds them.
    pub fn milestones(&self) -> &Milestones {
        &self.inner.milestones
    }

    /// The network description, as `heartwood-crypto` holds it.
    pub fn network(&self) -> &Network {
        &self.inner.network
    }

    /// The network description as the JSON text it was loaded from.
    pub(crate) fn network_json(&self) -> &str {
        &self.inner.network_json
    }

    /// The milestones as the JSON text they were loaded from.
    pub(crate) fn milestones_json(&self) -> &str {
        &self.inner.milestones_json
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;
    use crate::profile::DevnetOptions;

    pub(crate) const NETHASH: &str =
        "8a2cac9c4e7bb1bb8a42d1c3fd30c2c1ba5d3bf8e0e7ffb6c56c0bd6c0b50b8f";

    /// A small devnet configuration: network byte 90 and the devnet milestone of the reference
    /// implementation's rules, as JSON text.
    pub(crate) fn devnet_parts() -> (String, String) {
        let network = json!({
            "name": "devnet",
            "messagePrefix": "devnet message:\n",
            "addressCharacter": "d",
            "bip32": { "public": 70_617_039, "private": 70_615_956 },
            "pubKeyHash": 90,
            "nethash": NETHASH,
            "wif": 252,
            "slip44": 1,
            "client": { "token": "ROOT", "symbol": "ROOT", "explorer": "" }
        });
        let ranks: serde_json::Map<String, Value> = (1..=53)
            .map(|rank| (rank.to_string(), json!(200_000_000)))
            .collect();
        let milestones = json!([{
            "height": 1,
            "activeDelegates": 53,
            "block": { "version": 0, "maxTransactions": 150, "maxPayload": 2_097_152 },
            "blocksToRevokeDelegateResignation": 106,
            "blockTime": 8,
            "burn": { "feeBasisPoints": 9000, "txAmount": 2_000_000 },
            "dynamicFees": {
                "enabled": true,
                "addonBytes": {
                    "burn": 0, "delegateRegistration": 1_214_968, "delegateResignation": 0,
                    "secondSignature": 99, "transfer": 85, "vote": 98
                },
                "minFee": 6173
            },
            "epoch": "2026-01-01T00:00:00.000Z",
            "fees": { "staticFees": { "transfer": 50_000_000, "vote": 9_000_000 } },
            "transfer": { "maximum": 256, "minimum": 1 },
            "reward": 0,
            "dynamicReward": { "enabled": true, "ranks": ranks, "secondaryReward": 180_000_000 },
            "donations": {}
        }]);
        (network.to_string(), milestones.to_string())
    }

    pub(crate) fn devnet_chain() -> Chain {
        let (network, milestones) = devnet_parts();
        Chain::from_parts(
            &Profile::devnet(DevnetOptions::default()),
            &network,
            &milestones,
        )
        .unwrap()
    }

    #[test]
    fn load_and_pin() {
        let (network, milestones) = devnet_parts();
        let config = format!(
            r#"{{"network":{network},"milestones":{milestones},"genesisBlock":{{"payloadHash":"{NETHASH}"}}}}"#
        );
        let unpinned = Profile::devnet(DevnetOptions::default());
        let chain = Chain::load(&unpinned, &config).unwrap();
        assert_eq!(chain.nethash(), NETHASH);
        assert_eq!(chain.profile().chain().nethash.as_deref(), Some(NETHASH));
        assert_eq!(chain.network_byte(), 90);
        assert_eq!(chain.token().decimals, 8);
        assert_eq!(chain.token().symbol, "ROOT");
        assert_eq!(chain.stage_at(1), Stage::S1);

        // The pinned profile accepts the same chain and refuses another.
        assert!(Chain::load(chain.profile(), &config).is_ok());
        let other = unpinned.clone().with_nethash(&"00".repeat(32)).unwrap();
        assert!(matches!(
            Chain::load(&other, &config),
            Err(Error::NetworkMismatch {
                problem: MismatchProblem::Nethash { .. }
            })
        ));
        let bad_genesis = config.replace(
            &format!(r#""payloadHash":"{NETHASH}""#),
            r#""payloadHash":"00""#,
        );
        assert!(matches!(
            Chain::load(&unpinned, &bad_genesis),
            Err(Error::BadResponse { .. })
        ));
        // Hex digits in either case name the same hash, as in Chain::from_node.
        let upper_genesis = config.replace(
            &format!(r#""payloadHash":"{NETHASH}""#),
            &format!(r#""payloadHash":"{}""#, NETHASH.to_ascii_uppercase()),
        );
        assert!(Chain::load(&unpinned, &upper_genesis).is_ok());
    }

    #[test]
    fn refusals() {
        let (network, milestones) = devnet_parts();
        let profile = Profile::devnet(DevnetOptions::default());
        let byte_63 = network.replace(r#""pubKeyHash":90"#, r#""pubKeyHash":63"#);
        assert!(matches!(
            Chain::from_parts(&profile, &byte_63, &milestones),
            Err(Error::NetworkMismatch {
                problem: MismatchProblem::NetworkByte {
                    expected: 90,
                    actual: 63
                }
            })
        ));
        assert!(matches!(
            Chain::from_parts(&profile, &network, "[]"),
            Err(Error::BadResponse { .. })
        ));
        assert!(matches!(
            Chain::load(&profile, "{}"),
            Err(Error::BadResponse { .. })
        ));
        assert!(matches!(
            Chain::load(&profile, "not json"),
            Err(Error::BadResponse { .. })
        ));
        let declared = Profile::devnet_pq(DevnetOptions::default());
        assert!(matches!(
            Chain::from_parts(&declared, &network, &milestones),
            Err(Error::UnsupportedOnNetwork { .. })
        ));
    }
}
