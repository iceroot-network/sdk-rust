//! The serialized form of drafts and signed transactions.
//!
//! A JSON object in UTF-8, so that it can be read in any context that shows it:
//!
//! ```text
//! {
//!   "format": "iceroot-sdk/draft" | "iceroot-sdk/signed",
//!   "version": 1,
//!   "profile": "devnet",
//!   "stage": "s1",
//!   "network": { "byte": 90, "nethash": "<64 hex digits>" },
//!   "configuration": { "network": { ... }, "milestones": [ ... ] },
//!   "height": 123,
//!   "transaction": "<hex of the unsigned or signed bytes>",
//!   "fee": { "source": "floor" | "node-statistics" | "explicit", "floor": "<base units>" | null },
//!   "secondPublicKey": "<hex>" | null
//! }
//! ```
//!
//! `fee` and `secondPublicKey` belong to drafts only. The configuration is the network
//! description and milestones the draft was built under, so a context without network access can
//! sign; it is loaded again and checked against the reader's profile, whose network hash must be
//! pinned.
//!
//! The reader takes the fee from the transaction itself and computes its floor again: `fee.floor`
//! is written for other readers and checked only for its form, and `fee.source` is a claim that
//! [`super::Draft::deserialize`] checks against the floor.

use heartwood_crypto::identities::PublicKey;
use heartwood_crypto::utils::hex;
use serde_json::{Map, Value, json};

use crate::amount::Amount;
use crate::chain::Chain;
use crate::error::{Error, MismatchProblem};
use crate::fee::{FeeSource, ResolvedFee};
use crate::profile::{Profile, Stage};

/// The largest serialized form read, in bytes.
const MAX_BYTES: usize = 1 << 20;

/// The format version.
const VERSION: u64 = 1;

/// What a serialized form holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeKind {
    /// An unsigned draft.
    Draft,
    /// A signed transaction.
    Signed,
}

impl EnvelopeKind {
    const fn format(self) -> &'static str {
        match self {
            EnvelopeKind::Draft => "iceroot-sdk/draft",
            EnvelopeKind::Signed => "iceroot-sdk/signed",
        }
    }
}

/// The fields of a serialized form besides the chain.
#[derive(Debug, Clone)]
pub(crate) struct Envelope {
    pub(crate) kind: EnvelopeKind,
    pub(crate) height: u32,
    pub(crate) transaction: Vec<u8>,
    pub(crate) fee: Option<ResolvedFee>,
    pub(crate) second_key: Option<PublicKey>,
}

/// An [`Error::InvalidDraft`] for `reason`.
pub(crate) fn invalid(reason: &str) -> Error {
    Error::InvalidDraft {
        reason: reason.to_owned(),
    }
}

/// `Ok` when a serialized transaction's own network byte, `network`, is the network byte of
/// `chain`; else [`Error::NetworkMismatch`], as for any other part of the serialized form that
/// names another network.
pub(crate) fn check_network(network: u8, chain: &Chain) -> Result<(), Error> {
    let expected = chain.network_byte();
    if network == expected {
        Ok(())
    } else {
        Err(Error::NetworkMismatch {
            problem: MismatchProblem::NetworkByte {
                expected,
                actual: network,
            },
        })
    }
}

impl Envelope {
    /// The serialized form, for `chain`.
    pub(crate) fn encode(&self, chain: &Chain) -> Vec<u8> {
        // The configuration loaded, so it is JSON; it is embedded as values.
        let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
        let mut out = Map::new();
        out.insert("format".into(), json!(self.kind.format()));
        out.insert("version".into(), json!(VERSION));
        out.insert("profile".into(), json!(chain.profile().id()));
        out.insert("stage".into(), json!(chain.stage_at(self.height).as_str()));
        out.insert(
            "network".into(),
            json!({ "byte": chain.network_byte(), "nethash": chain.nethash() }),
        );
        out.insert(
            "configuration".into(),
            json!({
                "network": parse(chain.network_json()),
                "milestones": parse(chain.milestones_json()),
            }),
        );
        out.insert("height".into(), json!(self.height));
        out.insert("transaction".into(), json!(hex::encode(&self.transaction)));
        if self.kind == EnvelopeKind::Draft {
            out.insert(
                "fee".into(),
                match self.fee {
                    Some(fee) => json!({
                        "source": fee.source.as_str(),
                        "floor": fee.floor.map(|floor| floor.to_string()),
                    }),
                    None => Value::Null,
                },
            );
            out.insert(
                "secondPublicKey".into(),
                json!(self.second_key.as_ref().map(PublicKey::to_hex)),
            );
        }
        Value::Object(out).to_string().into_bytes()
    }
}

/// Read the serialized form `bytes` of `kind` for `profile`: the chain it names, loaded and
/// checked against the profile, and its fields.
pub(crate) fn decode(
    bytes: &[u8],
    profile: &Profile,
    kind: EnvelopeKind,
) -> Result<(Chain, Envelope), Error> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid("larger than 1 MiB"));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid("not JSON"))?;
    let object = value.as_object().ok_or_else(|| invalid("not an object"))?;
    let text = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(&format!("no {key}")))
    };
    if text("format")? != kind.format() {
        return Err(invalid("another format"));
    }
    if object.get("version").and_then(Value::as_u64) != Some(VERSION) {
        return Err(invalid("another version"));
    }
    let named = text("profile")?;
    if named != profile.id() {
        return Err(Error::NetworkMismatch {
            problem: MismatchProblem::Profile {
                expected: profile.id().to_owned(),
                actual: named.to_owned(),
            },
        });
    }
    if text("stage")? != Stage::S1.as_str() {
        return Err(invalid("another format stage"));
    }
    let network = object
        .get("network")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("no network"))?;
    let byte = network
        .get("byte")
        .and_then(Value::as_u64)
        .and_then(|byte| u8::try_from(byte).ok())
        .ok_or_else(|| invalid("no network byte"))?;
    let nethash = network
        .get("nethash")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("no network hash"))?;
    let expected_byte = profile.network_byte()?;
    if byte != expected_byte {
        return Err(Error::NetworkMismatch {
            problem: MismatchProblem::NetworkByte {
                expected: expected_byte,
                actual: byte,
            },
        });
    }
    let Some(pinned) = profile.chain().nethash.as_deref() else {
        return Err(Error::NetworkMismatch {
            problem: MismatchProblem::NotPinned,
        });
    };
    if !pinned.eq_ignore_ascii_case(nethash) {
        return Err(Error::NetworkMismatch {
            problem: MismatchProblem::Nethash {
                expected: pinned.to_owned(),
                actual: nethash.to_owned(),
            },
        });
    }
    let configuration = object
        .get("configuration")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("no configuration"))?;
    let part = |key: &str| {
        configuration
            .get(key)
            .map(Value::to_string)
            .ok_or_else(|| invalid(&format!("no configuration {key}")))
    };
    // Loading checks the configuration's own network byte and hash against the profile.
    let chain = Chain::from_parts(profile, &part("network")?, &part("milestones")?)?;

    let height = object
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| invalid("no height"))?;
    let transaction = hex::decode(text("transaction")?).map_err(|_| invalid("not hex"))?;
    let (fee, second_key) = match kind {
        EnvelopeKind::Signed => (None, None),
        EnvelopeKind::Draft => {
            let fee = object
                .get("fee")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("no fee"))?;
            let source = fee
                .get("source")
                .and_then(Value::as_str)
                .and_then(FeeSource::parse)
                .ok_or_else(|| invalid("no fee source"))?;
            let floor = match fee.get("floor") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) => Some(Amount::from_base_units(
                    text.parse()
                        .map_err(|_| invalid("the fee floor is not an amount"))?,
                )),
                Some(_) => return Err(invalid("the fee floor is not an amount")),
            };
            let second_key = match object.get("secondPublicKey") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) => Some(
                    PublicKey::from_hex(text)
                        .map_err(|_| invalid("the second key is not a key"))?,
                ),
                Some(_) => return Err(invalid("the second key is not a key")),
            };
            let fee = ResolvedFee {
                amount: Amount::ZERO,
                source,
                floor,
            };
            (Some(fee), second_key)
        }
    };
    Ok((
        chain,
        Envelope {
            kind,
            height,
            transaction,
            fee,
            second_key,
        },
    ))
}
