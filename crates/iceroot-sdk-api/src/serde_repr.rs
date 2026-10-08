//! The JSON form of the client's values (feature `serde`).
//!
//! Every binding of the SDK exchanges these values as JSON, so the form is part of the contract:
//!
//! - Field names are in camel case (`senderPublicKey`), and enum values are lower-case words joined
//!   by hyphens (`resigned-temporary`, `low-fee`).
//! - Integers of 64 bits and more (amounts, nonces, heights, times, lifetime counters) are decimal
//!   strings, because JavaScript numbers cannot hold every such value. Smaller integers (ranks,
//!   basis points, page numbers, sizes, wire types) are JSON numbers. On input a 64-bit or wider
//!   integer may also be a JSON number.
//! - An absent optional value is left out; on input `null` means absent too.
//! - An asset id is `ROOT` or 64 hex digits.
//! - A transaction kind is a `kind` field (`transfer`, `vote`, `burn`, `register-second-key`,
//!   `register-validator`, `resign-validator` or `other`), with `typeGroup` and `typeId` beside it
//!   for `other`. Transaction details are tagged by `kind` the same way, and a submission outcome
//!   by `status` (`accepted` or `rejected`).

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use crate::request::{Relay, Response};
use crate::types::{AssetId, TxKind};

/// An integer as a decimal string; on input also a JSON number.
pub(crate) mod decimal {
    use super::*;

    pub(crate) fn serialize<T: fmt::Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Integer,
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DecimalVisitor::<T>(std::marker::PhantomData))
    }
}

/// An optional integer as a decimal string, left out when absent.
pub(crate) mod decimal_option {
    use super::*;

    pub(crate) fn serialize<T: fmt::Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.collect_str(value),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: Integer,
        D: Deserializer<'de>,
    {
        struct OptionVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Integer> Visitor<'de> for OptionVisitor<T> {
            type Value = Option<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer as a decimal string, or null")
            }

            fn visit_none<E: de::Error>(self) -> Result<Option<T>, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Option<T>, E> {
                Ok(None)
            }

            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Option<T>, D::Error> {
                decimal::deserialize(d).map(Some)
            }
        }

        deserializer.deserialize_option(OptionVisitor::<T>(std::marker::PhantomData))
    }
}

/// The integer types written as decimal strings.
pub(crate) trait Integer: FromStr + TryFrom<u64> + TryFrom<i64> + TryFrom<u128> {
    /// Whether the type has negative values.
    const SIGNED: bool;
}

impl Integer for u64 {
    const SIGNED: bool = false;
}

impl Integer for u128 {
    const SIGNED: bool = false;
}

impl Integer for i64 {
    const SIGNED: bool = true;
}

struct DecimalVisitor<T>(std::marker::PhantomData<T>);

impl<T: Integer> Visitor<'_> for DecimalVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an integer as a decimal string")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        let digits = match text.strip_prefix('-') {
            Some(rest) if T::SIGNED => rest,
            _ => text,
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(E::custom(format!("{text:?} is not a decimal integer")));
        }
        text.parse()
            .map_err(|_| E::custom(format!("{text} is out of range")))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<T, E> {
        T::try_from(value).map_err(|_| E::custom(format!("{value} is out of range")))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<T, E> {
        T::try_from(value).map_err(|_| E::custom(format!("{value} is out of range")))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<T, E> {
        T::try_from(value).map_err(|_| E::custom(format!("{value} is out of range")))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<T, E> {
        Err(E::custom(format!(
            "{value} is not an integer written as a decimal string"
        )))
    }
}

// ------------------------------------------------------------------------------------------------
// Asset ids

impl Serialize for AssetId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AssetId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        AssetId::parse(&text).ok_or_else(|| {
            de::Error::custom(format!(
                "{text:?} is not an asset id (ROOT or 64 hex digits)"
            ))
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Transaction kinds

const KIND_FIELDS: &[&str] = &["kind", "typeGroup", "typeId"];

/// A transaction kind is written as the fields `kind`, and for other kinds `typeGroup` and
/// `typeId`, so that a record holding one flattens it among its own fields.
impl Serialize for TxKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let other = match self {
            TxKind::Other {
                type_group,
                type_id,
            } => Some((*type_group, *type_id)),
            _ => None,
        };
        let mut map = serializer.serialize_map(Some(if other.is_some() { 3 } else { 1 }))?;
        map.serialize_entry("kind", self.as_str())?;
        if let Some((type_group, type_id)) = other {
            map.serialize_entry("typeGroup", &type_group)?;
            map.serialize_entry("typeId", &type_id)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for TxKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KindVisitor;

        impl<'de> Visitor<'de> for KindVisitor {
            type Value = TxKind;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a transaction kind: { kind, typeGroup?, typeId? }")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<TxKind, A::Error> {
                let mut kind: Option<String> = None;
                let mut type_group: Option<u32> = None;
                let mut type_id: Option<u16> = None;
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "kind" => kind = Some(map.next_value()?),
                        "typeGroup" => type_group = map.next_value()?,
                        "typeId" => type_id = map.next_value()?,
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                let kind = kind.ok_or_else(|| de::Error::missing_field("kind"))?;
                match (kind.as_str(), type_group, type_id) {
                    ("other", Some(type_group), Some(type_id)) => Ok(TxKind::Other {
                        type_group,
                        type_id,
                    }),
                    ("other", _, _) => Err(de::Error::custom(
                        "a transaction kind \"other\" needs typeGroup and typeId",
                    )),
                    (name, None, None) => TxKind::from_name(name).ok_or_else(|| {
                        de::Error::custom(format!("{name:?} is not a transaction kind"))
                    }),
                    (name, _, _) => Err(de::Error::custom(format!(
                        "the transaction kind {name:?} takes no typeGroup or typeId"
                    ))),
                }
            }
        }

        deserializer.deserialize_struct("TxKind", KIND_FIELDS, KindVisitor)
    }
}

/// The extra byte-units per kind of the pool's fee settings: `[{ kind, typeGroup?, typeId?,
/// bytes }]`.
pub(crate) mod addon_bytes {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Entry {
        #[serde(flatten)]
        kind: TxKind,
        #[serde(with = "decimal")]
        bytes: u64,
    }

    #[derive(Serialize)]
    struct EntryRef<'a> {
        #[serde(flatten)]
        kind: &'a TxKind,
        #[serde(with = "decimal")]
        bytes: &'a u64,
    }

    pub(crate) fn serialize<S: Serializer>(
        entries: &[(TxKind, u64)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(entries.len()))?;
        for (kind, bytes) in entries {
            seq.serialize_element(&EntryRef { kind, bytes })?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<(TxKind, u64)>, D::Error> {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|e| (e.kind, e.bytes)).collect())
    }
}

// ------------------------------------------------------------------------------------------------
// Relays and responses

impl Serialize for Relay {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Relay {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Relay::parse(&text).map_err(de::Error::custom)
    }
}

/// A response: `{ status, headers: [[name, value]], body }`, the body being the text the node
/// sent (node APIs answer JSON, which is UTF-8).
#[derive(Serialize, Deserialize)]
struct ResponseRepr<'a> {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(borrow)]
    body: std::borrow::Cow<'a, str>,
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let body = std::str::from_utf8(self.body())
            .map_err(|_| serde::ser::Error::custom("the response body is not UTF-8 text"))?;
        ResponseRepr {
            status: self.status(),
            headers: self.headers().to_vec(),
            body: std::borrow::Cow::Borrowed(body),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = ResponseRepr::deserialize(deserializer)?;
        let mut response = Response::new(repr.status, repr.body.into_owned().into_bytes());
        for (name, value) in repr.headers {
            response = response.with_header(name, value);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Numbers {
        #[serde(with = "decimal")]
        wide: u128,
        #[serde(with = "decimal")]
        signed: i64,
        #[serde(
            default,
            with = "decimal_option",
            skip_serializing_if = "Option::is_none"
        )]
        maybe: Option<u64>,
    }

    #[test]
    fn integers_are_decimal_strings() {
        let value = Numbers {
            wide: u128::MAX,
            signed: -5,
            maybe: Some(u64::MAX),
        };
        let text = serde_json::to_value(&value).unwrap();
        assert_eq!(
            text,
            json!({ "wide": u128::MAX.to_string(), "signed": "-5", "maybe": u64::MAX.to_string() })
        );
        assert_eq!(serde_json::from_value::<Numbers>(text).unwrap(), value);
        let numbers: Numbers =
            serde_json::from_value(json!({ "wide": 7, "signed": -1, "maybe": null })).unwrap();
        assert_eq!((numbers.wide, numbers.signed, numbers.maybe), (7, -1, None));
        for bad in [
            json!({ "wide": "-1", "signed": "0" }),
            json!({ "wide": "+1", "signed": "0" }),
            json!({ "wide": "1.5", "signed": "0" }),
            json!({ "wide": "", "signed": "0" }),
            json!({ "wide": 1.5, "signed": "0" }),
            json!({ "wide": "1", "signed": "--1" }),
            json!({ "wide": "1", "signed": "0", "maybe": "18446744073709551616" }),
        ] {
            assert!(
                serde_json::from_value::<Numbers>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn kinds_and_assets() {
        let other = TxKind::Other {
            type_group: 1,
            type_id: 4,
        };
        assert_eq!(
            serde_json::to_value(other).unwrap(),
            json!({ "kind": "other", "typeGroup": 1, "typeId": 4 })
        );
        assert_eq!(
            serde_json::to_value(TxKind::RegisterSecondKey).unwrap(),
            json!({ "kind": "register-second-key" })
        );
        for kind in [
            TxKind::Transfer,
            TxKind::Vote,
            TxKind::Burn,
            TxKind::RegisterSecondKey,
            TxKind::RegisterValidator,
            TxKind::ResignValidator,
            other,
        ] {
            let value = serde_json::to_value(kind).unwrap();
            assert_eq!(serde_json::from_value::<TxKind>(value).unwrap(), kind);
        }
        for bad in [
            json!({ "kind": "other" }),
            json!({ "kind": "vote", "typeGroup": 2, "typeId": 2 }),
            json!({ "kind": "delegate" }),
            json!({}),
        ] {
            assert!(
                serde_json::from_value::<TxKind>(bad.clone()).is_err(),
                "{bad}"
            );
        }

        assert_eq!(serde_json::to_value(AssetId::ROOT).unwrap(), json!("ROOT"));
        let id = AssetId::from_bytes([0xab; 32]);
        let text = serde_json::to_value(id).unwrap();
        assert_eq!(text, json!("ab".repeat(32)));
        assert_eq!(serde_json::from_value::<AssetId>(text).unwrap(), id);
        assert_eq!(
            serde_json::from_value::<AssetId>(json!("AB".repeat(32))).unwrap(),
            id
        );
        assert_eq!(
            serde_json::from_value::<AssetId>(json!("00".repeat(32))).unwrap(),
            AssetId::ROOT
        );
        for bad in ["root", "ab", "zz".repeat(32).as_str()] {
            assert!(
                serde_json::from_value::<AssetId>(json!(bad)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn relays_and_responses() {
        let relay: Relay = serde_json::from_value(json!("http://127.0.0.1:4003/api/")).unwrap();
        assert_eq!(
            serde_json::to_value(&relay).unwrap(),
            json!("http://127.0.0.1:4003/api")
        );
        assert!(serde_json::from_value::<Relay>(json!("ftp://x")).is_err());

        let response = Response::new(429, "{}").with_header("Retry-After", "3");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value,
            json!({ "status": 429, "headers": [["Retry-After", "3"]], "body": "{}" })
        );
        assert_eq!(serde_json::from_value::<Response>(value).unwrap(), response);
        let bare: Response = serde_json::from_value(json!({ "status": 200, "body": "" })).unwrap();
        assert_eq!(bare, Response::new(200, ""));
        assert!(serde_json::to_value(Response::new(200, vec![0xff])).is_err());
    }
}
