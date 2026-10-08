//! Reading the JSON arguments the wrapper passes.
//!
//! The wrapper builds these values, but a JavaScript caller can pass anything, so every field is
//! checked and a wrong shape is an `InvalidArgument` error, never a panic.

use iceroot_sdk::Amount;
use serde_json::{Map, Value};

use crate::error::{BindingError, Result};

/// The JSON object in `text`.
pub fn parse_object(text: &str, what: &str) -> Result<Map<String, Value>> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(BindingError::argument(format!("{what} is not an object"))),
        Err(error) => Err(BindingError::argument(format!(
            "{what} is not JSON: {error}"
        ))),
    }
}

/// The member `key` of `object`, which must be present.
pub fn member<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| BindingError::argument(format!("{key} is missing")))
}

/// The member `key` of `object`, absent or `null` being `None`.
pub fn optional<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

/// The string member `key`.
pub fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    member(object, key)?
        .as_str()
        .ok_or_else(|| BindingError::argument(format!("{key} is not a string")))
}

/// The string member `key`, absent or `null` being `None`.
pub fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    optional(object, key)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| BindingError::argument(format!("{key} is not a string")))
        })
        .transpose()
}

/// The unsigned integer member `key`, at most `max`.
pub fn unsigned(object: &Map<String, Value>, key: &str, max: u64) -> Result<u64> {
    member(object, key)?
        .as_u64()
        .filter(|value| *value <= max)
        .ok_or_else(|| BindingError::argument(format!("{key} is not an integer from 0 to {max}")))
}

/// A decimal string of base units or a nonce: digits only, which the wrapper writes from a
/// `bigint`.
pub fn decimal(value: &Value, key: &str) -> Result<u128> {
    value
        .as_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 39 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u128>().ok())
        .ok_or_else(|| BindingError::argument(format!("{key} is not a decimal integer")))
}

/// The amount member `key`, a decimal string of base units.
pub fn amount(object: &Map<String, Value>, key: &str) -> Result<Amount> {
    decimal(member(object, key)?, key).map(Amount::from_base_units)
}

/// The `u64` member `key`, a decimal string.
pub fn decimal_u64(object: &Map<String, Value>, key: &str) -> Result<u64> {
    u64::try_from(decimal(member(object, key)?, key)?)
        .map_err(|_| BindingError::argument(format!("{key} is out of range")))
}

/// The array member `key`.
pub fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>> {
    member(object, key)?
        .as_array()
        .ok_or_else(|| BindingError::argument(format!("{key} is not an array")))
}

/// `value` as an object.
pub fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| BindingError::argument(format!("{what} is not an object")))
}

/// An amount as the wrapper reads it: a decimal string of base units.
pub fn amount_value(amount: Amount) -> Value {
    Value::String(amount.base_units().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_are_checked() {
        let object = parse_object(r#"{"a":"12","b":7,"c":null,"d":"x1"}"#, "o").unwrap();
        assert_eq!(amount(&object, "a").unwrap(), Amount::from_base_units(12));
        assert_eq!(unsigned(&object, "b", 10).unwrap(), 7);
        assert!(unsigned(&object, "b", 6).is_err());
        assert_eq!(optional(&object, "c"), None);
        assert!(amount(&object, "d").is_err());
        assert!(amount(&object, "missing").is_err());
        assert!(parse_object("[]", "o").is_err());
        assert!(parse_object("{", "o").is_err());
        assert!(decimal(&json!("-1"), "x").is_err());
        assert!(decimal(&json!(""), "x").is_err());
        assert!(decimal(&json!("9".repeat(40)), "x").is_err());
        assert_eq!(amount_value(Amount::from_base_units(5)), json!("5"));
    }
}
