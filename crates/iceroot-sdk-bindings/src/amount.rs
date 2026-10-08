//! Amounts: exact decimal text and base units, with no floating point anywhere.

use iceroot_sdk::Amount;
use iceroot_sdk::amount::FormatOptions;

use crate::error::{BindingError, Result};

/// The base units of the decimal amount `text` of an asset with `decimals` fraction digits, as a
/// decimal string. More fraction digits than the asset has are refused with `InvalidAmount`.
pub fn parse_amount(text: &str, decimals: u8) -> Result<String> {
    Ok(Amount::parse(text, decimals)?.base_units().to_string())
}

/// The base units `units` (a decimal string) as decimal text with `decimals` fraction digits.
/// `max_fraction` cuts further digits off, never rounding; `grouping` groups the whole part in
/// threes with commas.
pub fn format_amount(
    units: &str,
    decimals: u8,
    max_fraction: Option<u8>,
    grouping: bool,
) -> Result<String> {
    let units = crate::json::decimal(&serde_json::Value::String(units.to_owned()), "the amount")
        .map_err(|_| BindingError::argument("the amount is not a decimal integer of base units"))?;
    Ok(Amount::from_base_units(units).format(
        decimals,
        FormatOptions {
            max_fraction,
            grouping,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        assert_eq!(parse_amount("1.5", 8).unwrap(), "150000000");
        assert_eq!(
            parse_amount("1.123456789", 8).unwrap_err().code(),
            "InvalidAmount"
        );
        assert_eq!(format_amount("150000000", 8, None, false).unwrap(), "1.5");
        assert_eq!(
            format_amount("123456789012345678", 8, Some(2), true).unwrap(),
            "1,234,567,890.12"
        );
        assert_eq!(
            format_amount("-1", 8, None, false).unwrap_err().code(),
            "InvalidArgument"
        );
    }
}
