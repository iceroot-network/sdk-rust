//! Amounts in base units, and their decimal text.
//!
//! An [`Amount`] is a whole number of base units. It holds 128 bits, enough for every stage (64-bit
//! amounts today, 128-bit amounts from the IceRoot genesis); a field that carries fewer bits
//! refuses a larger amount with [`AmountProblem::TooLarge`]. Nothing here uses floating point.
//!
//! The decimals of an amount's text come from its asset: 8 for ROOT today, 18 from the IceRoot
//! genesis ([`crate::chain::Token::decimals`]).

use std::fmt;

use crate::error::{AmountProblem, Error};

/// The most decimals an asset may have: 10^38 still fits 128 bits.
pub const MAX_DECIMALS: u8 = 38;

/// An amount in base units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Amount(u128);

/// How [`Amount::format`] writes an amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FormatOptions {
    /// The most digits after the point. Further digits are cut off, never rounded, so the text
    /// never shows more than the amount. `None` shows every significant digit.
    pub max_fraction: Option<u8>,
    /// Group the whole part in threes with commas.
    pub grouping: bool,
}

impl Amount {
    /// Zero.
    pub const ZERO: Amount = Amount(0);

    /// The amount of `units` base units.
    pub const fn from_base_units(units: u128) -> Amount {
        Amount(units)
    }

    /// The amount in base units.
    pub const fn base_units(self) -> u128 {
        self.0
    }

    /// The amount as a 64-bit field, if it fits.
    pub fn to_u64(self) -> Option<u64> {
        u64::try_from(self.0).ok()
    }

    /// Whether the amount is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The sum, if it fits.
    pub const fn checked_add(self, other: Amount) -> Option<Amount> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Amount(sum)),
            None => None,
        }
    }

    /// The amount in the decimal `text` of an asset with `decimals` decimals: `"1.5"` with 8
    /// decimals is 150,000,000 base units.
    ///
    /// The text is digits with at most one point, at least one digit on each side of a point, and
    /// no more digits after the point than `decimals`. Signs, exponents, spaces and group
    /// separators are refused, so that nothing is guessed.
    pub fn parse(text: &str, decimals: u8) -> Result<Amount, Error> {
        let invalid = |problem| Error::InvalidAmount { problem };
        if decimals > MAX_DECIMALS {
            return Err(invalid(AmountProblem::Decimals { decimals }));
        }
        if text.is_empty() {
            return Err(invalid(AmountProblem::Empty));
        }
        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (text, None),
        };
        let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || fraction.is_some_and(|fraction| !digits(fraction)) {
            return Err(invalid(AmountProblem::Format));
        }
        let fraction = fraction.unwrap_or_default();
        if fraction.len() > usize::from(decimals) {
            return Err(invalid(AmountProblem::TooManyDecimals { decimals }));
        }
        let mut units: u128 = 0;
        let padding = usize::from(decimals) - fraction.len();
        for byte in whole
            .bytes()
            .chain(fraction.bytes())
            .chain(std::iter::repeat_n(b'0', padding))
        {
            units = units
                .checked_mul(10)
                .and_then(|units| units.checked_add(u128::from(byte - b'0')))
                .ok_or(invalid(AmountProblem::TooLarge))?;
        }
        Ok(Amount(units))
    }

    /// The decimal text of the amount for an asset with `decimals` decimals, without trailing
    /// zeros after the point: 150,000,000 base units with 8 decimals is `"1.5"`.
    ///
    /// `decimals` above [`MAX_DECIMALS`] are read as [`MAX_DECIMALS`].
    pub fn format(self, decimals: u8, options: FormatOptions) -> String {
        let decimals = usize::from(decimals.min(MAX_DECIMALS));
        let digits = format!("{:0width$}", self.0, width = decimals + 1);
        let (whole, fraction) = digits.split_at(digits.len() - decimals);
        let mut fraction = fraction.trim_end_matches('0');
        if let Some(max) = options.max_fraction {
            fraction = fraction
                .get(..usize::from(max).min(fraction.len()))
                .unwrap_or(fraction)
                .trim_end_matches('0');
        }
        let whole = if options.grouping {
            group_thousands(whole)
        } else {
            whole.to_owned()
        };
        if fraction.is_empty() {
            whole
        } else {
            format!("{whole}.{fraction}")
        }
    }
}

impl fmt::Display for Amount {
    /// The amount in base units.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Amount {
    fn from(units: u64) -> Amount {
        Amount(u128::from(units))
    }
}

/// `digits` with a comma before every group of three from the right.
fn group_thousands(digits: &str) -> String {
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// An asset's identity. Assets are identified by id, never by symbol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AssetId {
    /// ROOT, the network's own asset. Today it is the only asset.
    Root,
}

impl AssetId {
    /// The stable string form: `ROOT` for ROOT.
    pub const fn as_str(&self) -> &'static str {
        match self {
            AssetId::Root => "ROOT",
        }
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(text: &str, decimals: u8) -> AmountProblem {
        match Amount::parse(text, decimals) {
            Err(Error::InvalidAmount { problem }) => problem,
            other => panic!("{text}: {other:?}"),
        }
    }

    #[test]
    fn parse() {
        assert_eq!(Amount::parse("1.5", 8).unwrap().base_units(), 150_000_000);
        assert_eq!(Amount::parse("0", 8).unwrap(), Amount::ZERO);
        assert_eq!(Amount::parse("0.00000001", 8).unwrap().base_units(), 1);
        assert_eq!(Amount::parse("007", 0).unwrap().base_units(), 7);
        assert_eq!(
            Amount::parse("100000000", 8).unwrap().base_units(),
            10_000_000_000_000_000
        );
        assert_eq!(
            Amount::parse("1", 18).unwrap().base_units(),
            1_000_000_000_000_000_000
        );
        assert_eq!(
            Amount::parse("340282366920938463463374607431768211455", 0)
                .unwrap()
                .base_units(),
            u128::MAX
        );
        assert_eq!(
            problem("340282366920938463463374607431768211456", 0),
            AmountProblem::TooLarge
        );
        assert_eq!(problem("4", 38), AmountProblem::TooLarge);
        assert_eq!(problem("", 8), AmountProblem::Empty);
        for text in [
            "1.", ".5", "-1", "+1", "1e8", " 1", "1 ", "1,000", "1.2.3", "٣", "0x10",
        ] {
            assert_eq!(problem(text, 8), AmountProblem::Format, "{text:?}");
        }
        assert_eq!(
            problem("0.000000001", 8),
            AmountProblem::TooManyDecimals { decimals: 8 }
        );
        assert_eq!(problem("1", 39), AmountProblem::Decimals { decimals: 39 });
    }

    #[test]
    fn format() {
        let plain = FormatOptions::default();
        assert_eq!(Amount::from_base_units(150_000_000).format(8, plain), "1.5");
        assert_eq!(Amount::from_base_units(1).format(8, plain), "0.00000001");
        assert_eq!(Amount::ZERO.format(8, plain), "0");
        assert_eq!(Amount::from_base_units(123).format(0, plain), "123");
        let grouped = FormatOptions {
            max_fraction: Some(2),
            grouping: true,
        };
        assert_eq!(
            Amount::from_base_units(123_456_789_999_999_999).format(8, grouped),
            "1,234,567,899.99"
        );
        assert_eq!(Amount::from_base_units(100_000_000).format(8, grouped), "1");
        assert_eq!(Amount::from_base_units(100_900_000).format(8, grouped), "1");
        assert_eq!(Amount::from_base_units(999).format(0, grouped), "999");
        assert_eq!(Amount::from_base_units(1000).format(0, grouped), "1,000");
        assert_eq!(
            Amount::from_base_units(u128::MAX).format(38, plain),
            "3.40282366920938463463374607431768211455"
        );
    }

    #[test]
    fn round_trip() {
        for units in [
            0u128,
            1,
            9,
            10,
            99_999_999,
            100_000_000,
            123_456_789_012,
            u128::MAX,
        ] {
            for decimals in [0u8, 1, 8, 18, 38] {
                let amount = Amount::from_base_units(units);
                let text = amount.format(decimals, FormatOptions::default());
                assert_eq!(Amount::parse(&text, decimals), Ok(amount), "{text}");
            }
        }
    }
}
