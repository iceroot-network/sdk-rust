//! The verifier's time: the system clock, or a time given as `YYYY-MM-DDTHH:MM:SSZ`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since 1970-01-01T00:00:00Z on the system clock.
pub fn now_ms() -> Result<i64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock is before 1970".to_owned())?;
    i64::try_from(elapsed.as_millis()).map_err(|_| "the system clock is out of range".to_owned())
}

/// Milliseconds since 1970-01-01T00:00:00Z of `text`, a real UTC time written exactly as
/// `YYYY-MM-DDTHH:MM:SSZ` (the form of a link's times), from the year 1970.
pub fn parse_ms(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 20
        && bytes
            .iter()
            .enumerate()
            .all(|(position, byte)| match position {
                4 | 7 => *byte == b'-',
                10 => *byte == b'T',
                13 | 16 => *byte == b':',
                19 => *byte == b'Z',
                _ => byte.is_ascii_digit(),
            });
    if !shape {
        return None;
    }
    let field = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if year < 1970 || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the date, in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_times() {
        assert_eq!(parse_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_ms("2000-03-01T00:00:00Z"), Some(951_868_800_000));
        assert_eq!(parse_ms("2024-02-29T23:59:59Z"), Some(1_709_251_199_000));
        assert_eq!(parse_ms("2026-10-01T12:00:00Z"), Some(1_790_856_000_000));
    }

    #[test]
    fn refused_times() {
        for text in [
            "",
            "2026-10-01T12:00:00",
            "2026-10-01T12:00:00.000Z",
            "2026-10-01T12:00:00+00:00",
            "2026-10-01 12:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "1969-12-31T23:59:59Z",
            "２026-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_ms(text), None, "{text}");
        }
    }

    #[test]
    fn the_clock_is_after_1970() {
        assert!(now_ms().unwrap() > 0);
    }
}
