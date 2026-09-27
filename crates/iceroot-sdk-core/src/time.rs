//! RFC 3339 timestamps in UTC, without a clock: the caller passes the time.

/// Milliseconds per day.
const DAY_MS: i64 = 86_400_000;

/// Days from 1970-01-01 to the proleptic Gregorian date `year`-`month`-`day`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of `days` after 1970-01-01: year, month and day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The digits of `text` as a number, if it is exactly `width` ASCII digits.
fn digits(text: &str, width: usize) -> Option<i64> {
    if text.len() != width || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Milliseconds since 1970-01-01T00:00:00Z of the RFC 3339 timestamp `text`:
/// `YYYY-MM-DDTHH:MM:SS`, an optional fraction of a second (milliseconds kept, further digits
/// cut off), and `Z` or an offset `+HH:MM` / `-HH:MM`. A timestamp without a zone is refused, as
/// its instant would depend on the reader's time zone.
pub(crate) fn parse_rfc3339_ms(text: &str) -> Option<i64> {
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = digits(date_parts.next()?, 4)?;
    let month = digits(date_parts.next()?, 2)?;
    let day = digits(date_parts.next()?, 2)?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }

    let (clock, offset_minutes) = if let Some(clock) = time.strip_suffix('Z') {
        (clock, 0)
    } else {
        let split = time.len().checked_sub(6)?;
        let (clock, zone) = (time.get(..split)?, time.get(split..)?);
        let sign = match zone.get(..1)? {
            "+" => 1,
            "-" => -1,
            _ => return None,
        };
        let (hours, minutes) = zone.get(1..)?.split_once(':')?;
        let (hours, minutes) = (digits(hours, 2)?, digits(minutes, 2)?);
        if hours > 23 || minutes > 59 {
            return None;
        }
        (clock, sign * (hours * 60 + minutes))
    };
    let (clock, fraction) = match clock.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (clock, None),
    };
    let mut clock_parts = clock.split(':');
    let hour = digits(clock_parts.next()?, 2)?;
    let minute = digits(clock_parts.next()?, 2)?;
    let second = digits(clock_parts.next()?, 2)?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let millis = match fraction {
        None => 0,
        Some(fraction) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let kept = fraction.get(..fraction.len().min(3))?;
            digits(kept, kept.len())? * 10_i64.pow(3 - u32::try_from(kept.len()).ok()?)
        }
    };
    let days = days_from_civil(year, month, day);
    Some(days * DAY_MS + ((hour * 60 + minute - offset_minutes) * 60 + second) * 1000 + millis)
}

/// The RFC 3339 text of `seconds` since 1970-01-01T00:00:00Z, in UTC with whole seconds:
/// `YYYY-MM-DDTHH:MM:SSZ`. `None` outside the years 0 to 9999.
pub(crate) fn format_rfc3339_seconds(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.5Z"), Some(500));
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.1239Z"), Some(123));
        assert_eq!(
            parse_rfc3339_ms("2026-09-26T12:34:56Z"),
            Some(1_790_426_096_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2026-09-26T14:34:56+02:00"),
            Some(1_790_426_096_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2026-09-26T10:34:56-02:00"),
            Some(1_790_426_096_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
        for bad in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-26T24:00:00Z",
            "2026-09-26T23:59:60Z",
            "2026-09-26T12:34:56",
            "2026-09-26 12:34:56Z",
            "2026-9-26T12:34:56Z",
            "2026-09-26T12:34:56.Z",
            "2026-09-26T12:34:56+2:00",
            "",
            "+02026-09-26T12:34:56Z",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn format() {
        assert_eq!(
            format_rfc3339_seconds(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            format_rfc3339_seconds(1_790_426_096).as_deref(),
            Some("2026-09-26T12:34:56Z")
        );
        assert_eq!(
            format_rfc3339_seconds(-1).as_deref(),
            Some("1969-12-31T23:59:59Z")
        );
        assert_eq!(format_rfc3339_seconds(i64::MAX / 2), None);
        for seconds in (0..4_000_000_000_i64).step_by(7_777_777) {
            let text = format_rfc3339_seconds(seconds).unwrap();
            assert_eq!(parse_rfc3339_ms(&text), Some(seconds * 1000), "{text}");
        }
    }
}
