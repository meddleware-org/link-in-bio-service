//! Formatting times as RFC 3339 UTC timestamps.

/// `2027-11-16T00:00:00Z` for a Unix time in seconds.
pub fn rfc3339(unix: u64) -> String {
    // Whole days since the epoch, then the seconds of the day.
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // The calendar date from the day count.
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, (secs / 60) % 60, secs % 60)
}

/// A timestamp as the JSON APIs send it: RFC 3339 in UTC with `Z` and as many fractional digits as it has (none, 3, 6
/// or 9: `2026-11-17T09:41:07.123456Z`), the form chrono's serde wrote before the move to `time`.
pub fn rfc3339_full(t: ::time::OffsetDateTime) -> String {
    let t = t.to_offset(::time::UtcOffset::UTC);
    let secs = t
        .format(::time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]"))
        .unwrap_or_default();
    let fraction = match t.nanosecond() {
        0 => String::new(),
        n if n % 1_000_000 == 0 => format!(".{:03}", n / 1_000_000),
        n if n % 1_000 == 0 => format!(".{:06}", n / 1_000),
        n => format!(".{n:09}"),
    };
    format!("{secs}{fraction}Z")
}

/// Howard Hinnant's days-to-civil algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01, so leap days fall at the end of the year.
    let z = z + 719_468;
    // A 400-year era has 146 097 days.
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    // The year within the era, correcting for the century and leap-year rules.
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unit tests for the time formats.
#[cfg(test)]
mod tests {
    /// The epoch, a leap day and a recent date format correctly.
    #[test]
    fn known_dates() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::rfc3339(1_794_787_200), "2026-11-16T00:00:00Z");
    }

    /// The fraction is as short as is exact (none, 3, 6 or 9 digits), and any offset is written as UTC.
    #[test]
    fn full_precision() {
        use ::time::macros::datetime;
        assert_eq!(super::rfc3339_full(datetime!(2026-11-17 09:41:07 UTC)), "2026-11-17T09:41:07Z");
        assert_eq!(super::rfc3339_full(datetime!(2026-11-17 09:41:07.1 UTC)), "2026-11-17T09:41:07.100Z");
        assert_eq!(super::rfc3339_full(datetime!(2026-11-17 09:41:07.12345 UTC)), "2026-11-17T09:41:07.123450Z");
        assert_eq!(super::rfc3339_full(datetime!(2026-11-17 09:41:07.123456789 UTC)), "2026-11-17T09:41:07.123456789Z");
        assert_eq!(super::rfc3339_full(datetime!(2026-11-17 10:41:07 +01:00)), "2026-11-17T09:41:07Z");
    }
}
