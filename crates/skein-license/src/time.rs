//! ISO 8601 timestamps as milliseconds since the epoch, both ways, with no
//! date crate — the conversion is Howard Hinnant's civil-days algorithm.

const DAY_MS: i64 = 86_400_000;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

fn digits(s: &str) -> Option<i64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `YYYY-MM-DD`, or `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`, to milliseconds.
/// `None` for anything else — including a date that does not exist.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = match s.split_once(['T', 't']) {
        Some((d, r)) => (d, Some(r)),
        None => (s, None),
    };
    let mut parts = date.split('-');
    let (y, m, d) = (
        digits(parts.next()?)?,
        digits(parts.next()?)?,
        digits(parts.next()?)?,
    );
    if parts.next().is_some() || !(1..=12).contains(&m) || d < 1 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    // A day that does not exist (31 February) round-trips to another one.
    if civil_from_days(days) != (y, m, d) {
        return None;
    }
    let Some(rest) = rest else {
        return Some(days * DAY_MS);
    };
    let (clock, offset_ms) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, 0)
    } else {
        let at = rest.rfind(['+', '-'])?;
        let (c, off) = rest.split_at(at);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        (c, sign * (digits(oh)? * 3_600_000 + digits(om)? * 60_000))
    };
    let (hms, frac) = match clock.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (clock, None),
    };
    let mut t = hms.split(':');
    let (h, mi, se) = (digits(t.next()?)?, digits(t.next()?)?, digits(t.next()?)?);
    if t.next().is_some() || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let ms = match frac {
        None => 0,
        Some(f) => {
            let f3: String = f.chars().chain("000".chars()).take(3).collect();
            digits(f)?;
            digits(&f3)?
        }
    };
    Some(days * DAY_MS + h * 3_600_000 + mi * 60_000 + se * 1000 + ms - offset_ms)
}

/// Milliseconds to `YYYY-MM-DDTHH:MM:SS.sssZ`.
pub fn format_iso8601(ms: i64) -> String {
    let (y, m, d) = civil_from_days(ms.div_euclid(DAY_MS));
    let r = ms.rem_euclid(DAY_MS);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        r / 3_600_000,
        r / 60_000 % 60,
        r / 1000 % 60,
        r % 1000
    )
}

/// The UTC calendar month a moment falls in, `YYYY-MM` — the key the
/// monthly seat history is kept under.
pub fn month_of(ms: i64) -> String {
    format_iso8601(ms)[..7].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_parse_the_shapes_keys_carry_and_nothing_else() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_iso8601("1970-01-02"), Some(DAY_MS));
        let t = parse_iso8601("2026-09-28T12:34:56.789Z").unwrap();
        assert_eq!(format_iso8601(t), "2026-09-28T12:34:56.789Z");
        assert_eq!(parse_iso8601("2026-09-28T12:34:56Z"), Some(t - 789));
        assert_eq!(
            parse_iso8601("2026-09-28T14:34:56.789+02:00"),
            Some(t),
            "an offset is honoured"
        );
        assert_eq!(parse_iso8601("2026-09-28T10:34:56.789-02:00"), Some(t));
        assert_eq!(
            parse_iso8601("2024-02-29"),
            Some(parse_iso8601("2024-02-28").unwrap() + DAY_MS)
        );
        for bad in [
            "",
            "2026",
            "2026-13-01",
            "2026-02-31",
            "2026-00-10",
            "2026-01-01T25:00:00Z",
            "2026-01-01T00:00:00",
            "tomorrow",
            "2026-01-01T00:00:00.xZ",
            "2026-01-01-01",
        ] {
            assert_eq!(parse_iso8601(bad), None, "{bad:?}");
        }
        assert_eq!(month_of(t), "2026-09");
        assert_eq!(format_iso8601(-1), "1969-12-31T23:59:59.999Z");
    }
}
