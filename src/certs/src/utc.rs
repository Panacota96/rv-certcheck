//! UTC instants of the certificate layer, to the second, over the full proleptic Gregorian range the layer has
//! always accepted (years -262143 to +262142) and with RFC 3339's leap second (`23:59:60`).
//!
//! Plain integer arithmetic on purpose: jiff's `Timestamp` ends at 9999-12-30, and certificates carry
//! `notAfter 99991231235959Z` (RFC 5280's "no expiry") and later dates that must keep working exactly. The parsers
//! reproduce, byte for byte, what the layer accepted and rejected before the move off chrono (RUSTSEC-2026-0543),
//! including the error texts; `golden_time.rs` and `create::lab::golden_time` freeze that behaviour.

use std::time::{SystemTime, UNIX_EPOCH};

/// -262143-01-01T00:00:00Z, the first representable second.
const MIN_SECS: i64 = -8_334_601_228_800;
/// +262142-12-31T23:59:59Z, the last representable second.
const MAX_SECS: i64 = 8_210_266_876_799;
const MIN_YEAR: i64 = -262_143;
const MAX_YEAR: i64 = 262_142;

/// A UTC instant to the second. `leap` marks the leap second that follows `secs` (`23:59:60` when `secs` is
/// `23:59:59`): it is written as second 60 and orders after `secs` and before `secs + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime {
    secs: i64,
    leap: bool,
}

/// Why a date-time text was rejected (the texts the layer has always shown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    OutOfRange,
    Invalid,
    TooShort,
    TooLong,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ParseError::OutOfRange => "input is out of range",
            ParseError::Invalid => "input contains invalid characters",
            ParseError::TooShort => "premature end of input",
            ParseError::TooLong => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

use ParseError::*;

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month, day) of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0) => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 of a valid date within the range, else None.
fn date(y: i64, m: u32, d: u32) -> Option<i64> {
    ((MIN_YEAR..=MAX_YEAR).contains(&y)
        && (1..=12).contains(&m)
        && d >= 1
        && d <= days_in_month(y, m))
    .then(|| days_from_civil(y, m, d))
}

/// The year as RFC 3339 / ISO 8601 writes it: 4 digits, with a sign outside 0000–9999 (`+10000`, `-0001`).
fn year_text(y: i64) -> String {
    if (0..=9999).contains(&y) {
        format!("{y:04}")
    } else {
        format!("{}{:04}", if y < 0 { '-' } else { '+' }, y.unsigned_abs())
    }
}

impl UtcTime {
    /// The instant `secs` seconds after 1970-01-01T00:00:00Z; None outside the range.
    pub fn from_unix(secs: i64) -> Option<UtcTime> {
        (MIN_SECS..=MAX_SECS)
            .contains(&secs)
            .then_some(UtcTime { secs, leap: false })
    }

    /// The wall clock, truncated to the second.
    pub fn now() -> UtcTime {
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => {
                let d = e.duration();
                -(d.as_secs() as i64) - i64::from(d.subsec_nanos() > 0)
            }
        };
        UtcTime { secs, leap: false }
    }

    /// Seconds since the Unix epoch (a leap second counts as the second before it).
    pub fn unix(self) -> i64 {
        self.secs
    }

    /// `self` plus `days` days of 86 400 s. A leap second is left as soon as the time moves: forward it counts as
    /// the second before it (`23:59:60` + 1 day = next day `23:59:59`), backward as the second after it.
    ///
    /// # Panics
    /// When the result leaves the range (only a validity of millions of years can), with the message the layer
    /// has always panicked with.
    pub fn plus_days(self, days: i64) -> UtcTime {
        // A day count is bounded like the millisecond duration it always was.
        days.checked_mul(86_400_000)
            .expect("TimeDelta::days out of bounds");
        let delta = days * 86_400;
        if delta == 0 {
            return self;
        }
        let base = if self.leap && delta < 0 {
            self.secs + 1
        } else {
            self.secs
        };
        base.checked_add(delta)
            .and_then(UtcTime::from_unix)
            .expect("`DateTime + TimeDelta` overflowed")
    }

    /// (year, month, day, hour, minute, second); second 60 for a leap second.
    fn fields(self) -> (i64, u32, u32, u32, u32, u32) {
        let (days, sod) = (
            self.secs.div_euclid(86_400),
            self.secs.rem_euclid(86_400) as u32,
        );
        let (y, m, d) = civil_from_days(days);
        let s = sod % 60 + u32::from(self.leap);
        (y, m, d, sod / 3600, sod % 3600 / 60, s)
    }

    pub fn year(self) -> i64 {
        self.fields().0
    }

    /// `2026-06-01T12:00:00Z` (`+10000-…`, `-0001-…` outside 0000–9999).
    pub fn rfc3339(self) -> String {
        let (y, mo, d, h, mi, s) = self.fields();
        format!("{}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z", year_text(y))
    }

    /// UTCTime content `YYMMDDHHMMSSZ` (two-digit year).
    pub fn der_utc_time(self) -> String {
        let (y, mo, d, h, mi, s) = self.fields();
        format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y.rem_euclid(100))
    }

    /// GeneralizedTime content `YYYYMMDDHHMMSSZ`.
    pub fn der_generalized_time(self) -> String {
        let (y, mo, d, h, mi, s) = self.fields();
        format!("{}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", year_text(y))
    }

    /// Compact basic form for file names, `20260601T120000Z` (signed year outside 0000–9999, like the others).
    pub fn compact(self) -> String {
        let (y, mo, d, h, mi, s) = self.fields();
        format!("{}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z", year_text(y))
    }

    /// RFC 3339 `date-time` (`T`, `t` or a space between date and time; any number of fraction digits, dropped;
    /// leap second `:60`; `Z`/`z` or `±hh:mm` up to ±23:59, `−` U+2212 accepted as minus). Nothing else: no
    /// basic format, no `+hhmm`, no missing seconds, no surrounding spaces.
    pub fn parse_rfc3339(s: &str) -> Result<UtcTime, ParseError> {
        let b = s.as_bytes();
        if b.len() < 19 {
            return Err(TooShort);
        }
        let digit = |i: usize| -> Result<u32, ParseError> {
            if b[i].is_ascii_digit() {
                Ok(u32::from(b[i] - b'0'))
            } else {
                Err(Invalid)
            }
        };
        let sep = |i: usize, c: u8| if b[i] == c { Ok(()) } else { Err(Invalid) };
        let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
        sep(4, b'-')?;
        let month = digit(5)? * 10 + digit(6)?;
        sep(7, b'-')?;
        let day = digit(8)? * 10 + digit(9)?;
        let days = date(i64::from(year), month, day).ok_or(OutOfRange)?;
        if !matches!(b[10], b'T' | b't' | b' ') {
            return Err(Invalid);
        }
        let hour = digit(11)? * 10 + digit(12)?;
        sep(13, b':')?;
        let min = digit(14)? * 10 + digit(15)?;
        sep(16, b':')?;
        let sec = digit(17)? * 10 + digit(18)?;
        let (sec, leap) = if sec == 60 { (59, true) } else { (sec, false) };
        let mut rest = &s[19..];
        if let Some(frac) = rest.strip_prefix('.') {
            // 1 to 9 digits are read, more are skipped: only digits may follow the dot.
            let n = frac.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 {
                return Err(if frac.is_empty() { TooShort } else { Invalid });
            }
            rest = &frac[n..];
        }
        if hour >= 24 || min >= 60 || sec >= 60 {
            return Err(OutOfRange);
        }
        let offset = offset(rest)?;
        let secs = days * 86_400 + i64::from(hour * 3600 + min * 60 + sec) - i64::from(offset);
        Ok(UtcTime { secs, leap })
    }

    /// `YYYY-MM-DD` at midnight, read leniently the way the layer always read it: 1–2 digit month and day, a
    /// signed year of any length (`+2026`, `-0001`; 1–4 digits without a sign) and spaces before each number.
    pub fn parse_date(s: &str) -> Option<UtcTime> {
        let mut p = Lenient(s);
        let y = p.year()?;
        p.literal("-")?;
        let m = p.number(2, 1, 12)?;
        p.literal("-")?;
        let d = p.number(2, 1, 31)?;
        p.end()?;
        UtcTime::from_unix(date(y, m, d)? * 86_400)
    }

    /// OpenSSL's printed time without its ` GMT` (`Feb  1 00:00:00 2026`): month abbreviation (any case), day,
    /// `HH:MM:SS` (second 60 allowed) and year, read with the same leniency as [`UtcTime::parse_date`].
    pub fn parse_printed(s: &str) -> Option<UtcTime> {
        let mut p = Lenient(s);
        let month = p.month()?;
        p.space();
        let d = p.number(2, 1, 31)?;
        p.space();
        let h = p.number(2, 0, 23)?;
        p.literal(":")?;
        let mi = p.number(2, 0, 59)?;
        p.literal(":")?;
        let sec = p.number(2, 0, 60)?;
        p.space();
        let y = p.year()?;
        p.end()?;
        let days = date(y, month, d)?;
        let (sec, leap) = if sec == 60 { (59, true) } else { (sec, false) };
        Some(UtcTime {
            secs: days * 86_400 + i64::from(h * 3600 + mi * 60 + sec),
            leap,
        })
    }
}

/// `Z`/`z` or `±hh:mm` (hours 00–23, minutes 00–59) and nothing after it → seconds east of UTC.
fn offset(s: &str) -> Result<i32, ParseError> {
    if let Some(b'Z' | b'z') = s.as_bytes().first() {
        return if s.len() == 1 { Ok(0) } else { Err(TooLong) };
    }
    let (negative, s) = match s.chars().next() {
        Some('+') => (false, &s[1..]),
        Some('-') => (true, &s[1..]),
        Some('\u{2212}') => (true, &s['\u{2212}'.len_utf8()..]),
        Some(_) => return Err(Invalid),
        None => return Err(TooShort),
    };
    let b = s.as_bytes();
    if b.len() < 2 {
        return Err(TooShort);
    }
    if !(b[0].is_ascii_digit() && b[1].is_ascii_digit()) {
        return Err(Invalid);
    }
    let hours = i32::from((b[0] - b'0') * 10 + (b[1] - b'0'));
    match b.get(2) {
        Some(b':') => {}
        Some(_) => return Err(Invalid),
        None => return Err(TooShort),
    }
    let b = &b[3..];
    if b.len() < 2 {
        return Err(TooShort);
    }
    let minutes = match (b[0], b[1]) {
        (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
        (b'6'..=b'9', b'0'..=b'9') => return Err(OutOfRange),
        _ => return Err(Invalid),
    };
    if b.len() > 2 {
        return Err(TooLong);
    }
    let secs = hours * 3600 + minutes * 60;
    if secs >= 86_400 {
        return Err(OutOfRange);
    }
    Ok(if negative { -secs } else { secs })
}

/// The lenient field reader behind [`UtcTime::parse_date`] and [`UtcTime::parse_printed`].
struct Lenient<'a>(&'a str);

impl Lenient<'_> {
    fn space(&mut self) {
        self.0 = self.0.trim_start();
    }

    fn literal(&mut self, lit: &str) -> Option<()> {
        self.0 = self.0.strip_prefix(lit)?;
        Some(())
    }

    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }

    /// 1 to `max_digits` digits after optional whitespace, within `lo..=hi`.
    fn number(&mut self, max_digits: usize, lo: u32, hi: u32) -> Option<u32> {
        self.space();
        let v = self.digits(max_digits)?;
        u32::try_from(v).ok().filter(|v| (lo..=hi).contains(v))
    }

    fn digits(&mut self, max: usize) -> Option<i64> {
        let n = self
            .0
            .bytes()
            .take(max)
            .take_while(u8::is_ascii_digit)
            .count();
        if n == 0 {
            return None;
        }
        let mut v = 0i64;
        for c in self.0[..n].bytes() {
            v = v.checked_mul(10)?.checked_add(i64::from(c - b'0'))?;
        }
        self.0 = &self.0[n..];
        Some(v)
    }

    /// `+digits`, `-digits` (any length) or 1–4 digits, after optional whitespace.
    fn year(&mut self) -> Option<i64> {
        self.space();
        let y = if let Some(r) = self.0.strip_prefix('-') {
            self.0 = r;
            -self.digits(usize::MAX)?
        } else if let Some(r) = self.0.strip_prefix('+') {
            self.0 = r;
            self.digits(usize::MAX)?
        } else {
            self.digits(4)?
        };
        i32::try_from(y).ok().map(i64::from)
    }

    /// `Jan`…`Dec`, any case → 1–12.
    fn month(&mut self) -> Option<u32> {
        let b = self.0.as_bytes();
        if b.len() < 3 {
            return None;
        }
        let m = match (b[0] | 32, b[1] | 32, b[2] | 32) {
            (b'j', b'a', b'n') => 1,
            (b'f', b'e', b'b') => 2,
            (b'm', b'a', b'r') => 3,
            (b'a', b'p', b'r') => 4,
            (b'm', b'a', b'y') => 5,
            (b'j', b'u', b'n') => 6,
            (b'j', b'u', b'l') => 7,
            (b'a', b'u', b'g') => 8,
            (b's', b'e', b'p') => 9,
            (b'o', b'c', b't') => 10,
            (b'n', b'o', b'v') => 11,
            (b'd', b'e', b'c') => 12,
            _ => return None,
        };
        self.0 = &self.0[3..];
        Some(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OCSP response file name (`ocsp/<serial>-<compact>.der`): the GeneralizedTime fields with a `T`, as
    /// chrono's `%Y%m%dT%H%M%SZ` wrote them (golden GeneralizedTime vectors cover the field values).
    #[test]
    fn compact_is_the_generalized_time_with_a_t() {
        for s in [
            "2026-06-01T12:00:00Z",
            "2016-12-31T23:59:60Z",
            "9999-12-31T23:59:59Z",
            "0000-01-01T00:00:00Z",
        ] {
            let t = UtcTime::parse_rfc3339(s).unwrap();
            let g = t.der_generalized_time();
            assert_eq!(t.compact(), format!("{}T{}", &g[..8], &g[8..]));
        }
        assert_eq!(
            UtcTime::parse_rfc3339("2026-06-01T12:00:00Z")
                .unwrap()
                .compact(),
            "20260601T120000Z"
        );
        let far = UtcTime::from_unix(253_402_300_800).unwrap();
        assert_eq!(far.compact(), "+100000101T000000Z");
    }
}
