//! Window recurrences: `daily HH:MM <minutes>m` or `weekly <mon..sun> HH:MM <minutes>m`, in a timezone (7.5.3).
//! A start time that doesn't exist on a daylight-saving change runs at the next valid minute; a repeated one runs once,
//! at its first occurrence.

use std::fmt;
use std::str::FromStr;

use jiff::civil::{Date, DateTime, Time, Weekday};
use jiff::tz::{AmbiguousOffset, TimeZone};
use jiff::{Timestamp, ToSpan};

const MAX_DURATION_MIN: u32 = 7 * 24 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    Daily,
    Weekly(Weekday),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recurrence {
    pub repeat: Repeat,
    pub start: Time,
    pub duration_min: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid window `{0}`: expected `daily HH:MM <minutes>m` or `weekly <mon..sun> HH:MM <minutes>m`")]
pub struct ParseError(String);

fn weekday(s: &str) -> Option<Weekday> {
    Some(match s {
        "mon" => Weekday::Monday,
        "tue" => Weekday::Tuesday,
        "wed" => Weekday::Wednesday,
        "thu" => Weekday::Thursday,
        "fri" => Weekday::Friday,
        "sat" => Weekday::Saturday,
        "sun" => Weekday::Sunday,
        _ => return None,
    })
}

fn weekday_name(w: Weekday) -> &'static str {
    match w {
        Weekday::Monday => "mon",
        Weekday::Tuesday => "tue",
        Weekday::Wednesday => "wed",
        Weekday::Thursday => "thu",
        Weekday::Friday => "fri",
        Weekday::Saturday => "sat",
        Weekday::Sunday => "sun",
    }
}

fn time(s: &str) -> Option<Time> {
    let (h, m) = s.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    Time::new(h.parse().ok()?, m.parse().ok()?, 0, 0).ok()
}

fn duration(s: &str) -> Option<u32> {
    let n: u32 = s.strip_suffix('m')?.parse().ok()?;
    (1..=MAX_DURATION_MIN).contains(&n).then_some(n)
}

impl FromStr for Recurrence {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseError(s.to_string());
        let parts: Vec<&str> = s.split_whitespace().collect();
        let (repeat, rest) = match parts.as_slice() {
            ["daily", rest @ ..] => (Repeat::Daily, rest),
            ["weekly", day, rest @ ..] => (Repeat::Weekly(weekday(day).ok_or_else(err)?), rest),
            _ => return Err(err()),
        };
        let [start, dur] = rest else { return Err(err()) };
        Ok(Recurrence { repeat, start: time(start).ok_or_else(err)?, duration_min: duration(dur).ok_or_else(err)? })
    }
}

impl fmt::Display for Recurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.repeat {
            Repeat::Daily => f.write_str("daily")?,
            Repeat::Weekly(w) => write!(f, "weekly {}", weekday_name(w))?,
        }
        write!(f, " {:02}:{:02} {}m", self.start.hour(), self.start.minute(), self.duration_min)
    }
}

impl Recurrence {
    pub fn duration_ms(&self) -> i64 {
        i64::from(self.duration_min) * 60_000
    }

    fn on(&self, date: Date) -> bool {
        match self.repeat {
            Repeat::Daily => true,
            Repeat::Weekly(w) => date.weekday() == w,
        }
    }

    /// The start on `date` (local), in milliseconds, if the window runs that day.
    pub fn start_on(&self, tz: &TimeZone, date: Date) -> Option<i64> {
        if !self.on(date) {
            return None;
        }
        let mut dt: DateTime = date.to_datetime(self.start);
        // A gap: step to the next minute that exists.
        for _ in 0..24 * 60 {
            if !matches!(tz.to_ambiguous_zoned(dt).offset(), AmbiguousOffset::Gap { .. }) {
                break;
            }
            dt = dt.checked_add(1.minute()).ok()?;
        }
        // A fold resolves to the earlier instant, so the repeated hour runs once.
        Some(tz.to_ambiguous_zoned(dt).earlier().ok()?.timestamp().as_millisecond())
    }

    fn local_date(tz: &TimeZone, at_ms: i64) -> Option<Date> {
        Some(Timestamp::from_millisecond(at_ms).ok()?.to_zoned(tz.clone()).date())
    }

    /// The first start strictly after `after_ms`.
    pub fn next_start(&self, tz: &TimeZone, after_ms: i64) -> i64 {
        let Some(mut date) = Self::local_date(tz, after_ms).and_then(|d| d.yesterday().ok()) else { return i64::MAX };
        for _ in 0..10 {
            if let Some(start) = self.start_on(tz, date).filter(|s| *s > after_ms) {
                return start;
            }
            let Ok(next) = date.tomorrow() else { break };
            date = next;
        }
        i64::MAX
    }

    /// The start and end of the window open at `at_ms`, if one is.
    pub fn open_at(&self, tz: &TimeZone, at_ms: i64) -> Option<(i64, i64)> {
        let mut date = Self::local_date(tz, at_ms)?;
        // Look back far enough for the longest window.
        for _ in 0..=(MAX_DURATION_MIN / (24 * 60) + 1) {
            if let Some(start) = self.start_on(tz, date) {
                let end = start + self.duration_ms();
                if start <= at_ms && at_ms < end {
                    return Some((start, end));
                }
            }
            date = date.yesterday().ok()?;
        }
        None
    }
}
