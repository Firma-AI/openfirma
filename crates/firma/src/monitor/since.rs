//! Parse `--since` as a duration or RFC3339 timestamp.

use std::time::{Duration, SystemTime};

pub fn parse(input: &str) -> Result<SystemTime, String> {
    if let Some(duration) = parse_duration(input) {
        return Ok(SystemTime::now() - duration);
    }
    chrono::DateTime::parse_from_rfc3339(input)
        .map(SystemTime::from)
        .map_err(|error| format!("not a duration or RFC3339 timestamp: {error}"))
}

fn parse_duration(input: &str) -> Option<Duration> {
    let (number, unit) = input.split_at(input.len().saturating_sub(1));
    let value: u64 = number.parse().ok()?;
    let secs = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86_400,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minutes() {
        let time = parse("15m").expect("parse");
        let duration = SystemTime::now().duration_since(time).expect("now > time");
        assert!(duration.as_secs() >= 60 * 14);
        assert!(duration.as_secs() <= 60 * 16);
    }

    #[test]
    fn parses_rfc3339() {
        let _ = parse("2026-01-01T00:00:00Z").expect("rfc3339");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("abc").is_err());
    }
}
