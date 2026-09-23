//! Shared human-display helpers.
//!
//! Machine records retain raw values. These helpers only make those values
//! legible in terminal output.

/// Render Unix seconds as both the raw value and an RFC 3339 UTC instant.
pub fn timestamp(seconds: i64) -> String {
    match utc_rfc3339(seconds) {
        Some(text) => format!("{seconds} ({text})"),
        None => format!("{seconds} (not a representable UTC date)"),
    }
}

pub fn optional_timestamp(seconds: Option<i64>) -> String {
    seconds.map(timestamp).unwrap_or_else(|| "(none)".into())
}

/// Format Unix seconds as RFC 3339 UTC without a date dependency.
pub fn utc_rfc3339(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);

    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_rendered_in_utc() {
        assert_eq!(timestamp(0), "0 (1970-01-01T00:00:00Z)");
    }

    #[test]
    fn negative_timestamps_use_euclidean_days() {
        assert_eq!(utc_rfc3339(-1).as_deref(), Some("1969-12-31T23:59:59Z"));
    }
}
