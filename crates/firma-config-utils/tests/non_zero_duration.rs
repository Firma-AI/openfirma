use std::num::NonZeroU64;
use std::time::Duration;

use firma_config_utils::{NonZeroDuration, ZeroDurationError};
use serde::Deserialize;

#[test]
fn accepts_friendly_compact_durations() {
    for (json, expected) in [
        (r#""1h""#, Duration::from_hours(1)),
        (r#""30s""#, Duration::from_secs(30)),
        (r#""500ms""#, Duration::from_millis(500)),
    ] {
        let duration: NonZeroDuration =
            serde_json::from_str(json).expect("friendly non-zero duration parses");
        assert_eq!(duration.duration(), expected);
    }
}

#[test]
fn rejects_equivalent_friendly_zero_values() {
    for value in ["0ns", "0ms", "0s", "0m", "0h"] {
        let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
        let error =
            NonZeroDuration::deserialize(deserializer).expect_err("zero duration must fail");
        assert_eq!(error.to_string(), "duration must be greater than zero");
    }
}

#[test]
fn accepts_sub_millisecond_non_zero_duration() {
    let duration: NonZeroDuration =
        serde_json::from_str(r#""1ns""#).expect("nanosecond duration parses");

    assert_eq!(duration.duration(), Duration::from_nanos(1));
}

#[test]
fn construction_rejects_zero_and_static_defaults_preserve_values() {
    assert_eq!(NonZeroDuration::new(Duration::ZERO), Err(ZeroDurationError));
    assert_eq!(
        NonZeroDuration::try_from(Duration::ZERO),
        Err(ZeroDurationError)
    );
    assert_eq!(
        ZeroDurationError.to_string(),
        "duration must be greater than zero"
    );

    let duration = Duration::from_nanos(1);
    let non_zero =
        NonZeroDuration::try_from(duration).expect("non-zero duration constructs successfully");
    assert_eq!(Duration::from(non_zero), duration);
    assert_eq!(
        NonZeroDuration::from_static(Duration::from_mins(5)).duration(),
        Duration::from_mins(5)
    );
}

#[test]
fn serialization_round_trips_with_friendly_representation() {
    let duration = NonZeroDuration::new(Duration::new(65, 123_456_789))
        .expect("non-zero duration constructs successfully");

    let serialized = serde_json::to_string(&duration).expect("non-zero duration serializes");
    let value: serde_json::Value =
        serde_json::from_str(&serialized).expect("serialized non-zero duration is JSON");
    assert!(
        value.is_string(),
        "non-zero duration must serialize as a string"
    );

    let deserialized: NonZeroDuration =
        serde_json::from_str(&serialized).expect("serialized non-zero duration deserializes");
    assert_eq!(deserialized, duration);

    let whole_seconds = NonZeroU64::new(90).expect("test fixture is non-zero");
    assert_eq!(
        NonZeroDuration::from(whole_seconds).duration(),
        Duration::from_secs(90)
    );
}
