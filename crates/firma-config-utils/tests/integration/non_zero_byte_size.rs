use std::num::NonZeroU64;

use bytesize::ByteSize;
use firma_config_utils::{NonZeroByteSize, ZeroByteSizeError};
use serde::Deserialize;

#[test]
fn accepts_unit_bearing_sizes() {
    for (json, expected) in [
        (r#""4 MiB""#, 4 * 1024 * 1024),
        (r#""10MB""#, 10_000_000),
        (r#""1 B""#, 1),
    ] {
        let size: NonZeroByteSize =
            serde_json::from_str(json).expect("unit-bearing non-zero size parses");
        assert_eq!(size.bytes().get(), expected, "{json}");
    }
}

#[test]
fn rejects_zero_in_any_unit() {
    for value in ["0 B", "0 KiB", "0MB"] {
        let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
        let error = NonZeroByteSize::deserialize(deserializer).expect_err("zero size must fail");
        assert_eq!(error.to_string(), "byte size must be greater than zero");
    }
}

#[test]
fn rejects_a_bare_number() {
    let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new("1024");
    let error = NonZeroByteSize::deserialize(deserializer).expect_err("bare number must fail");
    assert_eq!(error.to_string(), "byte size must include a unit");
}

#[test]
fn construction_rejects_zero_and_preserves_bytes() {
    assert_eq!(NonZeroByteSize::new(ByteSize::b(0)), Err(ZeroByteSizeError));

    let size = NonZeroByteSize::try_from(ByteSize::kib(3)).expect("non-zero size constructs");
    assert_eq!(
        size.bytes(),
        NonZeroU64::new(3072).expect("test fixture is non-zero")
    );
    assert_eq!(ByteSize::from(size), ByteSize::kib(3));
    assert_eq!(
        NonZeroByteSize::from_static(ByteSize::mib(4)).bytes().get(),
        4 * 1024 * 1024
    );
}

#[test]
fn serialization_round_trips_as_an_exact_byte_count() {
    let size = NonZeroByteSize::from_static(ByteSize::b(12_345));

    let serialized = serde_json::to_string(&size).expect("non-zero size serializes");
    assert_eq!(serialized, r#""12345 B""#);

    let deserialized: NonZeroByteSize =
        serde_json::from_str(&serialized).expect("serialized non-zero size deserializes");
    assert_eq!(deserialized, size);
}
