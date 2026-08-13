use std::{collections::HashMap, str::FromStr};

use firma_http::HeaderValue;

#[test]
fn http_compatibility() {
    let mut hm = HashMap::new();
    hm.insert(
        // since hawk made us remove `from_static` wrapper, we have to do this explicitly
        HeaderValue(http::HeaderValue::from_static("x-api-key")),
        "foo",
    );
    assert!(hm.contains_key(&http::HeaderValue::from_static("x-api-key")));
}

#[test]
fn from_str_rejects_control_bytes() {
    std::assert_matches!(HeaderValue::from_str("foo\nbar"), Err(_));
}

#[test]
fn converts_to_and_from_http_header_value() {
    let inner = http::HeaderValue::from_static("foo");
    let wrapped = HeaderValue::from(&inner);

    assert_eq!(http::HeaderValue::from(&wrapped), inner);
    assert_eq!(http::HeaderValue::from(wrapped), inner);
}

#[test]
fn serializes_utf8_value_as_string() {
    let value = HeaderValue::from_str("foo").expect("valid header value");

    assert_eq!(
        serde_json::to_value(&value).expect("serialize"),
        serde_json::json!("foo")
    );
}

#[test]
fn serializes_non_utf8_value_as_bytes() {
    let value =
        HeaderValue(http::HeaderValue::from_bytes(&[0xff, 0x80]).expect("valid header value"));

    assert_eq!(
        serde_json::to_value(&value).expect("serialize"),
        serde_json::json!([0xff, 0x80])
    );
}

#[test]
fn deserializes_string_into_header_value() {
    let value: HeaderValue = serde_json::from_value(serde_json::json!("foo")).expect("deserialize");

    assert_eq!(
        value,
        HeaderValue::from_str("foo").expect("valid header value")
    );
}

#[test]
fn deserializes_bytes_into_header_value() {
    let value: HeaderValue =
        serde_json::from_value(serde_json::json!([0xff, 0x80])).expect("deserialize");

    assert_eq!(
        value,
        HeaderValue(http::HeaderValue::from_bytes(&[0xff, 0x80]).expect("valid header value"))
    );
}

#[test]
fn deserialize_rejects_invalid_bytes() {
    let result: Result<HeaderValue, _> = serde_json::from_value(serde_json::json!([0x00]));

    std::assert_matches!(result, Err(_));
}

#[test]
fn deserialize_rejects_invalid_string() {
    let result: Result<HeaderValue, _> = serde_json::from_str("\"\\u0000\"");

    std::assert_matches!(result, Err(_));
}

#[test]
fn round_trips_non_utf8_value_through_json() {
    let value =
        HeaderValue(http::HeaderValue::from_bytes(&[0xff, 0x80]).expect("valid header value"));
    let json = serde_json::to_string(&value).expect("serialize");
    let round_tripped: HeaderValue = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(round_tripped, value);
}
