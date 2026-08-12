use firma_http::{FIRMA_SESSION_ID_HEADER_NAME, HeaderMap};

#[test]
fn new_and_default_are_empty() {
    assert!(HeaderMap::new().0.is_empty());
    assert!(HeaderMap::default().0.is_empty());
}

#[test]
fn get_firma_session_id_returns_value_when_present() {
    let mut map = HeaderMap::new();
    map.insert(
        FIRMA_SESSION_ID_HEADER_NAME,
        http::HeaderValue::from_static("abc123"),
    );

    assert_eq!(
        map.get_firma_session_id().expect("valid utf8"),
        Some("abc123")
    );
}

#[test]
fn get_firma_session_id_returns_none_when_absent() {
    assert_eq!(
        HeaderMap::new().get_firma_session_id().expect("no header"),
        None
    );
}

#[test]
fn get_firma_session_id_returns_err_for_invalid_utf8() {
    let mut map = HeaderMap::new();
    map.insert(
        FIRMA_SESSION_ID_HEADER_NAME,
        http::HeaderValue::from_bytes(&[0xff, 0x80]).expect("valid header value"),
    );

    std::assert_matches!(map.get_firma_session_id(), Err(_));
}

#[test]
fn deref_mut_mutates_inner_map() {
    let mut map = HeaderMap::new();
    map.insert("x-foo", http::HeaderValue::from_static("bar"));

    assert_eq!(
        map.get("x-foo"),
        Some(&http::HeaderValue::from_static("bar"))
    );
}

#[test]
fn from_ref_clones_into_http_header_map() {
    let mut map = HeaderMap::new();
    map.insert("x-foo", http::HeaderValue::from_static("bar"));

    assert_eq!(http::HeaderMap::from(&map), map.0);
}

#[test]
fn from_iterator_inserts_single_value_per_key() {
    let map = HeaderMap::from_iter([
        (
            http::HeaderName::from_static("x-foo"),
            http::HeaderValue::from_static("1"),
        ),
        (
            http::HeaderName::from_static("x-bar"),
            http::HeaderValue::from_static("2"),
        ),
    ]);

    assert_eq!(map.get("x-foo"), Some(&http::HeaderValue::from_static("1")));
    assert_eq!(map.get("x-bar"), Some(&http::HeaderValue::from_static("2")));
    assert_eq!(map.0.len(), 2);
}

#[test]
fn from_iterator_appends_duplicate_keys() {
    let map = HeaderMap::from_iter([
        (
            http::HeaderName::from_static("x-foo"),
            http::HeaderValue::from_static("1"),
        ),
        (
            http::HeaderName::from_static("x-foo"),
            http::HeaderValue::from_static("2"),
        ),
    ]);

    let values: Vec<_> = map.get_all("x-foo").iter().collect();
    assert_eq!(
        values,
        vec![
            &http::HeaderValue::from_static("1"),
            &http::HeaderValue::from_static("2")
        ]
    );
}

#[test]
fn serialize_single_value_is_scalar() {
    let mut map = HeaderMap::new();
    map.insert("x-foo", http::HeaderValue::from_static("bar"));

    assert_eq!(
        serde_json::to_value(&map).expect("serialize"),
        serde_json::json!({ "x-foo": "bar" })
    );
}

#[test]
fn serialize_multiple_values_is_array() {
    let mut map = HeaderMap::new();
    map.append("x-foo", http::HeaderValue::from_static("1"));
    map.append("x-foo", http::HeaderValue::from_static("2"));

    assert_eq!(
        serde_json::to_value(&map).expect("serialize"),
        serde_json::json!({ "x-foo": ["1", "2"] })
    );
}

#[test]
fn deserialize_single_value_inserts_entry() {
    let map: HeaderMap =
        serde_json::from_value(serde_json::json!({ "x-foo": "bar" })).expect("deserialize");

    assert_eq!(
        map.get("x-foo"),
        Some(&http::HeaderValue::from_static("bar"))
    );
}

#[test]
fn deserialize_multiple_values_appends_entries() {
    let map: HeaderMap =
        serde_json::from_value(serde_json::json!({ "x-foo": ["1", "2"] })).expect("deserialize");

    let values: Vec<_> = map.get_all("x-foo").iter().collect();
    assert_eq!(
        values,
        vec![
            &http::HeaderValue::from_static("1"),
            &http::HeaderValue::from_static("2")
        ]
    );
}

#[test]
fn deserialize_rejects_invalid_header_name() {
    let result: Result<HeaderMap, _> =
        serde_json::from_value(serde_json::json!({ "x foo": "bar" }));

    std::assert_matches!(result, Err(_));
}

#[test]
fn deserialize_rejects_invalid_header_value() {
    let result: Result<HeaderMap, _> =
        serde_json::from_value(serde_json::json!({ "x-foo": [0x00] }));

    std::assert_matches!(result, Err(_));
}

#[test]
fn round_trips_multi_value_headers_through_json() {
    let mut map = HeaderMap::new();
    map.append("x-foo", http::HeaderValue::from_static("1"));
    map.append("x-foo", http::HeaderValue::from_static("2"));
    map.insert("x-bar", http::HeaderValue::from_static("baz"));

    let json = serde_json::to_string(&map).expect("serialize");
    let round_tripped: HeaderMap = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(round_tripped, map);
}
