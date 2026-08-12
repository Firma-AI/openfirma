use firma_http::HeaderMap;

#[test]
fn opaque_header_values_round_trip_through_json() -> Result<(), Box<dyn std::error::Error>> {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-opaque",
        http::HeaderValue::from_bytes(b"prefix-\xff-suffix")?,
    );
    let headers = HeaderMap(headers);

    let encoded = serde_json::to_vec(&headers)?;
    let decoded: HeaderMap = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, headers);
    Ok(())
}
