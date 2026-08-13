use std::collections::HashMap;

use firma_http::HeaderName;

#[test]
fn http_compatibility() {
    let mut hm = HashMap::new();
    hm.insert(HeaderName::from_static("x-api-key"), "foo");
    assert!(hm.contains_key(&http::HeaderName::from_static("x-api-key")));
}
