use std::collections::HashMap;

use firma_http::Authority;

#[test]
fn http_compatibility() {
    let mut hm = HashMap::new();
    hm.insert(Authority::from_static("x-api-key"), "foo");
    assert!(hm.contains_key(&http::uri::Authority::from_static("x-api-key")));
}
