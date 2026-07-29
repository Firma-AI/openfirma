use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher};

#[test]
fn scoped_selector_serde_shape_is_explicit() {
    let matcher = SecretMatcher::Json {
        record_path: "$[*]".to_owned(),
        value_path: "$.credentials.value".to_owned(),
        name_path: "$.credentials.key".to_owned(),
        item_selector: Some(SecretJsonSelector {
            path: "$.metadata.title".to_owned(),
            scope: SecretJsonSelectorScope::Record,
        }),
        domain_selector: Some(SecretJsonSelector {
            path: "$.domain".to_owned(),
            scope: SecretJsonSelectorScope::Document,
        }),
    };

    let serialized = serde_json::to_value(matcher).unwrap();

    assert_eq!(
        serialized,
        serde_json::json!({
            "type": "json",
            "record_path": "$[*]",
            "value_path": "$.credentials.value",
            "name_path": "$.credentials.key",
            "item_selector": {"path": "$.metadata.title", "scope": "record"},
            "domain_selector": {"path": "$.domain", "scope": "document"}
        })
    );
}
