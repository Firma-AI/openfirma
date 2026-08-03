use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, SecretNameSource};

#[test]
fn scoped_selector_serde_shape_is_explicit() {
    let matcher = SecretMatcher::Json {
        record_path: "$[*]".to_owned(),
        value_path: "$.credentials.value".to_owned(),
        name: SecretNameSource::Path {
            path: "$.credentials.key".to_owned(),
        },
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
            "name": {"source": "path", "path": "$.credentials.key"},
            "item_selector": {"path": "$.metadata.title", "scope": "record"},
            "domain_selector": {"path": "$.domain", "scope": "document"}
        })
    );
}

#[test]
fn record_key_name_source_serde_shape_is_explicit() {
    let matcher = SecretMatcher::Json {
        record_path: "$.data.data.*".to_owned(),
        value_path: "$".to_owned(),
        name: SecretNameSource::RecordKey,
        item_selector: None,
        domain_selector: None,
    };

    let serialized = serde_json::to_value(matcher).unwrap();

    assert_eq!(
        serialized,
        serde_json::json!({
            "type": "json",
            "record_path": "$.data.data.*",
            "value_path": "$",
            "name": {"source": "record_key"},
        })
    );
}
