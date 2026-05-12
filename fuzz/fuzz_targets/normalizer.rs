#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use firma_sidecar::{
    config::{MappingRuleConfig, MappingRulesFile},
    enforcement::registry::ActionClassRegistry,
    normalizer::{IntentNormalizer, MappingTable, RawRequest},
};
use libfuzzer_sys::fuzz_target;

fn static_normalizer() -> &'static IntentNormalizer {
    static N: OnceLock<IntentNormalizer> = OnceLock::new();
    N.get_or_init(|| {
        let registry = ActionClassRegistry::v0_1();
        // Minimal representative rules covering several action classes.
        let rules = vec![
            MappingRuleConfig {
                method: Some("GET".into()),
                host: "api.github.com".into(),
                path: Some("/repos/*/*".into()),
                action_class: "code.read".into(),
            },
            MappingRuleConfig {
                method: Some("POST".into()),
                host: "api.stripe.com".into(),
                path: Some("/v1/charges".into()),
                action_class: "payment.charge".into(),
            },
            MappingRuleConfig {
                method: None,
                host: "*.example.com".into(),
                path: None,
                action_class: "communication.external.send".into(),
            },
        ];
        let file = MappingRulesFile { rules };
        let table = MappingTable::from_config(&file, &registry, false)
            .expect("static normalizer rules are valid");
        IntentNormalizer::new(table)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Split on NUL bytes: method\0host\0path
    let mut parts = s.splitn(3, '\0');
    let method = parts.next().unwrap_or("GET");
    let host = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    let request = RawRequest {
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        headers: HashMap::new(),
        body: None,
        is_https: false,
    };

    let _ = static_normalizer().normalize(&request);
});
