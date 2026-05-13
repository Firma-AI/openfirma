#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
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

#[derive(Arbitrary, Debug)]
struct FuzzRequest {
    method: String,
    host: String,
    path: String,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
    is_https: bool,
}

fuzz_target!(|input: FuzzRequest| {
    let request = RawRequest {
        method: input.method,
        host: input.host,
        path: input.path,
        headers: input.headers,
        body: input.body,
        is_https: input.is_https,
    };
    let _ = static_normalizer().normalize(&request);
});
