#![no_main]

use std::sync::OnceLock;

use firma_sidecar::{
    config::MappingRulesFile,
    enforcement::registry::ActionClassRegistry,
    normalizer::MappingTable,
};
use libfuzzer_sys::fuzz_target;

fn static_registry() -> &'static ActionClassRegistry {
    static R: OnceLock<ActionClassRegistry> = OnceLock::new();
    R.get_or_init(ActionClassRegistry::v0_1)
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(file) = toml::from_str::<MappingRulesFile>(s) else {
        return;
    };
    let _ = MappingTable::from_config(&file, static_registry(), false);
});
