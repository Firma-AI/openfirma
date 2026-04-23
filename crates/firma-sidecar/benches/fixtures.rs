// Shared helpers for criterion benches. Each bench `include!`s this file
// (benches are separate crates, so a normal `mod fixtures` would not be
// visible cross-bench). No inner attributes — `include!` inlines at the
// call site and inner attributes would apply to the whole bench crate.

const BUNDLE_SRC: &str = include_str!("fixtures/reference_bundle.cedar");
const SCHEMA_SRC: &str = include_str!("fixtures/reference_schema.cedarschema");

#[allow(dead_code)]
fn reference_bundle() -> firma_core::policy::PolicyBundle {
    firma_core::policy::PolicyBundle::new(
        "reference-v1".to_string(),
        BUNDLE_SRC.as_bytes().to_vec(),
        SCHEMA_SRC.as_bytes().to_vec(),
        3600,
    )
}
