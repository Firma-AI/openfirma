//! Keeps the Cedar schema and the canonical action-class registry in lockstep.

use firma_core::ActionClass;
use firma_core::cedar::FIRMA_SCHEMA;

/// Every canonical class must be a declared Cedar action.
///
/// A policy naming a class the schema does not declare is rejected at bundle
/// load, so a class added to the enum without a matching `action` declaration
/// would make that class unusable in policy while still passing every other
/// test.
#[test]
fn every_action_class_is_declared_in_the_cedar_schema() {
    let missing: Vec<&str> = ActionClass::ALL
        .iter()
        .map(|class| class.as_str())
        .filter(|name| !FIRMA_SCHEMA.contains(&format!("action \"{name}\"")))
        .collect();

    assert_eq!(missing, Vec::<&str>::new());
}

/// The schema must not declare actions the enum does not know.
#[test]
fn the_cedar_schema_declares_no_unknown_action() {
    let declared = FIRMA_SCHEMA
        .match_indices("action \"")
        .filter_map(|(index, marker)| {
            let rest = &FIRMA_SCHEMA[index + marker.len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .filter(|name| name.parse::<ActionClass>().is_err())
        .collect::<Vec<_>>();

    assert_eq!(declared, Vec::<&str>::new());
}
