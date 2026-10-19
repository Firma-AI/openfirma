//! Keeps the Cedar schema and the canonical action-class registry in lockstep.

use firma_core::ActionClass;
use firma_core::cedar::FIRMA_SCHEMA;

fn schema_action_ids() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (schema, _) = cedar_policy::Schema::from_cedarschema_str(FIRMA_SCHEMA)?;
    let mut ids = schema
        .actions()
        .map(|action| AsRef::<str>::as_ref(action.id()).to_owned())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    Ok(ids)
}

/// Every canonical class must be a declared Cedar action.
///
/// A policy naming a class the schema does not declare is rejected at bundle
/// load, so a class added to the enum without a matching `action` declaration
/// would make that class unusable in policy while still passing every other
/// test.
#[test]
fn every_action_class_is_declared_in_the_cedar_schema() -> Result<(), Box<dyn std::error::Error>> {
    let declared = schema_action_ids()?;
    let missing: Vec<&str> = ActionClass::ALL
        .iter()
        .map(|class| class.as_str())
        .filter(|name| !declared.iter().any(|id| id == name))
        .collect();

    assert_eq!(missing, Vec::<&str>::new());
    Ok(())
}

/// The schema must not declare actions the enum does not know.
#[test]
fn the_cedar_schema_declares_no_unknown_action() -> Result<(), Box<dyn std::error::Error>> {
    let unknown = schema_action_ids()?
        .into_iter()
        .filter(|name| name.parse::<ActionClass>().is_err())
        .collect::<Vec<_>>();

    assert_eq!(unknown, Vec::<String>::new());
    Ok(())
}
