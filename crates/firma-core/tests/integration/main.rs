use std::collections::BTreeSet;

use firma_core::ActionClass;

mod action_class_schema;
mod agent_id;
mod policy_resource;
mod resource_entity;
mod secret_matcher;
mod token_id;

#[test]
fn action_class_set_uses_canonical_string_order() {
    let actual = ActionClass::ALL
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(ActionClass::as_str)
        .collect::<Vec<_>>();
    let mut expected = ActionClass::ALL
        .iter()
        .map(|action| action.as_str())
        .collect::<Vec<_>>();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}
