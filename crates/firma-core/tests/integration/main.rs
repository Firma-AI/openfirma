use std::collections::BTreeSet;

use firma_core::ActionClass;

mod action_class_schema;
mod agent_id;
mod mapping;
mod policy_resource;
mod resource_entity;
mod secret_matcher;
mod token_id;

#[test]
fn action_class_catalog_is_stable() {
    let names = ActionClass::ALL
        .iter()
        .map(|action| action.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    insta::assert_snapshot!(names, @r"
    account.permission.change
    browser.purchase
    calendar.create
    calendar.delete
    calendar.read
    calendar.update
    code.destructive
    code.merge
    code.read
    code.review.read
    code.review.submit
    code.write
    communication.external.delete
    communication.external.draft
    communication.external.filter
    communication.external.manage
    communication.external.read
    communication.external.send
    communication.internal.send
    credential.read
    credential.write
    customer.read
    customer.write
    document.delete
    document.read
    document.schema.write
    document.write
    filesystem.delete
    filesystem.read
    filesystem.write
    issue.read
    issue.write
    memory.cross_namespace.read
    memory.cross_namespace.write
    notification.manage
    payment.cancel
    payment.catalog.write
    payment.dispute
    payment.method.manage
    payment.method.setup
    payment.payout
    payment.purchase
    payment.read
    payment.refund
    payment.subscription
    payment.tax
    payment.transfer
    repo.admin
    repo.lifecycle
    security.alert.read
    system.execute
    system.install
    ");
}

#[test]
fn action_class_set_uses_canonical_string_order() {
    let order = ActionClass::ALL
        .iter()
        .map(|action| action.as_str())
        .collect::<Vec<_>>();
    let mut sorted = order.clone();
    sorted.sort_unstable();

    assert_eq!(
        order, sorted,
        "ActionClass::ALL must stay in canonical string order"
    );

    let via_ord = ActionClass::ALL
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(ActionClass::as_str)
        .collect::<Vec<_>>();

    assert_eq!(via_ord, sorted, "ActionClass::Ord must match string order");
}
