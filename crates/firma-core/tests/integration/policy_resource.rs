use std::collections::HashMap;

use firma_core::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};

fn intent() -> ExecutionIntent {
    ExecutionIntent {
        action_class: "communication.external.read".to_string(),
        resource: ExecutionIntent::resource_map_from(
            "backend.composio.dev/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS",
        ),
        params: ActionParams::Http(HttpParams {
            method: HttpMethod::POST,
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
        }),
        raw_transport: "https".to_string(),
        raw_action_ref: "POST /api/v3.1/tools/execute/GMAIL_FETCH_EMAILS".to_string(),
    }
}

#[test]
fn policy_resource_falls_back_to_transport_resource() {
    let intent = intent();

    assert_eq!(intent.policy_resource_display(), intent.resource_display());
}

#[test]
fn logical_policy_resource_does_not_change_transport_resource() {
    let mut intent = intent();
    intent.resource.insert(
        "policy_resource".to_string(),
        "composio://gmail/GMAIL_FETCH_EMAILS".to_string(),
    );

    assert_eq!(
        intent.policy_resource_display(),
        "composio://gmail/GMAIL_FETCH_EMAILS"
    );
    assert_eq!(
        intent.resource_display(),
        "backend.composio.dev/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS"
    );
}
