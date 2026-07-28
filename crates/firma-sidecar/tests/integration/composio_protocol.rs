use std::collections::HashMap;

use firma_http::Method;
use firma_sidecar::composio::{ComposioCatalogs, DecodeResult, decode};
use firma_sidecar::normalizer::RawRequest;

const GMAIL_SOURCE: &str = r#"{
  "toolkit": "gmail",
  "version": "20251111_00",
  "tools": [
    {
      "toolkit": "gmail",
      "version": "20251111_00",
      "slug": "GMAIL_FETCH_EMAILS",
      "name": "Fetch emails",
      "description": "Fetch email metadata"
    },
    {
      "toolkit": "gmail",
      "version": "20251111_00",
      "slug": "GMAIL_SEND_EMAIL",
      "name": "Send email",
      "description": "Send an email"
    }
  ]
}"#;

const GMAIL_MAPPING: &str = r#"{
  "toolkit": "gmail",
  "version": "20251111_00",
  "mappings": {
    "GMAIL_FETCH_EMAILS": "communication.external.read",
    "GMAIL_SEND_EMAIL": "communication.external.send"
  }
}"#;

const CALENDAR_SOURCE: &str = r#"{
  "toolkit": "googlecalendar",
  "version": "20260623_00",
  "tools": [
    {
      "toolkit": "googlecalendar",
      "version": "20260623_00",
      "slug": "GOOGLECALENDAR_CREATE_EVENT",
      "name": "Create event",
      "description": "Create a calendar event"
    }
  ]
}"#;

const CALENDAR_MAPPING: &str = r#"{
  "toolkit": "googlecalendar",
  "version": "20260623_00",
  "mappings": {
    "GOOGLECALENDAR_CREATE_EVENT": "calendar.create"
  }
}"#;

fn catalogs() -> anyhow::Result<ComposioCatalogs> {
    Ok(ComposioCatalogs::from_json_pairs([
        (GMAIL_SOURCE, GMAIL_MAPPING),
        (CALENDAR_SOURCE, CALENDAR_MAPPING),
    ])?)
}

fn request(host: &str, path: &str, body: &serde_json::Value) -> RawRequest {
    request_with_body(host, path, body.to_string().into_bytes())
}

fn request_with_body(host: &str, path: &str, body: Vec<u8>) -> RawRequest {
    RawRequest {
        method: Method::POST,
        host: host.to_string(),
        path: path.to_string(),
        headers: HashMap::new(),
        body: Some(body),
        is_https: true,
    }
}

fn actions(result: DecodeResult) -> anyhow::Result<Vec<firma_sidecar::composio::ComposioAction>> {
    let DecodeResult::Actions(actions) = result else {
        anyhow::bail!("expected decoded Composio actions");
    };
    Ok(actions)
}

#[test]
fn direct_execution_requires_and_uses_the_pinned_version() -> anyhow::Result<()> {
    let request = request(
        "backend.composio.dev",
        "/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS",
        &serde_json::json!({
            "version": "20251111_00",
            "user_id": "pai-assistant:bot-1",
            "connected_account_id": "account-1",
            "arguments": {"query": "secret search"},
        }),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(decoded.len(), 1);
    assert_eq!(
        decoded[0].envelope.intent.policy_resource_display(),
        "composio://gmail/GMAIL_FETCH_EMAILS"
    );
    assert_eq!(
        decoded[0].envelope.intent.resource_display(),
        "backend.composio.dev/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS"
    );
    assert_eq!(
        decoded[0].context.user_id.as_deref(),
        Some("pai-assistant:bot-1")
    );
    assert_eq!(
        decoded[0].context.connected_account_id.as_deref(),
        Some("account-1")
    );
    let firma_core::ActionParams::Http(params) = &decoded[0].envelope.intent.params else {
        anyhow::bail!("expected HTTP logical action");
    };
    assert_eq!(params.body, None);
    assert!(params.headers.is_empty());
    Ok(())
}

/// A nonstandard port must not demote a protected host to generic
/// normalization; host matching is port-agnostic.
#[test]
fn nonstandard_ports_still_hit_the_protected_hosts() -> anyhow::Result<()> {
    let request = request(
        "backend.composio.dev:8443",
        "/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS",
        &serde_json::json!({"version": "20251111_00"}),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(
        decoded[0].envelope.intent.policy_resource_display(),
        "composio://gmail/GMAIL_FETCH_EMAILS"
    );
    Ok(())
}

/// The logical envelope must never retain the raw query string: clients can
/// stuff tool arguments after `?`, and the envelope travels inside denial
/// decisions and diagnostics.
#[test]
fn logical_envelope_drops_the_query_string() -> anyhow::Result<()> {
    let request = request(
        "backend.composio.dev",
        "/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS?query=secret+search",
        &serde_json::json!({"version": "20251111_00"}),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(
        decoded[0].envelope.intent.resource_display(),
        "backend.composio.dev/api/v3.1/tools/execute/GMAIL_FETCH_EMAILS"
    );
    assert_eq!(
        decoded[0].envelope.intent.raw_action_ref,
        "POST /api/v3.1/tools/execute/GMAIL_FETCH_EMAILS"
    );
    Ok(())
}

#[test]
fn direct_execution_rejects_missing_or_wrong_versions() -> anyhow::Result<()> {
    for body in [
        serde_json::json!({"arguments": {}}),
        serde_json::json!({"version": "latest", "arguments": {}}),
    ] {
        let request = request(
            "backend.composio.dev",
            "/api/v3/tools/execute/GMAIL_SEND_EMAIL",
            &body,
        );
        assert!(matches!(
            decode(&request, &catalogs()?),
            DecodeResult::Deny(_)
        ));
    }
    Ok(())
}

#[test]
fn session_execution_uses_the_pinned_local_slug_allowlist() -> anyhow::Result<()> {
    let request = request(
        "backend.composio.dev",
        "/api/v3.1/tool_router/session/trs_1/execute",
        &serde_json::json!({
            "tool_slug": "GOOGLECALENDAR_CREATE_EVENT",
            "arguments": {"summary": "private"},
            "account": "calendar-work",
        }),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(decoded[0].envelope.intent.action_class, "calendar.create");
    assert_eq!(decoded[0].context.session_id.as_deref(), Some("trs_1"));
    assert_eq!(
        decoded[0].context.connected_account_id.as_deref(),
        Some("calendar-work")
    );
    Ok(())
}

#[test]
fn hosted_mcp_decodes_directly_exposed_provider_tools() -> anyhow::Result<()> {
    let request = request(
        "app.composio.dev",
        "/tool_router/v3/trs_mcp/mcp",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "GMAIL_SEND_EMAIL",
                "arguments": {
                    "account": "mailbox",
                    "recipient": "secret@example.test"
                }
            }
        }),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(
        decoded[0].envelope.intent.action_class,
        "communication.external.send"
    );
    assert_eq!(decoded[0].context.session_id.as_deref(), Some("trs_mcp"));
    Ok(())
}

/// Hosted MCP is reachable under the backend host as well, and its stream and
/// teardown verbs carry no tool call.
#[test]
fn backend_host_hosted_mcp_decodes_calls_and_passes_session_verbs() -> anyhow::Result<()> {
    let call = request(
        "backend.composio.dev",
        "/api/v3.1/mcp/mcp_session_1",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "GOOGLECALENDAR_CREATE_EVENT",
                "arguments": {"summary": "private"}
            }
        }),
    );

    let decoded = actions(decode(&call, &catalogs()?))?;

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].envelope.intent.action_class, "calendar.create");
    assert_eq!(
        decoded[0].context.session_id.as_deref(),
        Some("mcp_session_1")
    );

    let stream = RawRequest {
        method: Method::GET,
        ..request_with_body("backend.composio.dev", "/api/v3/mcp/mcp_session_1", vec![])
    };

    assert!(matches!(
        decode(&stream, &catalogs()?),
        DecodeResult::Passthrough
    ));
    Ok(())
}

#[test]
fn multi_execute_expands_ordered_children_without_arguments() -> anyhow::Result<()> {
    let request = request(
        "app.composio.dev",
        "/tool_router/v3/trs_batch/mcp",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "COMPOSIO_MULTI_EXECUTE_TOOL",
                "arguments": {
                    "tools": [
                        {
                            "tool_slug": "GMAIL_FETCH_EMAILS",
                            "arguments": {"query": "secret one"}
                        },
                        {
                            "tool_slug": "GMAIL_SEND_EMAIL",
                            "arguments": {"body": "secret two"}
                        }
                    ]
                }
            }
        }),
    );

    let decoded = actions(decode(&request, &catalogs()?))?;

    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].context.tool_slug, "GMAIL_FETCH_EMAILS");
    assert_eq!(decoded[1].context.tool_slug, "GMAIL_SEND_EMAIL");
    assert_eq!(decoded[0].context.batch_index, Some(0));
    assert_eq!(decoded[1].context.batch_index, Some(1));
    assert_eq!(decoded[0].context.batch_size, Some(2));
    assert_eq!(decoded[1].context.batch_size, Some(2));
    Ok(())
}

#[test]
fn protocol_failures_are_secret_safe() -> anyhow::Result<()> {
    let mut request = request(
        "app.composio.dev",
        "/tool_router/v3/trs_batch/mcp",
        &serde_json::json!({"secret": "do-not-log"}),
    );
    request.body = Some(br#"{"secret":"do-not-log","method":"#.to_vec());

    let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
        anyhow::bail!("expected protocol denial");
    };

    assert_eq!(denial.detail, "invalid Composio execution payload");
    assert!(!denial.detail.contains("do-not-log"));
    Ok(())
}

#[test]
fn json_rpc_batches_and_remote_execution_fail_closed() -> anyhow::Result<()> {
    let batch = request(
        "app.composio.dev",
        "/tool_router/v3/trs_1/mcp",
        &serde_json::json!([]),
    );
    assert!(matches!(
        decode(&batch, &catalogs()?),
        DecodeResult::Deny(_)
    ));

    let shell = request(
        "app.composio.dev",
        "/tool_router/v3/trs_1/mcp",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "COMPOSIO_REMOTE_BASH_TOOL",
                "arguments": {"command": "secret"}
            }
        }),
    );
    assert!(matches!(
        decode(&shell, &catalogs()?),
        DecodeResult::Deny(_)
    ));
    Ok(())
}

#[test]
fn recognized_mcp_discovery_passes_through_but_other_hosts_are_unrelated() -> anyhow::Result<()> {
    let list = request(
        "app.composio.dev",
        "/tool_router/v3/trs_1/mcp",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1.5,
            "method": "tools/list",
            "enabled": true,
            "optional": null,
            "metadata": [-1, "safe"]
        }),
    );
    assert!(matches!(
        decode(&list, &catalogs()?),
        DecodeResult::Passthrough
    ));

    let unrelated = request(
        "app.composio.dev.evil.test",
        "/tool_router/v3/trs_1/mcp",
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    assert!(matches!(
        decode(&unrelated, &catalogs()?),
        DecodeResult::Unrelated
    ));
    Ok(())
}

#[test]
fn duplicate_json_keys_fail_closed_at_every_execution_selector_level() -> anyhow::Result<()> {
    for (host, path, body) in [
        (
            "backend.composio.dev",
            "/api/v3/tools/execute/GMAIL_SEND_EMAIL",
            r#"{"version":"20251111_00","version":"latest","arguments":{}}"#,
        ),
        (
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}"#,
        ),
        (
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"GMAIL_FETCH_EMAILS","name":"GMAIL_SEND_EMAIL","arguments":{}}}"#,
        ),
        (
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"GMAIL_FETCH_EMAILS","arguments":{"account":"one","account":"two"}}}"#,
        ),
        (
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"COMPOSIO_MULTI_EXECUTE_TOOL","arguments":{"tools":[{"tool_slug":"GMAIL_FETCH_EMAILS","tool_slug":"GMAIL_SEND_EMAIL"}]}}}"#,
        ),
    ] {
        let request = request_with_body(host, path, body.as_bytes().to_vec());
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("duplicate JSON key must fail closed");
        };
        assert_eq!(denial.code, "malformed_payload");
    }
    Ok(())
}

#[test]
fn mcp_resource_methods_fail_closed() -> anyhow::Result<()> {
    for method in ["resources/list", "resources/read"] {
        let request = request(
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method}),
        );
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("MCP resource method must fail closed");
        };
        assert_eq!(denial.code, "unsupported_mcp_method");
    }
    Ok(())
}

/// Account-lifecycle writes are logical actions: they must reach capability
/// and Cedar evaluation as `account.permission.change` instead of passing
/// through ungoverned.
#[test]
fn lifecycle_writes_are_governed_as_account_permission_change() -> anyhow::Result<()> {
    for (method, path, slug, account, session) in [
        (
            Method::POST,
            "/api/v3/connected_accounts",
            "COMPOSIO_CREATE_CONNECTED_ACCOUNT",
            None,
            None,
        ),
        (
            Method::DELETE,
            "/api/v3/connected_accounts/ca_123",
            "COMPOSIO_DELETE_CONNECTED_ACCOUNT",
            Some("ca_123"),
            None,
        ),
        (
            Method::PATCH,
            "/api/v3/connected_accounts/ca_123",
            "COMPOSIO_UPDATE_CONNECTED_ACCOUNT",
            Some("ca_123"),
            None,
        ),
        (
            Method::POST,
            "/api/v3/connected_accounts/ca_123/refresh",
            "COMPOSIO_UPDATE_CONNECTED_ACCOUNT",
            Some("ca_123"),
            None,
        ),
        (
            Method::POST,
            "/api/v3/auth_configs",
            "COMPOSIO_CREATE_AUTH_CONFIG",
            None,
            None,
        ),
        (
            Method::DELETE,
            "/api/v3/auth_configs/ac_9",
            "COMPOSIO_DELETE_AUTH_CONFIG",
            None,
            None,
        ),
        (
            Method::POST,
            "/api/v3.1/tool_router/session/trs_1/link",
            "COMPOSIO_LINK_SESSION_ACCOUNT",
            None,
            Some("trs_1"),
        ),
    ] {
        let mut lifecycle = request("backend.composio.dev", path, &serde_json::json!({}));
        lifecycle.method = method.clone();
        if method != Method::POST {
            lifecycle.body = None;
        }
        let decoded = actions(decode(&lifecycle, &catalogs()?))?;
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].envelope.intent.action_class,
            "account.permission.change"
        );
        assert_eq!(
            decoded[0].envelope.intent.policy_resource_display(),
            format!("composio://composio/{slug}")
        );
        assert_eq!(
            decoded[0].envelope.intent.raw_action_ref,
            format!("{method} {path}")
        );
        assert_eq!(decoded[0].context.connected_account_id.as_deref(), account);
        assert_eq!(decoded[0].context.session_id.as_deref(), session);
    }
    Ok(())
}

#[test]
fn non_post_and_backend_lifecycle_routes_are_classified_exactly() -> anyhow::Result<()> {
    for (method, host, path, expected_passthrough) in [
        (Method::GET, "backend.composio.dev", "/api/v3/tools", true),
        (
            Method::GET,
            "backend.composio.dev",
            "/api/v3/connected_accounts",
            true,
        ),
        (
            Method::GET,
            "backend.composio.dev",
            "/api/v3/execute",
            false,
        ),
        (
            Method::GET,
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            true,
        ),
        (
            Method::POST,
            "backend.composio.dev",
            "/api/v3/toolkits",
            true,
        ),
        (
            Method::POST,
            "backend.composio.dev",
            "/api/v3/unsupported",
            false,
        ),
    ] {
        let mut request = request(host, path, &serde_json::json!({}));
        request.method = method;
        let decoded = decode(&request, &catalogs()?);
        assert_eq!(
            matches!(decoded, DecodeResult::Passthrough),
            expected_passthrough
        );
    }
    Ok(())
}

#[test]
fn missing_and_scalar_payloads_fail_closed() -> anyhow::Result<()> {
    let mut missing = request(
        "backend.composio.dev",
        "/api/v3/tools/execute/GMAIL_SEND_EMAIL",
        &serde_json::json!({}),
    );
    missing.body = None;

    for request in [
        missing,
        request_with_body(
            "backend.composio.dev",
            "/api/v3/tools/execute/GMAIL_SEND_EMAIL",
            b"true".to_vec(),
        ),
    ] {
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("missing or scalar payload must fail closed");
        };
        assert_eq!(denial.code, "malformed_payload");
    }
    Ok(())
}

#[test]
fn unsupported_backend_execution_shapes_fail_closed() -> anyhow::Result<()> {
    for (path, body, expected_code) in [
        (
            "/api/v3/tools/execute/proxy",
            serde_json::json!({"version": "20251111_00"}),
            "raw_proxy_unsupported",
        ),
        (
            "/api/v3.1/tool_router/session/trs_1/execute",
            serde_json::json!({"tool_slug": "GMAIL_SEND_EMAIL", "experimental": {}}),
            "custom_tools_unsupported",
        ),
        (
            "/api/v3.1/tool_router/session/trs_1/execute",
            serde_json::json!({"arguments": {}}),
            "malformed_payload",
        ),
        (
            "/api/v3.1/tool_router/session/trs_1/execute_meta",
            serde_json::json!({"arguments": {}}),
            "malformed_payload",
        ),
    ] {
        let request = request("backend.composio.dev", path, &body);
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("unsupported backend execution shape must fail closed");
        };
        assert_eq!(denial.code, expected_code);
    }
    Ok(())
}

#[test]
fn meta_tool_control_and_execution_routes_are_explicit() -> anyhow::Result<()> {
    for slug in ["COMPOSIO_SEARCH_TOOLS", "COMPOSIO_GET_TOOL_SCHEMAS"] {
        let request = request(
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": slug, "arguments": {}}
            }),
        );
        assert!(matches!(
            decode(&request, &catalogs()?),
            DecodeResult::Passthrough
        ));
    }

    let execute = request(
        "app.composio.dev",
        "/tool_router/v3/trs_1/mcp",
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "COMPOSIO_EXECUTE_TOOL",
                "arguments": {
                    "tool_slug": "GMAIL_FETCH_EMAILS",
                    "account": "mailbox"
                }
            }
        }),
    );
    assert_eq!(
        actions(decode(&execute, &catalogs()?))?[0]
            .context
            .connected_account_id
            .as_deref(),
        Some("mailbox")
    );

    for (slug, arguments, expected_code) in [
        (
            "COMPOSIO_EXECUTE_TOOL",
            serde_json::Value::Null,
            "malformed_payload",
        ),
        (
            "COMPOSIO_EXECUTE_TOOL",
            serde_json::json!({}),
            "malformed_payload",
        ),
        (
            "COMPOSIO_UNKNOWN_TOOL",
            serde_json::json!({}),
            "unsupported_meta_tool",
        ),
    ] {
        let request = request(
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": slug, "arguments": arguments}
            }),
        );
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("invalid meta-tool shape must fail closed");
        };
        assert_eq!(denial.code, expected_code);
    }
    Ok(())
}

#[test]
fn invalid_multi_execute_shapes_fail_closed() -> anyhow::Result<()> {
    let too_many = vec![serde_json::json!({"tool_slug": "GMAIL_FETCH_EMAILS"}); 51];
    for (arguments, expected_code) in [
        (serde_json::Value::Null, "malformed_payload"),
        (serde_json::json!({}), "malformed_payload"),
        (serde_json::json!({"tools": []}), "invalid_batch_size"),
        (serde_json::json!({"tools": too_many}), "invalid_batch_size"),
        (
            serde_json::json!({"tools": ["not-an-object"]}),
            "malformed_payload",
        ),
        (
            serde_json::json!({"tools": [{"arguments": {}}]}),
            "malformed_payload",
        ),
        (
            serde_json::json!({"tools": [{"tool_slug": "GMAIL_UNKNOWN"}]}),
            "unknown_tool",
        ),
    ] {
        let request = request(
            "app.composio.dev",
            "/tool_router/v3/trs_1/mcp",
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "COMPOSIO_MULTI_EXECUTE_TOOL",
                    "arguments": arguments
                }
            }),
        );
        let DecodeResult::Deny(denial) = decode(&request, &catalogs()?) else {
            anyhow::bail!("invalid multi-execute shape must fail closed");
        };
        assert_eq!(denial.code, expected_code);
    }
    Ok(())
}

#[test]
fn catalog_validation_rejects_unmapped_and_unknown_classes() {
    let unmapped = GMAIL_MAPPING.replace("\"communication.external.read\"", "null");
    assert!(matches!(
        ComposioCatalogs::from_json_pairs([(GMAIL_SOURCE, unmapped.as_str())]),
        Err(firma_sidecar::composio::CatalogError::MissingMapping)
    ));

    let unknown = GMAIL_MAPPING.replace("\"communication.external.read\"", "\"gmail.read\"");
    assert!(matches!(
        ComposioCatalogs::from_json_pairs([(GMAIL_SOURCE, unknown.as_str())]),
        Err(firma_sidecar::composio::CatalogError::UnknownActionClass)
    ));
}
