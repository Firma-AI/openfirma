//! Decodes supported Composio execution protocols into logical actions.
//!
//! The decoder runs before generic HTTP normalization. It recognizes the two
//! exact Composio hosts, rejects ambiguous execution shapes, and never retains
//! tool arguments in logical envelopes or diagnostics.

mod catalog;

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chrono::Utc;
use firma_core::{ActionParams, ExecutionIntent, HttpMethod, HttpParams};
use firma_http::Method;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::normalizer::{NormalizedEnvelope, RawRequest};

#[doc(inline)]
pub use catalog::{CatalogError, ComposioCatalogs};

const BACKEND_HOST: &str = "backend.composio.dev";
const APP_HOST: &str = "app.composio.dev";
const MAX_MULTI_ACTIONS: usize = 50;

/// Exact hosts the decoder recognizes; HTTPS MITM must cover both for
/// Composio governance to see any tool call.
pub(crate) const PROTECTED_HOSTS: [&str; 2] = [BACKEND_HOST, APP_HOST];

/// Canonical class assigned to Composio account-lifecycle writes.
///
/// Linking, updating, or removing connected accounts and auth configurations
/// changes what an agent can reach through Composio, so those writes are
/// logical actions rather than ungoverned passthrough.
const LIFECYCLE_ACTION_CLASS: &str = "account.permission.change";

/// Toolkit segment used by lifecycle policy resources
/// (`composio://composio/<slug>`).
const LIFECYCLE_TOOLKIT: &str = "composio";

/// Sanitized metadata attached to one decoded logical action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposioContext {
    /// Pinned toolkit identifier.
    pub toolkit: String,
    /// Pinned tool slug.
    pub tool_slug: String,
    /// Composio user selector or `PAi` assistant value.
    pub user_id: Option<String>,
    /// Requested connected account identifier or alias.
    pub connected_account_id: Option<String>,
    /// Tool Router or hosted MCP session identity.
    pub session_id: Option<String>,
    /// Zero-based child index for a multi-execute call.
    pub batch_index: Option<u32>,
    /// Total child count for a multi-execute call.
    pub batch_size: Option<u32>,
}

/// One immutable logical action decoded from the original request.
#[derive(Debug, Clone)]
pub struct ComposioAction {
    /// Logical policy envelope with no arguments or sensitive headers.
    pub envelope: NormalizedEnvelope,
    /// Sanitized Composio policy context.
    pub context: ComposioContext,
}

/// Sanitized fail-closed protocol rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolDenial {
    /// Stable machine-readable denial code.
    pub code: &'static str,
    /// Human-readable detail that never includes request arguments.
    pub detail: &'static str,
}

/// Four-way Composio protocol classification.
#[derive(Debug, Clone)]
pub enum DecodeResult {
    /// Traffic does not target an exact protected Composio host.
    Unrelated,
    /// A recognized control-plane or discovery call may pass through.
    Passthrough,
    /// One or more ordered logical execution actions were decoded.
    Actions(Vec<ComposioAction>),
    /// Protected traffic was malformed, ambiguous, or unsupported.
    Deny(ProtocolDenial),
}

/// Decode a raw HTTP request before generic normalization.
#[must_use]
pub fn decode(request: &RawRequest, catalogs: &ComposioCatalogs) -> DecodeResult {
    let host = canonical_host(&request.host);
    if host != BACKEND_HOST && host != APP_HOST {
        return DecodeResult::Unrelated;
    }
    let result = decode_protected(request, &host, catalogs);
    // A query string never participates in the policy decision, so letting it
    // ride along on an admitted dispatch would smuggle unevaluated input
    // upstream. Read-only passthrough keeps its query (pagination and the
    // like); governed actions refuse it.
    if matches!(result, DecodeResult::Actions(_)) && request.path.contains('?') {
        return deny(
            "query_string_unsupported",
            "Composio governed requests must not carry a query string",
        );
    }
    result
}

fn decode_protected(request: &RawRequest, host: &str, catalogs: &ComposioCatalogs) -> DecodeResult {
    if request.method != Method::POST {
        if let Some(result) = decode_lifecycle_write(request, host) {
            return result;
        }
        // Lifecycle families accept reads and governed writes only; an
        // extension method (e.g. TRACE) is neither and must not audit as a
        // recognized passthrough.
        if host == BACKEND_HOST
            && is_lifecycle_path(path_only(&request.path))
            && !matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS)
        {
            return deny("unsupported_route", "unsupported Composio route");
        }
        return if is_recognized_non_execution_path(host, path_only(&request.path)) {
            DecodeResult::Passthrough
        } else {
            deny("unsupported_route", "unsupported Composio route")
        };
    }
    let Some(body) = request.body.as_deref() else {
        return deny("malformed_payload", "invalid Composio execution payload");
    };
    let Ok(payload) = parse_json_without_duplicate_keys(body) else {
        return deny("malformed_payload", "invalid Composio execution payload");
    };
    if payload.is_array() {
        return deny(
            "json_rpc_batch_unsupported",
            "Composio JSON-RPC batches are unsupported",
        );
    }
    let Some(object) = payload.as_object() else {
        return deny("malformed_payload", "invalid Composio execution payload");
    };
    // Hosted MCP is served under both protected hosts, so the JSON-RPC shape
    // is selected by path rather than by host.
    if is_mcp_path(path_only(&request.path)) {
        return decode_mcp(request, object, catalogs);
    }
    if host == APP_HOST {
        return deny("unsupported_route", "unsupported Composio route");
    }
    decode_backend(request, object, catalogs)
}

fn decode_backend(
    request: &RawRequest,
    payload: &Map<String, Value>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    let path = path_only(&request.path);
    let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    match components.as_slice() {
        ["api", "v3" | "v3.1", "tools", "execute", slug] => {
            decode_direct(request, payload, slug, catalogs)
        }
        [
            "api",
            "v3" | "v3.1",
            "tool_router",
            "session",
            session_id,
            "execute",
        ] => decode_session(request, payload, Some(session_id), catalogs),
        [
            "api",
            "v3" | "v3.1",
            "tool_router",
            "session",
            session_id,
            "execute_meta",
        ] => decode_meta_route(request, payload, Some(session_id), catalogs),
        [
            "api",
            "v3" | "v3.1",
            "connected_accounts" | "auth_configs",
            ..,
        ]
        | ["api", "v3" | "v3.1", "tool_router", "session", _, "link"] => {
            decode_lifecycle_write(request, BACKEND_HOST)
                .unwrap_or_else(|| deny("unsupported_route", "unsupported Composio route"))
        }
        _ if is_recognized_non_execution_path(BACKEND_HOST, path) => DecodeResult::Passthrough,
        _ => deny("unsupported_route", "unsupported Composio route"),
    }
}

/// Return whether a path belongs to a governed account-lifecycle family.
fn is_lifecycle_path(path: &str) -> bool {
    let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    matches!(
        components.as_slice(),
        [
            "api",
            "v3" | "v3.1",
            "connected_accounts" | "auth_configs",
            ..,
        ] | ["api", "v3" | "v3.1", "tool_router", "session", _, "link"]
    )
}

/// Decode an account-lifecycle write into one governed logical action.
///
/// Returns `None` for requests that are not lifecycle writes (read methods or
/// unrelated routes), letting the caller fall back to passthrough or denial.
fn decode_lifecycle_write(request: &RawRequest, host: &str) -> Option<DecodeResult> {
    if host != BACKEND_HOST
        || !matches!(
            request.method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        )
    {
        return None;
    }
    let path = path_only(&request.path);
    let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    match components.as_slice() {
        [
            "api",
            "v3" | "v3.1",
            family @ ("connected_accounts" | "auth_configs"),
            rest @ ..,
        ] => {
            let verb = match request.method {
                Method::POST if rest.is_empty() => "CREATE",
                Method::DELETE => "DELETE",
                _ => "UPDATE",
            };
            let noun = if *family == "connected_accounts" {
                "CONNECTED_ACCOUNT"
            } else {
                "AUTH_CONFIG"
            };
            let account = (*family == "connected_accounts")
                .then(|| rest.first().copied())
                .flatten();
            Some(lifecycle_action(
                request,
                &format!("COMPOSIO_{verb}_{noun}"),
                None,
                account,
            ))
        }
        [
            "api",
            "v3" | "v3.1",
            "tool_router",
            "session",
            session_id,
            "link",
        ] => Some(lifecycle_action(
            request,
            "COMPOSIO_LINK_SESSION_ACCOUNT",
            Some(session_id),
            None,
        )),
        _ => None,
    }
}

/// Build the single governed logical action for a lifecycle write.
fn lifecycle_action(
    request: &RawRequest,
    slug: &str,
    session_id: Option<&str>,
    account: Option<&str>,
) -> DecodeResult {
    let Ok(method) = HttpMethod::try_from(&request.method) else {
        return deny("unsupported_route", "unsupported Composio route");
    };
    let context = ComposioContext {
        toolkit: LIFECYCLE_TOOLKIT.to_string(),
        tool_slug: slug.to_string(),
        user_id: None,
        connected_account_id: account.map(str::to_string),
        session_id: session_id.map(str::to_string),
        batch_index: None,
        batch_size: None,
    };
    DecodeResult::Actions(vec![ComposioAction {
        envelope: logical_envelope(request, LIFECYCLE_ACTION_CLASS, &context, method),
        context,
    }])
}

fn decode_direct(
    request: &RawRequest,
    payload: &Map<String, Value>,
    slug: &str,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    if slug == "proxy" {
        return deny(
            "raw_proxy_unsupported",
            "Composio raw proxy execution is unsupported",
        );
    }
    let Some(version) = string_field(payload, "version") else {
        return deny(
            "unpinned_tool",
            "Composio direct execution requires a pinned toolkit version",
        );
    };
    decode_tool(
        request,
        slug,
        Some(version),
        string_field(payload, "user_id"),
        string_field(payload, "connected_account_id"),
        None,
        None,
        catalogs,
    )
}

fn decode_session(
    request: &RawRequest,
    payload: &Map<String, Value>,
    session_id: Option<&str>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    // Best-effort marker: Composio may rename this field, so the catalog
    // lookup below stays the real gate for custom tools; this check only
    // produces a more specific denial code while the marker matches.
    if payload.contains_key("experimental") {
        return deny(
            "custom_tools_unsupported",
            "experimental Composio custom tools are unsupported",
        );
    }
    let Some(slug) = string_field(payload, "tool_slug") else {
        return deny("malformed_payload", "invalid Composio execution payload");
    };
    if slug.starts_with("COMPOSIO_") {
        return decode_meta(
            request,
            slug,
            payload.get("arguments").and_then(Value::as_object),
            session_id,
            catalogs,
        );
    }
    decode_tool(
        request,
        slug,
        string_field(payload, "version"),
        string_field(payload, "user_id"),
        string_field(payload, "account"),
        session_id,
        None,
        catalogs,
    )
}

fn decode_meta_route(
    request: &RawRequest,
    payload: &Map<String, Value>,
    session_id: Option<&str>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    let Some(slug) = string_field(payload, "tool_slug") else {
        return deny("malformed_payload", "invalid Composio execution payload");
    };
    decode_meta(
        request,
        slug,
        payload.get("arguments").and_then(Value::as_object),
        session_id,
        catalogs,
    )
}

fn decode_mcp(
    request: &RawRequest,
    payload: &Map<String, Value>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    let Some(method) = string_field(payload, "method") else {
        return deny("malformed_payload", "invalid Composio JSON-RPC payload");
    };
    if method != "tools/call" {
        return if matches!(
            method,
            "initialize" | "notifications/initialized" | "ping" | "tools/list"
        ) {
            DecodeResult::Passthrough
        } else {
            deny(
                "unsupported_mcp_method",
                "unsupported Composio JSON-RPC method",
            )
        };
    }
    let Some(params) = payload.get("params").and_then(Value::as_object) else {
        return deny("malformed_payload", "invalid Composio JSON-RPC payload");
    };
    let Some(slug) = string_field(params, "name") else {
        return deny("malformed_payload", "invalid Composio JSON-RPC payload");
    };
    let arguments = params.get("arguments").and_then(Value::as_object);
    let session_id = mcp_session_id(path_only(&request.path));
    if slug.starts_with("COMPOSIO_") {
        return decode_meta(request, slug, arguments, session_id, catalogs);
    }
    let account = arguments.and_then(|value| {
        string_field(value, "account").or_else(|| string_field(value, "connected_account_id"))
    });
    decode_tool(
        request, slug, None, None, account, session_id, None, catalogs,
    )
}

fn decode_meta(
    request: &RawRequest,
    slug: &str,
    arguments: Option<&Map<String, Value>>,
    session_id: Option<&str>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    match slug {
        "COMPOSIO_MULTI_EXECUTE_TOOL" => decode_multi(request, arguments, session_id, catalogs),
        "COMPOSIO_EXECUTE_TOOL" => {
            let Some(arguments) = arguments else {
                return deny("malformed_payload", "invalid Composio execution payload");
            };
            let Some(child_slug) = string_field(arguments, "tool_slug") else {
                return deny("malformed_payload", "invalid Composio execution payload");
            };
            decode_tool(
                request,
                child_slug,
                string_field(arguments, "version"),
                string_field(arguments, "user_id"),
                string_field(arguments, "account")
                    .or_else(|| string_field(arguments, "connected_account_id")),
                session_id,
                None,
                catalogs,
            )
        }
        "COMPOSIO_SEARCH_TOOLS" | "COMPOSIO_GET_TOOL_SCHEMAS" => DecodeResult::Passthrough,
        "COMPOSIO_REMOTE_BASH_TOOL" | "COMPOSIO_REMOTE_WORKBENCH" => deny(
            "remote_execution_unsupported",
            "Composio shell and workbench execution are unsupported",
        ),
        _ => deny("unsupported_meta_tool", "unsupported Composio meta-tool"),
    }
}

fn decode_multi(
    request: &RawRequest,
    arguments: Option<&Map<String, Value>>,
    session_id: Option<&str>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    let Some(tools) = arguments
        .and_then(|value| value.get("tools"))
        .and_then(Value::as_array)
    else {
        return deny(
            "malformed_payload",
            "invalid Composio multi-execute payload",
        );
    };
    if tools.is_empty() || tools.len() > MAX_MULTI_ACTIONS {
        return deny(
            "invalid_batch_size",
            "Composio multi-execute requires between 1 and 50 tools",
        );
    }
    let Ok(batch_size) = u32::try_from(tools.len()) else {
        return deny(
            "invalid_batch_size",
            "Composio multi-execute requires between 1 and 50 tools",
        );
    };
    let mut actions = Vec::with_capacity(tools.len());
    for (index, tool) in tools.iter().enumerate() {
        let Some(tool) = tool.as_object() else {
            return deny(
                "malformed_payload",
                "invalid Composio multi-execute payload",
            );
        };
        let Some(slug) = string_field(tool, "tool_slug") else {
            return deny(
                "malformed_payload",
                "invalid Composio multi-execute payload",
            );
        };
        let Ok(batch_index) = u32::try_from(index) else {
            return deny(
                "invalid_batch_size",
                "Composio multi-execute requires between 1 and 50 tools",
            );
        };
        match action_for_tool(
            request,
            slug,
            string_field(tool, "version"),
            string_field(tool, "user_id"),
            string_field(tool, "account").or_else(|| string_field(tool, "connected_account_id")),
            session_id,
            Some((batch_index, batch_size)),
            catalogs,
        ) {
            Ok(action) => actions.push(action),
            Err(denial) => return DecodeResult::Deny(denial),
        }
    }
    DecodeResult::Actions(actions)
}

#[expect(
    clippy::too_many_arguments,
    reason = "protocol fields remain explicit at the trust boundary"
)]
fn decode_tool(
    request: &RawRequest,
    slug: &str,
    version: Option<&str>,
    user_id: Option<&str>,
    account: Option<&str>,
    session_id: Option<&str>,
    batch: Option<(u32, u32)>,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    match action_for_tool(
        request, slug, version, user_id, account, session_id, batch, catalogs,
    ) {
        Ok(action) => DecodeResult::Actions(vec![action]),
        Err(denial) => DecodeResult::Deny(denial),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "protocol fields remain explicit at the trust boundary"
)]
fn action_for_tool(
    request: &RawRequest,
    slug: &str,
    version: Option<&str>,
    user_id: Option<&str>,
    account: Option<&str>,
    session_id: Option<&str>,
    batch: Option<(u32, u32)>,
    catalogs: &ComposioCatalogs,
) -> Result<ComposioAction, ProtocolDenial> {
    let Some(entry) = catalogs.lookup(slug) else {
        return Err(ProtocolDenial {
            code: "unknown_tool",
            detail: "Composio tool is not in a pinned local catalog",
        });
    };
    if let Some(version) = version
        && version != entry.version
    {
        return Err(ProtocolDenial {
            code: "version_mismatch",
            detail: "Composio toolkit version does not match the pinned catalog",
        });
    }
    let (batch_index, batch_size) =
        batch.map_or((None, None), |(index, size)| (Some(index), Some(size)));
    let context = ComposioContext {
        toolkit: entry.toolkit.clone(),
        tool_slug: slug.to_string(),
        user_id: user_id.map(str::to_string),
        connected_account_id: account.map(str::to_string),
        session_id: session_id.map(str::to_string),
        batch_index,
        batch_size,
    };
    Ok(ComposioAction {
        envelope: logical_envelope(
            request,
            entry.action_class.as_str(),
            &context,
            HttpMethod::POST,
        ),
        context,
    })
}

fn logical_envelope(
    request: &RawRequest,
    action_class: &str,
    context: &ComposioContext,
    method: HttpMethod,
) -> NormalizedEnvelope {
    let mut resource = BTreeMap::from([
        ("host".to_string(), canonical_host(&request.host)),
        ("path".to_string(), path_only(&request.path).to_string()),
        ("provider".to_string(), "composio".to_string()),
        (
            "policy_resource".to_string(),
            format!("composio://{}/{}", context.toolkit, context.tool_slug),
        ),
        ("composio_toolkit".to_string(), context.toolkit.clone()),
        ("composio_tool_slug".to_string(), context.tool_slug.clone()),
    ]);
    insert_optional(
        &mut resource,
        "composio_user_id",
        context.user_id.as_deref(),
    );
    insert_optional(
        &mut resource,
        "composio_account",
        context.connected_account_id.as_deref(),
    );
    insert_optional(
        &mut resource,
        "composio_session_id",
        context.session_id.as_deref(),
    );
    if let Some(index) = context.batch_index {
        resource.insert("composio_batch_index".to_string(), index.to_string());
    }
    if let Some(size) = context.batch_size {
        resource.insert("composio_batch_size".to_string(), size.to_string());
    }
    NormalizedEnvelope {
        intent: ExecutionIntent {
            action_class: action_class.to_string(),
            resource,
            params: ActionParams::Http(HttpParams {
                method,
                headers: HashMap::new(),
                body: None,
                query: HashMap::new(),
            }),
            raw_transport: if request.is_https { "https" } else { "http" }.to_string(),
            raw_action_ref: format!("{method} {}", path_only(&request.path)),
        },
        timestamp: Utc::now(),
    }
}

fn insert_optional(resource: &mut BTreeMap<String, String>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        resource.insert(key.to_string(), value.to_string());
    }
}

/// Read a non-empty string field, treating an empty value as absent.
fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = entries.next_value::<StrictJsonValue>()?;
            object.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(object)))
    }
}

fn parse_json_without_duplicate_keys(body: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let payload = StrictJsonValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(payload.0)
}

pub(crate) fn is_protected_host(host: &str) -> bool {
    matches!(canonical_host(host).as_str(), BACKEND_HOST | APP_HOST)
}

/// Lowercase the host and strip any trailing `:port`, not just the scheme
/// default, so a nonstandard port cannot demote a protected host to
/// `Unrelated` generic normalization.
fn canonical_host(host: &str) -> String {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    match normalized.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            name.to_string()
        }
        _ => normalized,
    }
}

fn path_only(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

fn is_mcp_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    matches!(
        parts.as_slice(),
        ["tool_router", "v3" | "v3.1", _, "mcp"] | ["api", "v3" | "v3.1", "mcp", _]
    )
}

fn mcp_session_id(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    match parts.as_slice() {
        ["tool_router", "v3" | "v3.1", session_id, "mcp"]
        | ["api", "v3" | "v3.1", "mcp", session_id] => Some(session_id),
        _ => None,
    }
}

fn is_recognized_non_execution_path(host: &str, path: &str) -> bool {
    // Hosted MCP sessions use GET for the event stream and DELETE for
    // teardown; neither carries a tool call.
    if is_mcp_path(path) {
        return true;
    }
    if host == APP_HOST {
        return false;
    }
    let parts: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    matches!(
        parts.as_slice(),
        ["api", "v3" | "v3.1", "tools"]
            | ["api", "v3" | "v3.1", "tools", _]
            | [
                "api",
                "v3" | "v3.1",
                "toolkits" | "connected_accounts" | "auth_configs",
                ..
            ]
            | ["api", "v3" | "v3.1", "tool_router", "session"]
            | ["api", "v3" | "v3.1", "tool_router", "session", _]
            | [
                "api",
                "v3" | "v3.1",
                "tool_router",
                "session",
                _,
                "tools" | "toolkits" | "search" | "link"
            ]
    )
}

fn deny(code: &'static str, detail: &'static str) -> DecodeResult {
    DecodeResult::Deny(ProtocolDenial { code, detail })
}
