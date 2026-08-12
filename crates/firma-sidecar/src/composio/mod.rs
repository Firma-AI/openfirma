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
use firma_http::{Authority, HeaderMap, Method};
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
const LIFECYCLE_WRITE_ACTION_CLASS: &str = "account.permission.change";

/// Canonical class assigned to Composio account-lifecycle reads.
///
/// Listing connected accounts or auth configurations discloses which
/// integrations exist and how they authenticate, so those reads are governed
/// credential disclosure rather than ungoverned discovery passthrough.
const LIFECYCLE_READ_ACTION_CLASS: &str = "credential.read";

/// Toolkit segment used by lifecycle policy resources
/// (`composio://composio/<slug>`).
const LIFECYCLE_TOOLKIT: &str = "composio";

/// Whether an execution route must carry the pinned toolkit version.
///
/// Direct execution has a native `version` field and requires one, so
/// Composio can only run the version the local snapshot classified. Tool
/// Router session routes and hosted MCP JSON-RPC define no version field in
/// Composio's API; demanding one there would deny every stock client, so on
/// those routes the pin is honored when a client chooses to attach one and
/// the pinned slug allowlist stays the guarantee when it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionPolicy {
    /// Deny `unpinned_tool` when the request carries no version.
    Required,
    /// Accept an absent version; a present but mismatched one still denies.
    Optional,
}

/// Sanitized metadata attached to one decoded logical action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposioContext {
    /// Pinned toolkit identifier.
    toolkit: String,
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
    let host = canonical_host(request.host.as_str());
    if host != BACKEND_HOST && host != APP_HOST {
        return DecodeResult::Unrelated;
    }
    // MCP session URLs deny query strings uniformly, discovery included, so
    // a query-carrying URL fails at `initialize` with a clear denial rather
    // than handshaking and then failing on every `tools/call`.
    if request.path.contains('?') && is_mcp_path(path_only(&request.path)) {
        return deny(
            "query_string_unsupported",
            "Composio MCP requests must not carry a query string",
        );
    }
    let result = decode_protected(request, &host, catalogs);
    // A query string never participates in the policy decision, so letting it
    // ride along on an admitted dispatch would smuggle unevaluated input
    // upstream. Read-only passthrough keeps its query (pagination and the
    // like); governed actions refuse it, except account-lifecycle reads, where
    // a cursor selects a page of the same listing rather than changing which
    // action is being classified.
    if matches!(result, DecodeResult::Actions(_))
        && request.path.contains('?')
        && !is_lifecycle_read(&result)
    {
        return deny(
            "query_string_unsupported",
            "Composio governed requests must not carry a query string",
        );
    }
    result
}

/// Whether a decoded result is entirely account-lifecycle reads.
///
/// Both conditions are needed: a catalog tool can also map to `credential.read`
/// (`GMAIL_LIST_CSE_KEYPAIRS` does), and only the synthetic lifecycle toolkit
/// distinguishes a route the decoder classified itself from a provider tool.
fn is_lifecycle_read(result: &DecodeResult) -> bool {
    let DecodeResult::Actions(actions) = result else {
        return false;
    };
    !actions.is_empty()
        && actions.iter().all(|action| {
            action.context.toolkit == LIFECYCLE_TOOLKIT
                && action.envelope.intent.action_class == LIFECYCLE_READ_ACTION_CLASS
        })
}

fn decode_protected(request: &RawRequest, host: &str, catalogs: &ComposioCatalogs) -> DecodeResult {
    if request.method != Method::POST {
        if let Some(result) = decode_lifecycle_write(request, host) {
            return result;
        }
        // Governed before the passthrough recognizer: `connected_accounts` and
        // `auth_configs` reads are credential disclosure, not discovery.
        if let Some(result) = decode_lifecycle_read(request, host) {
            return result;
        }
        let path = path_only(&request.path);
        if !is_recognized_non_execution_path(host, path) {
            return deny("unsupported_route", "unsupported Composio route");
        }
        // Recognized routes accept only read methods (plus DELETE for MCP
        // session teardown); an extension method such as TRACE is neither a
        // read nor a governed write and must not audit as passthrough.
        let allowed = if is_mcp_path(path) {
            matches!(
                request.method,
                Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE
            )
        } else {
            matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS)
        };
        return if allowed {
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
    // Lifecycle writes are checked first; execution routes never classify as
    // lifecycle, and a lifecycle route the write decoder declines (POST to
    // `session/{id}`) falls through to the fail-closed arm below.
    if let Some(result) = decode_lifecycle_write(request, BACKEND_HOST) {
        return result;
    }
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
        // Session creation binds the connected accounts every later call
        // executes within, so it decodes into governed lifecycle actions
        // rather than passing through. The read-route recognizer is
        // deliberately not reused as a POST allowlist: it enumerates GET
        // shapes, and admitting writes through it would skip capability
        // checks and policy evaluation — a POST to an existing session
        // resource (a route Composio does not define) falls through to the
        // fail-closed arm below.
        ["api", "v3" | "v3.1", "tool_router", "session"] => {
            decode_session_creation(request, payload)
        }
        _ => deny("unsupported_route", "unsupported Composio route"),
    }
}

/// Structural classification of a governed account-lifecycle route.
///
/// This is the single place the lifecycle route shapes are written down;
/// path detection and write decoding both derive from it so a new family or
/// API version cannot be added to one and silently missed by the other.
/// Fields borrow from the classified path to keep detection allocation-free.
enum LifecycleRoute<'a> {
    /// A `connected_accounts` or `auth_configs` route.
    Family {
        /// Slug noun for the family (`CONNECTED_ACCOUNT` or `AUTH_CONFIG`).
        noun: &'static str,
        /// Connected account identifier from the path, when addressed.
        account_id: Option<&'a str>,
        /// Whether the path addresses the collection rather than an item.
        is_collection: bool,
    },
    /// A Tool Router session resource (`session/{id}`).
    Session {
        /// Session identifier from the path.
        session_id: &'a str,
    },
    /// The Tool Router session `link` route.
    SessionLink {
        /// Session identifier from the path.
        session_id: &'a str,
    },
}

/// Classify a path against the governed lifecycle route shapes.
fn classify_lifecycle_route(path: &str) -> Option<LifecycleRoute<'_>> {
    let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    match components.as_slice() {
        [
            "api",
            "v3" | "v3.1",
            family @ ("connected_accounts" | "auth_configs"),
            rest @ ..,
        ] => Some(LifecycleRoute::Family {
            noun: if *family == "connected_accounts" {
                "CONNECTED_ACCOUNT"
            } else {
                "AUTH_CONFIG"
            },
            account_id: (*family == "connected_accounts")
                .then(|| rest.first().copied())
                .flatten(),
            is_collection: rest.is_empty(),
        }),
        ["api", "v3" | "v3.1", "tool_router", "session", session_id] => {
            Some(LifecycleRoute::Session { session_id })
        }
        [
            "api",
            "v3" | "v3.1",
            "tool_router",
            "session",
            session_id,
            "link",
        ] => Some(LifecycleRoute::SessionLink { session_id }),
        _ => None,
    }
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
    match classify_lifecycle_route(path_only(&request.path))? {
        LifecycleRoute::Family {
            noun,
            account_id,
            is_collection,
        } => {
            let verb = match request.method {
                Method::POST if is_collection => "CREATE",
                Method::DELETE => "DELETE",
                _ => "UPDATE",
            };
            Some(lifecycle_action(
                request,
                LIFECYCLE_WRITE_ACTION_CLASS,
                &format!("COMPOSIO_{verb}_{noun}"),
                None,
                account_id,
            ))
        }
        LifecycleRoute::Session { session_id } => {
            // Session creation targets the collection and is decoded by
            // `decode_session_creation`; a POST to an existing session
            // resource is declined here so `decode_backend` fails it closed.
            if request.method == Method::POST {
                return None;
            }
            if request.method == Method::DELETE {
                return Some(lifecycle_action(
                    request,
                    LIFECYCLE_WRITE_ACTION_CLASS,
                    "COMPOSIO_DELETE_SESSION",
                    Some(session_id),
                    None,
                ));
            }
            // A session update can rebind the session's connected accounts
            // (`connected_accounts` in Composio's patch schema), making it
            // the same perimeter-defining write as creation, so a body it
            // carries must be inspected and each selected account exposed
            // to policy; an uninspectable body fails closed.
            Some(decode_session_update(request, session_id))
        }
        LifecycleRoute::SessionLink { session_id } => Some(lifecycle_action(
            request,
            LIFECYCLE_WRITE_ACTION_CLASS,
            "COMPOSIO_LINK_SESSION_ACCOUNT",
            Some(session_id),
            None,
        )),
    }
}

/// Decode an account-lifecycle read into one governed logical action.
///
/// Reads of `connected_accounts` and `auth_configs` disclose which
/// integrations an agent can reach and how they authenticate, so they are
/// governed as `credential.read` instead of passing through with the other
/// discovery routes. Returns `None` for anything else — including Tool Router
/// session reads and MCP streams, which carry no credential metadata and stay
/// passthrough.
fn decode_lifecycle_read(request: &RawRequest, host: &str) -> Option<DecodeResult> {
    if host != BACKEND_HOST
        || !matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS)
    {
        return None;
    }
    let LifecycleRoute::Family {
        noun,
        account_id,
        is_collection,
    } = classify_lifecycle_route(path_only(&request.path))?
    else {
        return None;
    };
    let verb = if is_collection { "LIST" } else { "GET" };
    Some(lifecycle_action(
        request,
        LIFECYCLE_READ_ACTION_CLASS,
        &format!("COMPOSIO_{verb}_{noun}"),
        None,
        account_id,
    ))
}

/// Build the single governed logical action for a lifecycle request.
fn lifecycle_action(
    request: &RawRequest,
    action_class: &str,
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
        envelope: logical_envelope(request, action_class, &context, method),
        context,
    }])
}

/// Decode a Tool Router session creation into governed lifecycle actions.
///
/// Session creation is the perimeter-defining write: Composio stores the
/// selected accounts on the session, and a later call may omit the account
/// selector entirely, leaving the server to resolve it from that stored
/// state. Policy therefore meets each selected account here or never. One
/// `COMPOSIO_CREATE_SESSION` action is emitted per selected account, and a
/// creation that selects none still decodes into a single unbound action
/// because it reshapes the agent's reachable surface.
fn decode_session_creation(request: &RawRequest, payload: &Map<String, Value>) -> DecodeResult {
    session_perimeter_actions(
        request,
        "COMPOSIO_CREATE_SESSION",
        None,
        string_field(payload, "user_id"),
        payload,
    )
}

/// Decode a Tool Router session update into governed lifecycle actions.
///
/// Composio's session patch schema accepts a `connected_accounts` selection
/// that rebinds the accounts the session executes with, so an update is the
/// same perimeter-defining write as creation. A body that cannot be parsed
/// fails closed rather than decoding unbound, because it could smuggle a
/// rebinding past policy; an update without a body (or without an account
/// selection) decodes into a single unbound `COMPOSIO_UPDATE_SESSION`
/// action.
fn decode_session_update(request: &RawRequest, session_id: &str) -> DecodeResult {
    let Some(body) = request.body.as_deref() else {
        return lifecycle_action(
            request,
            LIFECYCLE_WRITE_ACTION_CLASS,
            "COMPOSIO_UPDATE_SESSION",
            Some(session_id),
            None,
        );
    };
    let Ok(payload) = parse_json_without_duplicate_keys(body) else {
        return deny("malformed_payload", "invalid Composio session payload");
    };
    let Some(payload) = payload.as_object() else {
        return deny("malformed_payload", "invalid Composio session payload");
    };
    session_perimeter_actions(
        request,
        "COMPOSIO_UPDATE_SESSION",
        Some(session_id),
        None,
        payload,
    )
}

/// Extract the deduplicated account selection from a session payload's
/// `connected_accounts` map.
///
/// Returns `None` when the payload selects no accounts. The selection must
/// be a map of non-empty string lists; anything else fails closed, and a
/// selection larger than the shared multi-action bound is refused so one
/// request cannot fan out into an unbounded number of policy evaluations.
fn selected_session_accounts(
    payload: &Map<String, Value>,
) -> Result<Option<Vec<&str>>, DecodeResult> {
    let Some(selected) = payload.get("connected_accounts") else {
        return Ok(None);
    };
    let Some(by_toolkit) = selected.as_object() else {
        return Err(deny(
            "malformed_payload",
            "invalid Composio session account selection",
        ));
    };
    let mut accounts: Vec<&str> = Vec::new();
    let mut total = 0_usize;
    for ids in by_toolkit.values() {
        let Some(ids) = ids.as_array() else {
            return Err(deny(
                "malformed_payload",
                "invalid Composio session account selection",
            ));
        };
        for id in ids {
            let Some(id) = id.as_str().filter(|value| !value.is_empty()) else {
                return Err(deny(
                    "malformed_payload",
                    "invalid Composio session account selection",
                ));
            };
            total += 1;
            if total > MAX_MULTI_ACTIONS {
                return Err(deny(
                    "invalid_batch_size",
                    "Composio session account selections are limited to 50 accounts",
                ));
            }
            if !accounts.contains(&id) {
                accounts.push(id);
            }
        }
    }
    Ok((!accounts.is_empty()).then_some(accounts))
}

/// Build the governed lifecycle actions for a perimeter-defining session
/// write, one per selected account or a single unbound action when the
/// payload selects none.
fn session_perimeter_actions(
    request: &RawRequest,
    slug: &str,
    session_id: Option<&str>,
    user_id: Option<&str>,
    payload: &Map<String, Value>,
) -> DecodeResult {
    let Ok(method) = HttpMethod::try_from(&request.method) else {
        return deny("unsupported_route", "unsupported Composio route");
    };
    let accounts = match selected_session_accounts(payload) {
        Ok(accounts) => accounts,
        Err(denial) => return denial,
    };
    let bound_accounts: Vec<Option<&str>> = accounts.map_or_else(
        || vec![None],
        |accounts| accounts.into_iter().map(Some).collect(),
    );
    DecodeResult::Actions(
        bound_accounts
            .into_iter()
            .map(|account| {
                let context = ComposioContext {
                    toolkit: LIFECYCLE_TOOLKIT.to_string(),
                    tool_slug: slug.to_string(),
                    user_id: user_id.map(str::to_string),
                    connected_account_id: account.map(str::to_string),
                    session_id: session_id.map(str::to_string),
                    batch_index: None,
                    batch_size: None,
                };
                ComposioAction {
                    envelope: logical_envelope(
                        request,
                        LIFECYCLE_WRITE_ACTION_CLASS,
                        &context,
                        method,
                    ),
                    context,
                }
            })
            .collect(),
    )
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
    decode_tool(
        request,
        slug,
        string_field(payload, "version"),
        string_field(payload, "user_id"),
        string_field(payload, "connected_account_id"),
        None,
        None,
        VersionPolicy::Required,
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
            VersionPolicy::Optional,
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
        VersionPolicy::Optional,
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
        VersionPolicy::Optional,
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
        return decode_meta(
            request,
            slug,
            arguments,
            session_id,
            VersionPolicy::Optional,
            catalogs,
        );
    }
    let account = arguments.and_then(|value| {
        string_field(value, "account").or_else(|| string_field(value, "connected_account_id"))
    });
    // JSON-RPC has no version slot of its own, so the pin travels as a tool
    // argument the same way the account selector does. It is honored when a
    // client sends it and cannot be demanded when one does not.
    let version = arguments.and_then(|value| string_field(value, "version"));
    decode_tool(
        request,
        slug,
        version,
        None,
        account,
        session_id,
        None,
        VersionPolicy::Optional,
        catalogs,
    )
}

fn decode_meta(
    request: &RawRequest,
    slug: &str,
    arguments: Option<&Map<String, Value>>,
    session_id: Option<&str>,
    policy: VersionPolicy,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    match slug {
        "COMPOSIO_MULTI_EXECUTE_TOOL" => {
            decode_multi(request, arguments, session_id, policy, catalogs)
        }
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
                policy,
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
    policy: VersionPolicy,
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
            policy,
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
    policy: VersionPolicy,
    catalogs: &ComposioCatalogs,
) -> DecodeResult {
    match action_for_tool(
        request, slug, version, user_id, account, session_id, batch, policy, catalogs,
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
    policy: VersionPolicy,
    catalogs: &ComposioCatalogs,
) -> Result<ComposioAction, ProtocolDenial> {
    let Some(entry) = catalogs.lookup(slug) else {
        return Err(ProtocolDenial {
            code: "unknown_tool",
            detail: "Composio tool is not in a pinned local catalog",
        });
    };
    // Every execution route funnels through here, so this is the single
    // version gate. A stated version must match the pin on every route; only
    // whether one is required at all varies, and only for hosted MCP.
    match version {
        Some(version) if version != entry.version => {
            return Err(ProtocolDenial {
                code: "version_mismatch",
                detail: "Composio toolkit version does not match the pinned catalog",
            });
        }
        None if policy == VersionPolicy::Required => {
            return Err(ProtocolDenial {
                code: "unpinned_tool",
                detail: "Composio execution requires a pinned toolkit version",
            });
        }
        _ => {}
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
        ("host".to_string(), envelope_host(request.host.as_str())),
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
                headers: HeaderMap::new(),
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

pub(crate) fn is_protected_host(host: &Authority) -> bool {
    matches!(
        canonical_host(host.as_str()).as_str(),
        BACKEND_HOST | APP_HOST
    )
}

/// Trim, lowercase, and strip any trailing `:port` and trailing dot — not
/// just the scheme default — so no host spelling (`Backend.Composio.Dev.`,
/// `backend.composio.dev.:443`, padded whitespace) can demote a protected
/// host to `Unrelated` generic normalization. Also used to canonicalize
/// mapping-rule host patterns before glob matching in the startup coverage
/// check.
pub(crate) fn canonical_host(host: &str) -> String {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let without_port = match normalized.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            name
        }
        _ => normalized.as_str(),
    };
    without_port.trim_end_matches('.').to_string()
}

/// Canonicalize the host recorded in a governed logical envelope.
///
/// The connector rebuilds the outbound URL from this resource value, so unlike
/// [`canonical_host`] a nonstandard port must survive: dropping it would
/// dispatch an admitted request to 443 instead of the port it arrived on.
/// Default ports still collapse, so every spelling of one authority yields a
/// single envelope host, exactly as generic normalization does.
fn envelope_host(host: &str) -> String {
    crate::normalizer::mapping::normalize_host_pattern(host)
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
    // `connected_accounts` and `auth_configs` are deliberately absent: their
    // reads are governed as `credential.read` by `decode_lifecycle_read` and
    // their writes by `decode_lifecycle_write`, so any method that reaches
    // here on those routes is neither and must fail closed.
    let parts: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
    matches!(
        parts.as_slice(),
        ["api", "v3" | "v3.1", "tools"]
            | ["api", "v3" | "v3.1", "tools", _]
            | ["api", "v3" | "v3.1", "toolkits", ..]
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
