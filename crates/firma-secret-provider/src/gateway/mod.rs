//! Wire types and client transport for the secret-gateway control channel
//! between firma-sidecar's HTTP MITM intercept and firma-run's broker.
//!
//! The broker owns the persistent secret store; the Sidecar mints
//! placeholders locally (see [`crate::SecretPlaceholder`]) so it can
//! substitute them synchronously into the response body it forwards, then
//! reports the mapping to the broker via [`PushRequest`]. Later, when the
//! Sidecar needs to inject the real value into an outbound request, it looks
//! placeholders back up via [`ResolveRequest`]. [`Str`] borrows from the
//! request buffer where possible to avoid copying secret material.
//!
//! This module defines the wire types themselves; [`client`] implements the
//! transport that speaks the protocol over a [`client::config::GatewayClientConfig`]-tuned
//! connection to an [`endpoint::GatewayEndpoint`].

use std::collections::HashSet;

use firma_http::Authority;
use firma_http::Str;
use serde::{Deserialize, Serialize};

use crate::SecretPlaceholder;

pub mod client;
pub mod endpoint;

/// A gateway call, tagged by `action` in its wire representation (e.g.
/// `{"action": "secret.push", ...}`) so the broker can dispatch without a
/// second parse pass.
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum GatewayRequest<'a> {
    /// Look up previously pushed placeholders and return their plaintext
    /// values.
    #[serde(rename = "secret.resolve")]
    Resolve(#[serde(borrow)] ResolveRequest<'a>),
    /// Register a newly minted placeholder and the secret value it stands
    /// for.
    #[serde(rename = "secret.push")]
    Push(#[serde(borrow)] PushRequest<'a>),
}

/// Request to resolve a batch of placeholders back to plaintext, scoped to
/// the request's target host.
#[derive(Deserialize, Serialize)]
pub struct ResolveRequest<'a> {
    /// Placeholder tokens to resolve, in the order the response's
    /// [`PlaceholderResult`]s are returned.
    #[serde(borrow)]
    pub placeholders: Vec<Str<'a>>,
    /// Target host of the outbound request. Used to filter domain-scoped
    /// secrets: a secret stored for `api.github.com` will not resolve for
    /// requests to `api.stripe.com`.
    pub domain: Authority,
}

#[derive(Deserialize, Serialize)]
pub struct PushRequest<'a> {
    /// Already-minted placeholder token (the Sidecar mints locally so it can
    /// substitute synchronously into the response body it forwards).
    #[serde(borrow)]
    pub placeholder: Str<'a>,
    /// Base64-encoded plaintext secret value.
    #[serde(borrow)]
    pub value_b64: Str<'a>,
    /// Hosts the secret is scoped to, mirroring a CLI intercept's
    /// `domain_selector`-derived scope: one entry per host the matcher
    /// extracted from the item. A secret may legitimately be scoped to more
    /// than one host; an empty set means the secret is unscoped and
    /// resolves for any request host.
    pub domain: HashSet<Authority>,
}

/// Per-placeholder outcome of a [`ResolveRequest`]. One placeholder failing
/// to resolve (unknown token, wrong domain scope) does not fail the whole
/// batch — each entry reports its own success or error.
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaceholderResult<'a> {
    /// Base64-encoded plaintext secret value.
    Ok {
        #[serde(borrow)]
        secret_b64: Str<'a>,
    },
    /// Resolution failed, e.g. the placeholder is unknown or out of domain
    /// scope for the requesting host.
    Err {
        #[serde(borrow)]
        error: Str<'a>,
    },
}

/// Outcome of a [`PushRequest`].
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PushResponse<'a> {
    /// Echoes back the stored placeholder token.
    Ok { placeholder: SecretPlaceholder },
    /// The broker rejected or failed to persist the mapping.
    Err {
        #[serde(borrow)]
        error: Str<'a>,
    },
}
