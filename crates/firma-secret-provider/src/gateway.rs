use firma_http::Str;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(tag = "action")]
pub enum GatewayRequest<'a> {
    #[serde(rename = "secret.resolve")]
    Resolve(#[serde(borrow)] ResolveRequest<'a>),
    #[serde(rename = "secret.push")]
    Push(#[serde(borrow)] PushRequest<'a>),
}

#[derive(Deserialize, Serialize)]
pub struct ResolveRequest<'a> {
    #[serde(borrow)]
    pub placeholders: Vec<Str<'a>>,
    /// Target host of the outbound request. Used to filter domain-scoped
    /// secrets: a secret stored for `api.github.com` will not resolve for
    /// requests to `api.stripe.com`.
    pub domain: Str<'a>,
}

#[derive(Deserialize, Serialize)]
pub struct PushRequest<'a> {
    /// Already-minted placeholder token (the Sidecar mints locally so it can
    /// substitute synchronously into the response body it forwards).
    #[serde(borrow)]
    pub placeholder: Str<'a>,
    /// Base64-encoded plaintext secret value.
    pub value_b64: Str<'a>,
    /// Host the secret is scoped to, mirroring a CLI intercept's
    /// `domain_path`-derived scope: `Some(host)` when the matcher's
    /// `domain_path`/`domain_is_url` extracted a host from the item, `None`
    /// when it did not (the secret then resolves for any request host).
    #[serde(borrow, default)]
    pub domain: Option<Str<'a>>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum PlaceholderResult<'a> {
    Ok {
        #[serde(borrow)]
        secret_b64: Str<'a>,
    },
    Err {
        error: Str<'a>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum PushResponse<'a> {
    Ok {
        #[serde(borrow)]
        placeholder: Str<'a>,
    },
    Err {
        error: Str<'a>,
    },
}
