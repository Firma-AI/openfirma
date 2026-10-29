//! The remote Authority connection inputs of `firma config --mode agent-remote`:
//! URL, optional CA certificate and public key, from flags, the existing
//! `firma.toml` or prompts.

use std::borrow::Cow;

use anyhow::{Context as _, Result};
use dialoguer::theme::ColorfulTheme;

use super::ExistingConfigDefaults;
use crate::args::config::InitArgs;

/// Preserve operator routing when only the URL spelling or scheme changes.
/// Compare parsed hosts and effective ports so equivalent IPv6 spellings and
/// implicit default ports do not discard a same-endpoint route or mTLS identity.
pub(super) fn same_authority_endpoint(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (url::Url::parse(left), url::Url::parse(right)) else {
        return false;
    };
    left.host().is_some()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

struct RemoteAuthorityField<'a> {
    value: Option<Cow<'a, str>>,
    existing: Option<Cow<'a, str>>,
    interactive: bool,
    theme: &'a ColorfulTheme,
    prompt: &'a str,
    context: &'a str,
    flag: &'a str,
    configured_name: &'a str,
}

fn collect_required_remote_authority_field(field: RemoteAuthorityField<'_>) -> Result<String> {
    let (flag, configured_name) = (field.flag, field.configured_name);
    collect_optional_remote_authority_field(field)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{flag} is required when --mode agent-remote and no existing remote {configured_name} is configured"
        )
    })
}

/// The flag value, else the existing one; interactively, a prompt prefilled
/// with the existing one. A blank answer keeps the existing value, so the field
/// is left unset only when there is none: clearing a value takes an edit of
/// `firma.toml`, never a blank input.
fn collect_optional_remote_authority_field(
    field: RemoteAuthorityField<'_>,
) -> Result<Option<String>> {
    let existing = field
        .existing
        .filter(|value| !value.trim().is_empty())
        .map(Cow::into_owned);
    let value = match field.value {
        Some(value) if value.trim().is_empty() => {
            anyhow::bail!("{} must not be empty", field.flag)
        }
        Some(value) => value.into_owned(),
        None if !field.interactive => return Ok(existing),
        None => dialoguer::Input::with_theme(field.theme)
            .with_prompt(field.prompt)
            .default(existing.clone().unwrap_or_default())
            .interact_text()
            .with_context(|| field.context.to_string())?,
    };
    Ok(if value.trim().is_empty() {
        existing
    } else {
        Some(value)
    })
}

pub(super) fn collect_remote_connect_inputs(
    args: &InitArgs,
    existing: &ExistingConfigDefaults,
    interactive: bool,
    theme: &ColorfulTheme,
) -> Result<(String, Option<String>, String)> {
    let url = collect_required_remote_authority_field(RemoteAuthorityField {
        value: args.authority_url.as_deref().map(Cow::Borrowed),
        existing: existing.authority_url.as_deref().map(Cow::Borrowed),
        interactive,
        theme,
        prompt: "Authority URL",
        context: "authority URL prompt",
        flag: "--authority-url",
        configured_name: "URL",
    })?;
    // Without a CA the Sidecar verifies the Authority against the platform's
    // trusted roots, which is enough for a publicly trusted certificate. An
    // existing CA belongs to the Authority it was configured for, so it is
    // offered again only for that same Authority; for another one, leaving the
    // CA out must mean the platform's roots.
    let same_authority = existing
        .authority_url
        .as_deref()
        .is_some_and(|old| same_authority_endpoint(old, &url));
    if let Some(previous) = &existing.authority_ca_cert
        && !same_authority
        && args.authority_ca_cert.is_none()
    {
        crate::output::warn(format!(
            "the existing CA certificate {} is not reused for {url}: it was configured for \
             another Authority; set a CA certificate if this one needs it",
            previous.display()
        ));
    }
    let existing_ca = existing
        .authority_ca_cert
        .as_ref()
        .filter(|_| same_authority);
    let ca = collect_optional_remote_authority_field(RemoteAuthorityField {
        value: args
            .authority_ca_cert
            .as_deref()
            .map(|p| p.to_string_lossy()),
        existing: existing_ca.map(|p| p.to_string_lossy()),
        interactive,
        theme,
        // A prefilled answer comes back on an empty one, so only a prompt
        // without a current CA can offer "empty" as a choice.
        prompt: if existing_ca.is_some() {
            "Path to authority CA certificate (PEM; remove ca_cert_paths from firma.toml to stop pinning it)"
        } else {
            "Path to authority CA certificate (PEM, empty for a public certificate)"
        },
        context: "authority CA cert prompt",
        flag: "--authority-ca-cert",
        configured_name: "CA certificate",
    })?;
    let pub_key = collect_required_remote_authority_field(RemoteAuthorityField {
        value: args
            .authority_pub_key
            .as_deref()
            .map(|p| p.to_string_lossy()),
        existing: existing
            .authority_pub_key
            .as_ref()
            .map(|p| p.to_string_lossy()),
        interactive,
        theme,
        prompt: "Path to authority public key",
        context: "authority public key prompt",
        flag: "--authority-pub-key",
        configured_name: "public key",
    })?;
    Ok((url, ca, pub_key))
}
