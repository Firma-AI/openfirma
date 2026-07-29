use std::str::FromStr;

use http::{
    Uri,
    uri::{Authority, InvalidUri},
};

use super::MatcherError;

/// Extract the host (and port, if non-standard) from a URL string.
///
/// Strips the scheme prefix and any path/query/fragment suffix. Intended for
/// converting vault-stored URLs like `https://github.com` into the bare hostname
/// `github.com` that matches HTTP `Host` headers.
pub(super) fn parse_authority(url: &str) -> Result<Authority, MatcherError> {
    if let Ok(authority) = Authority::from_str(url) {
        return remove_credentials(&authority).map_err(|error| MatcherError::InvalidUri {
            uri: redact_input_for_error(url),
            error,
        });
    }

    let uri = Uri::from_str(url).map_err(|error| MatcherError::InvalidUri {
        uri: redact_input_for_error(url),
        error,
    })?;
    let authority = uri
        .authority()
        .ok_or_else(|| MatcherError::NoHostInUri(redact_input_for_error(url)))?;
    remove_credentials(authority).map_err(|error| MatcherError::InvalidUri {
        uri: redact_input_for_error(url),
        error,
    })
}

/// Strips credentials from an authority.
#[inline]
fn remove_credentials(authority: &Authority) -> Result<Authority, InvalidUri> {
    authority.as_str().split_once('@').map_or_else(
        || Ok(authority.clone()),
        |(_credentials, domain)| Authority::from_str(domain),
    )
}

/// Strips parameters and credentials from a URL to avoid leaking secrets.
fn redact_input_for_error(url: &str) -> String {
    let url = url.split_once('?').map_or(url, |(base, _params)| base);
    let Some((credentials, domain)) = url.split_once('@') else {
        return url.to_owned();
    };
    format!(
        "{}{domain}",
        credentials
            .find("://")
            .map_or("", |pos| &credentials[0..pos + 3])
    )
}
