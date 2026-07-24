//! Placeholder token minting: substitutes `{name}`/`{item}` markers in a
//! `placeholder_template` with percent-encoded values.
//!
//! Shared by firma-run's CLI intercept (which also owns the canonical
//! `Placeholder` dictionary-key type and the persistent `SecretStore`) and
//! firma-sidecar's HTTP MITM intercept (which mints locally so its
//! single-pass extraction can substitute the placeholder synchronously, then
//! pushes the pre-minted placeholder + value to firma-run's broker for
//! storage — see `secret_gateway_client::push_secret`).

const NAME_MARKER: &str = "{name}";
const ITEM_MARKER: &str = "{item}";

/// Mint a placeholder token from a `@placeholder`-style template.
///
/// `{name}` is always replaced with the percent-encoded `name`. `{item}` is
/// replaced with the percent-encoded `item` when `Some`; left unchanged when
/// the template contains it but `item` is `None`.
#[must_use]
pub fn mint_placeholder(template: &str, item: Option<&str>, name: &str) -> String {
    let mut encoded_name = String::new();
    encode_segment(name, &mut encoded_name);
    let after_name = template.replace(NAME_MARKER, &encoded_name);
    match item {
        Some(item) => {
            let mut encoded_item = String::new();
            encode_segment(item, &mut encoded_item);
            after_name.replace(ITEM_MARKER, &encoded_item)
        }
        None => after_name,
    }
}

/// Percent-encode `input` down to the unreserved set (`[A-Za-z0-9._-]`);
/// every other byte becomes `%XX`.
fn encode_segment(input: &str, out: &mut String) {
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0f));
        }
    }
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_name_marker_with_percent_encoding() {
        let placeholder = mint_placeholder("firma-secret://aws/{name}", None, "db pass");
        assert_eq!(placeholder, "firma-secret://aws/db%20pass");
    }

    #[test]
    fn substitutes_item_marker_when_present() {
        let placeholder = mint_placeholder(
            "firma-secret://1password/{item}/{name}",
            Some("GitHub"),
            "token",
        );
        assert_eq!(placeholder, "firma-secret://1password/GitHub/token");
    }

    #[test]
    fn leaves_item_marker_unchanged_when_item_absent() {
        let placeholder = mint_placeholder("firma-secret://1password/{item}/{name}", None, "token");
        assert_eq!(placeholder, "firma-secret://1password/{item}/token");
    }
}
