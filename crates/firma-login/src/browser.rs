use std::io::Write;

use url::Url;

/// Environment variable that stops the login flow from launching a browser
/// when it holds an enabling value. The authorization URL is still printed.
///
/// An empty value, `0`, or `false` (any case) leaves the browser launch on.
const NO_BROWSER_ENV: &str = "FIRMA_LOGIN_NO_BROWSER";

/// Prints the authorization URL and tries to open it in the default browser.
///
/// The browser launch is skipped when [`NO_BROWSER_ENV`] holds an enabling
/// value.
#[expect(clippy::missing_errors_doc, reason = "self-explanatory I/O result")]
pub fn print_and_open(authorization_url: &Url, output: &mut impl Write) -> std::io::Result<()> {
    writeln!(output, "{authorization_url}")?;
    output.flush()?;
    if !browser_disabled(std::env::var_os(NO_BROWSER_ENV).as_deref()) {
        let _ = webbrowser::open(authorization_url.as_str());
    }

    Ok(())
}

/// Whether the variable's value asks to skip the browser launch.
fn browser_disabled(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| {
        let value = value.to_string_lossy();
        let value = value.trim();
        !(value.is_empty() || value == "0" || value.eq_ignore_ascii_case("false"))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::browser_disabled;

    #[test]
    fn only_an_enabling_value_disables_the_browser() {
        for (value, expected) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("False"), false),
            (Some("1"), true),
            (Some("true"), true),
        ] {
            assert_eq!(
                browser_disabled(value.map(OsStr::new)),
                expected,
                "{value:?}"
            );
        }
    }
}
