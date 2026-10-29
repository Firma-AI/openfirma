use firma_config_utils::http::{
    HttpOrHttps, HttpOrigin, HttpUrl, HttpUrlError, Https, HttpsOrLoopbackHttp, ParseHttpUrlError,
    SchemePolicy, host_is_this_machine,
};

fn origin<P: SchemePolicy>(value: &str) -> Result<HttpOrigin<P>, ParseHttpUrlError> {
    value.parse()
}

fn http_url<P: SchemePolicy>(value: &str) -> Result<HttpUrl<P>, ParseHttpUrlError> {
    value.parse()
}

#[test]
fn origin_serializes_equivalent_spellings_canonically() {
    for (input, display, url) in [
        (
            "https://Firma.Example:443/",
            "https://firma.example",
            "https://firma.example/",
        ),
        (
            "https://firma.example:8443",
            "https://firma.example:8443",
            "https://firma.example:8443/",
        ),
    ] {
        let origin = origin::<Https>(input).expect("origin is valid");

        assert_eq!(origin.to_string(), display, "{input}");
        assert_eq!(origin.as_url().as_str(), url, "{input}");
    }
}

#[test]
fn origin_rejects_every_path_except_root() {
    for input in ["https://firma.example/login", "https://firma.example//"] {
        assert_eq!(
            origin::<Https>(input),
            Err(HttpUrlError::Path.into()),
            "{input}"
        );
    }
}

#[test]
fn both_shapes_reject_partial_or_empty_components_in_a_fixed_order() {
    for (input, expected) in [
        ("file:///etc/firma", HttpUrlError::MissingHost),
        ("https://:secret@firma.example/", HttpUrlError::Credentials),
        (
            "ftp://operator@firma.example/login?tenant=example#section",
            HttpUrlError::Credentials,
        ),
        ("https://firma.example/?", HttpUrlError::Query),
        (
            "https://firma.example/?tenant=example#",
            HttpUrlError::Query,
        ),
        ("https://firma.example/#", HttpUrlError::Fragment),
    ] {
        assert_eq!(
            origin::<HttpOrHttps>(input),
            Err(expected.into()),
            "{input}"
        );
        assert_eq!(
            http_url::<HttpOrHttps>(input),
            Err(expected.into()),
            "{input}"
        );
    }
}

#[test]
fn scheme_policies_decide_http_by_host() {
    use HttpUrlError::{HttpRequiresLoopback, RequiresHttps, UnsupportedScheme};

    for (input, https, loopback) in [
        ("https://firma.example/", Ok(()), Ok(())),
        (
            "http://firma.example/",
            Err(RequiresHttps),
            Err(HttpRequiresLoopback),
        ),
        ("http://127.0.0.2:3000/", Err(RequiresHttps), Ok(())),
        ("http://[::1]:3000/", Err(RequiresHttps), Ok(())),
        ("http://LOCALHOST:3000/", Err(RequiresHttps), Ok(())),
        (
            "http://localhost.firma.example/",
            Err(RequiresHttps),
            Err(HttpRequiresLoopback),
        ),
        (
            "http://[::ffff:127.0.0.1]/",
            Err(RequiresHttps),
            Err(HttpRequiresLoopback),
        ),
        (
            "ftp://firma.example/",
            Err(UnsupportedScheme),
            Err(UnsupportedScheme),
        ),
    ] {
        assert_eq!(
            origin::<Https>(input).map(drop),
            https.map_err(Into::into),
            "{input}"
        );
        assert_eq!(
            origin::<HttpsOrLoopbackHttp>(input).map(drop),
            loopback.map_err(Into::into),
            "{input}"
        );
        let any = if input.starts_with("ftp:") {
            Err(UnsupportedScheme)
        } else {
            Ok(())
        };
        assert_eq!(
            origin::<HttpOrHttps>(input).map(drop),
            any.map_err(Into::into),
            "{input}"
        );
    }
}

#[test]
fn url_keeps_its_path_as_written_and_joins_beneath_it() {
    for (input, joined) in [
        ("https://firma.example", "https://firma.example/approvals/1"),
        (
            "https://firma.example/team",
            "https://firma.example/team/approvals/1",
        ),
        (
            "https://firma.example/team/",
            "https://firma.example/team/approvals/1",
        ),
    ] {
        let url = http_url::<Https>(input).expect("URL is valid");
        let written = url::Url::parse(input).expect("test URL parses");

        assert_eq!(url.as_url(), &written, "{input}");
        assert_eq!(url.to_string(), written.as_str(), "{input}");
        assert_eq!(url.join_path("approvals/1").as_str(), joined, "{input}");
    }
}

#[test]
fn deserialization_applies_the_declared_policy() {
    let loopback: HttpOrigin<HttpsOrLoopbackHttp> =
        serde_json::from_str(r#""http://127.0.0.1:3000/""#).expect("loopback HTTP is allowed");
    let https = serde_json::from_str::<HttpOrigin<Https>>(r#""http://127.0.0.1:3000/""#)
        .expect_err("HTTPS is required");
    let malformed = serde_json::from_str::<HttpUrl<Https>>(r#""firma.example""#)
        .expect_err("a relative URL is malformed");

    assert_eq!(
        serde_json::to_string(&loopback).expect("origin serializes"),
        r#""http://127.0.0.1:3000""#
    );
    insta::assert_snapshot!(https, @"URL must use HTTPS");
    insta::assert_snapshot!(malformed, @"URL is malformed: relative URL without a base");
}

#[test]
fn a_host_is_this_machine_when_it_is_localhost_or_a_loopback_address() {
    for (host, this_machine) in [
        ("localhost", true),
        ("LOCALHOST.", true),
        ("127.0.0.1", true),
        ("[::1]", true),
        ("[::ffff:127.0.0.1]", true),
        ("localhost.firma.example", false),
        ("10.0.0.7", false),
        ("control.firma.ai.", false),
        ("[::ffff:10.0.0.7]", false),
    ] {
        assert_eq!(host_is_this_machine(host), this_machine, "{host}");
    }
}
