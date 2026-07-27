use firma_core::SecretMatcher;
use firma_secret_provider::{CliIntegrationSpec, CompiledMatcher, IntegrationRegistry};

#[test]
fn builtins_cover_all_four_managers() {
    let registry = IntegrationRegistry::with_builtins();
    for name in ["bws", "op", "vault", "doppler"] {
        assert!(
            registry.get(name).is_some(),
            "missing built-in spec for {name}"
        );
    }
}

#[test]
fn unknown_binary_returns_none() {
    let registry = IntegrationRegistry::with_builtins();
    assert!(registry.get("unknown-tool").is_none());
}

#[test]
fn bws_spec_has_expected_credential_env_and_placeholder() {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.get("bws").expect("bws spec");
    assert!(
        spec.credential_env_vars
            .iter()
            .any(|v| v == "BWS_ACCESS_TOKEN")
    );
    assert!(spec.provider_id.eq("bitwarden"));
}

#[test]
fn op_output_is_correctly_parsed_by_builtin_config() {
    #[derive(Debug, PartialEq, Eq)]
    struct Entry {
        name: String,
        value: String,
        domain: Option<String>,
        item: Option<String>,
    }

    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.get("op").expect("op spec");
    let matcher = CompiledMatcher::compile(&spec.matcher).expect("spec compiles");
    let secret = String::from("ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ12"); // trufflehog:ignore
    let op_output = format!(
        r#"{{
      "id": "abcd1234efgh5678ijkl9012mnop3456",
      "title": "GitHub",
      "vault": {{
        "id": "qrstuv1234567890wxyz",
        "name": "Employee"
      }},
      "category": "LOGIN",
      "urls": [
        {{
          "primary": true,
          "href": "https://github.com/login"
        }}
      ],
      "fields": [
        {{
          "id": "username",
          "type": "STRING",
          "label": "username",
          "value": "user.name"
        }},
        {{
          "id": "password",
          "type": "CONCEALED",
          "label": "token",
          "value": "{secret}"
        }}
      ]
    }}"#
    );
    let mut entries = Vec::new();
    let out = matcher
        .rewrite(op_output.as_bytes(), &mut |name, value, domain, item| {
            entries.push(Entry {
                name: name.to_owned(),
                value: value.expose().to_owned(),
                domain: domain.map(|authority| authority.as_str().to_owned()),
                item: item.map(ToOwned::to_owned),
            });
            String::from("<placeholder>")
        })
        .expect("rewrite successful");
    assert!(
        String::from_utf8(out)
            .expect("valid utf8")
            .contains("<placeholder>")
    );
    assert!(entries.len() == 1);
    let entry = entries.pop().expect("entry");
    assert_eq!(
        entry,
        Entry {
            name: String::from("token"),
            value: secret,
            domain: Some(String::from("github.com")),
            item: Some(String::from("GitHub"))
        }
    );
}

#[test]
fn push_custom_spec_takes_precedence_over_builtin() {
    let mut registry = IntegrationRegistry::with_builtins();
    registry.push(CliIntegrationSpec {
        binary_name: String::from("bws"),
        provider_id: String::from("custom"),
        credential_env_vars: vec![],
        matcher: SecretMatcher::Json {
            record_path: String::from("$[*]"),
            value_path: String::from("$.value"),
            name_path: String::from("$.key"),
            item_selector: None,
            domain_selector: None,
        },
        strip_arg_flags: vec![],
        forced_args: vec![],
    });
    let spec = registry.get("bws").expect("bws spec after push");
    assert!(spec.provider_id.eq("custom"));
}
