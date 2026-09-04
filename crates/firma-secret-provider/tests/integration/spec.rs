use firma_config_schema::secret_provider::SecretProviderConfig;
use firma_core::{SecretMatcher, SecretNameSource};
use firma_secret_provider::{
    IntegrationConfigError, IntegrationSpec, MatchingResolution,
    broker::BinaryNameError,
    spec::cli::{CliIntegrationConfigError, CliIntegrationSpec},
};

fn cli_spec(
    binary_name: &str,
) -> Result<CliIntegrationSpec<SecretMatcher>, CliIntegrationConfigError> {
    CliIntegrationSpec::new(
        String::from(binary_name),
        String::from("example"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

#[test]
fn cli_config_deserializes_and_validates() {
    let input = r#"
type = "cli"
binary_name = "bws"
provider_id = "bitwarden"
credential_env_vars = ["BWS_ACCESS_TOKEN"]
stripped_options = [{ name = "--output", takes_value = true }]

[[matchers]]
type = "sensitive_command"
argv = ["secret", "get"]
match = "prefix"

[matchers.matcher]
type = "json"
record_path = "$"
value_path = "$.value"

[matchers.matcher.name]
source = "path"
path = "$.key"
"#;

    let config: SecretProviderConfig =
        toml::from_str(input).unwrap_or_else(|error| panic!("valid CLI config TOML: {error}"));
    let spec = IntegrationSpec::try_from(config)
        .unwrap_or_else(|error| panic!("valid CLI integration: {error}"));
    assert_eq!(spec.provider_id(), "bitwarden");
    let cli = spec.as_cli().expect("cli spec");
    assert_eq!(cli.binary_name(), "bws");
    assert!(spec.as_http().is_none());
    assert_eq!(
        cli.resolve_args(&["secret", "get", "abc"].map(String::from)),
        MatchingResolution::Matcher(&SecretMatcher::Json {
            record_path: String::from("$"),
            value_path: String::from("$.value"),
            name: SecretNameSource::Path {
                path: String::from("$.key")
            },
            item_selector: None,
            domain_selector: None,
        })
    );
}

#[test]
fn http_config_deserializes_without_validation_boundary() {
    let input = r#"
type = "http"
provider_id = "aws-secrets-manager"
host = "secretsmanager.*.amazonaws.com"

[[matchers]]
type = "sensitive_command"
path = "/get"

[matchers.matcher]
type = "regex"
pattern = "(?P<name>.+)=(?P<value>.+)"
"#;

    let config: SecretProviderConfig =
        toml::from_str(input).unwrap_or_else(|error| panic!("valid HTTP config TOML: {error}"));
    let spec = IntegrationSpec::try_from(config)
        .unwrap_or_else(|error| panic!("valid HTTP integration: {error}"));
    assert_eq!(spec.provider_id(), "aws-secrets-manager");
    let http = spec.as_http().expect("http spec");
    assert_eq!(http.host, "secretsmanager.*.amazonaws.com");
    assert!(spec.as_cli().is_none());
}

#[test]
fn try_from_propagates_cli_validation_errors() {
    let config: SecretProviderConfig = toml::from_str(
        r#"
type = "cli"
binary_name = "example"
provider_id = "example"
credential_env_vars = []
stripped_options = [{ name = "", takes_value = true }]
matchers = []
"#,
    )
    .unwrap_or_else(|error| panic!("plain config: {error}"));

    let Err(error) = IntegrationSpec::try_from(config) else {
        panic!("empty option name must fail validation");
    };
    std::assert_matches!(
        &error,
        IntegrationConfigError::Cli(
            firma_secret_provider::spec::cli::CliIntegrationConfigError::EmptyOptionName
        )
    );
    insta::assert_snapshot!(error.to_string(), @"option name must not be empty");
}

#[test]
fn cli_config_rejects_reserved_broker_readiness_binary() {
    let config: SecretProviderConfig = toml::from_str(
        r#"
type = "cli"
binary_name = "__firma_broker_readiness_probe__"
provider_id = "example"
credential_env_vars = []
matchers = []
"#,
    )
    .unwrap_or_else(|error| panic!("plain config: {error}"));

    let Err(error) = IntegrationSpec::try_from(config) else {
        panic!("reserved broker readiness binary must fail validation");
    };
    std::assert_matches!(
        &error,
        IntegrationConfigError::Cli(CliIntegrationConfigError::ReservedBinaryName { name })
            if name == "__firma_broker_readiness_probe__"
    );
    insta::assert_snapshot!(error.to_string(), @"CLI binary name `__firma_broker_readiness_probe__` is reserved for internal broker readiness checks");
}

#[test]
fn cli_spec_rejects_empty_binary_name() {
    let Err(error) = cli_spec("") else {
        panic!("empty binary name must fail validation");
    };
    std::assert_matches!(
        &error,
        CliIntegrationConfigError::InvalidBinaryName {
            source: BinaryNameError::Empty
        }
    );
    insta::assert_snapshot!(error.to_string(), @"invalid CLI binary name: binary name must not be empty");
}

#[test]
fn cli_spec_rejects_non_basename_binary_names() {
    let binary_names = [".", "..", "dir/bws", r"dir\bws", "C:bws", "bws\0shim"];

    for binary_name in binary_names {
        let Err(error) = cli_spec(binary_name) else {
            panic!("non-basename binary name must fail validation: {binary_name:?}");
        };
        assert_eq!(
            error,
            CliIntegrationConfigError::InvalidBinaryName {
                source: BinaryNameError::NotBasename(String::from(binary_name)),
            },
            "unexpected error for {binary_name:?}"
        );
    }
}
