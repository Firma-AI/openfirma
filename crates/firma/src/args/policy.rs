//! Args for `firma policy`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Arguments for `firma policy`.
#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

/// Subcommands of `firma policy`.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Print all available posture and mapping templates.
    List,
    /// Parse and schema-check a Cedar policy file against the Firma schema.
    Validate {
        /// Path to the Cedar policy file (`.cedar`).
        file: PathBuf,
    },
    /// Run a policy unit-test fixture against a Cedar policy bundle.
    Test {
        /// Path to the test fixture file.
        fixture: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: PolicyArgs,
    }

    fn try_parse(argv: &[&str]) -> Result<PolicyArgs, clap::Error> {
        Wrapper::try_parse_from(argv).map(|w| w.args)
    }

    #[test]
    fn validate_subcommand_parses() {
        let args =
            try_parse(&["firma-policy", "validate", "policy.cedar"]).expect("parse validate");
        match args.command {
            PolicyCommand::Validate { file } => {
                assert_eq!(file, PathBuf::from("policy.cedar"));
            }
            PolicyCommand::Test { .. } | PolicyCommand::List => {
                panic!("expected validate subcommand")
            }
        }
    }

    #[test]
    fn test_subcommand_parses() {
        let args = try_parse(&["firma-policy", "test", "fixture.json"]).expect("parse test");
        match args.command {
            PolicyCommand::Test { fixture } => {
                assert_eq!(fixture, PathBuf::from("fixture.json"));
            }
            PolicyCommand::Validate { .. } | PolicyCommand::List => {
                panic!("expected test subcommand")
            }
        }
    }

    #[test]
    fn missing_subcommand_is_error() {
        assert!(try_parse(&["firma-policy"]).is_err());
    }
}
