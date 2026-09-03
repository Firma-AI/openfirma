//! `firma doctor` command-line arguments.

use std::path::PathBuf;

use clap::Args as ClapArgs;

/// Parsed `firma doctor` arguments.
///
/// The unified `firma.toml` is selected by the global `--config` / `FIRMA_CONFIG`.
///
/// `--state-dir` overrides the resolved state directory.
///
/// `--json` switches output to a single JSON object (one field per check).
///
/// `--timeout` caps every reachability probe (TCP / UDS connect). The default
/// is 500 ms — small because `doctor` is supposed to feel snappy and we
/// already report unreachable as a structured `FAIL`, not a hang.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Override the runtime state directory inspected for pid files, sockets,
    /// and component logs.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Emit a single JSON object (one field per check) instead of the
    /// pretty-printed report. Useful for scripting and CI assertions.
    #[arg(long)]
    pub json: bool,
    /// Per-probe network timeout in milliseconds (TCP / UDS connect). Kept
    /// small so unreachable endpoints fail fast as a structured `FAIL`
    /// instead of hanging the report.
    #[arg(long, default_value_t = 500)]
    pub timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: Args,
    }

    fn try_parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Wrapper::try_parse_from(argv).map(|w| w.args)
    }

    #[test]
    fn defaults_parse() {
        let args = try_parse(&["firma-doctor"]).expect("parse default");
        assert!(args.state_dir.is_none());
        assert!(!args.json);
        assert_eq!(args.timeout_ms, 500);
    }

    #[test]
    fn json_flag_parses() {
        let args = try_parse(&["firma-doctor", "--json"]).expect("parse json");
        assert!(args.json);
    }

    #[test]
    fn timeout_flag_overrides_default() {
        let args = try_parse(&["firma-doctor", "--timeout-ms", "1500"]).expect("parse timeout");
        assert_eq!(args.timeout_ms, 1500);
    }
}
