//! Runner for `firma __proxy-bridge`.

use std::process::ExitCode;

use firma_run::proxy_bridge::{ProxyBridgeInput, execute_proxy_bridge};

use crate::args::run::ProxyBridgeArgs;

/// Run the hidden proxy-bridge helper.
///
/// # Errors
///
/// Returns an error if the bridge fails to bind or terminates abnormally.
pub fn run(args: ProxyBridgeArgs) -> anyhow::Result<ExitCode> {
    let input = ProxyBridgeInput {
        listen: args.listen,
        upstream_uds: args.upstream_uds,
    };
    match execute_proxy_bridge(&input) {
        Ok(code) => Ok(exit_code(code)),
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

fn exit_code(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        let exit = u8::try_from(code).unwrap_or(1);
        ExitCode::from(exit)
    }
}
