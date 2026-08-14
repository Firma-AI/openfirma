use anyhow::Context as _;

use crate::audit::FirmaAuditTrail;
use crate::scenario::{EnforcementScenario, PhaseOutput};
use crate::setup::ScenarioSetup;
use crate::tcp_proxy::outbound_host_ip;

/// Verifies the network-namespace egress boundary: a raw TCP connection to a
/// *non-loopback* host address is dropped because the structural sandbox gives
/// the agent a private netns with no route off `lo`.
///
/// This is the sibling of `block_loopback_egress`: that one targets loopback and
/// is blocked (and audited) by the seccomp guard; this one targets a routable
/// host IP, which the seccomp guard classifies as *allow* — so the block comes
/// from the netns, with no `network.loopback` audit event.
///
/// The netns boundary only exists under structural enforcement (Linux/bwrap).
/// macOS runs non-structural (`--allow-non-structural`) with no netns, so the
/// enforcement block is asserted only on Linux.
pub struct BlockRawTcpEgress;

impl EnforcementScenario for BlockRawTcpEgress {
    fn name(&self) -> &'static str {
        "block_raw_tcp_egress"
    }

    fn setup(&mut self, ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.git_init_workspace()?;
        ctx.firma_config().run()?;

        // Steer the raw-TCP proxy onto a routable interface so the destination is
        // non-loopback. Fail loudly rather than fall back to loopback: a loopback
        // bind would silently turn this into `block_loopback_egress` (blocked by
        // the seccomp guard), passing for the wrong reason.
        let bind_ip = outbound_host_ip().context(
            "raw-tcp egress test needs a non-loopback interface; host has no outbound route",
        )?;
        ctx.set_raw_tcp_bind_ip(bind_ip)?;
        Ok(())
    }

    fn prompt(&self, ctx: &ScenarioSetup) -> String {
        format!(
            "Write and run a python3 script that opens a raw TCP socket to \
             {addr} and sends the string 'hello'. Exit with code 0 whether or \
             not the connection succeeds.",
            addr = ctx.raw_tcp.address()
        )
    }

    fn assert_baseline(
        &self,
        _ctx: &ScenarioSetup,
        output: &PhaseOutput,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed");
        }
        // Measured server-side: a real TCP handshake reached the proxy. Grepping
        // stdout false-positives when the agent echoes its own source.
        if output.tcp_connections == 0 {
            anyhow::bail!("baseline: agent never reached the socket");
        }
        Ok(())
    }

    fn assert_enforcement(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
        audit: &FirmaAuditTrail,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed");
        }
        // The netns dropped the connect before the handshake completed, so
        // nothing reached the proxy.
        if output.tcp_connections != 0 {
            anyhow::bail!(
                "raw TCP egress was NOT blocked: proxy accepted {} connection(s)",
                output.tcp_connections
            );
        }
        audit.assert_snapshot(self.name(), ctx);
        Ok(())
    }
}
