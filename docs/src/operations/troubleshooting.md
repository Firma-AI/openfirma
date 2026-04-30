# Troubleshooting

Sections:
[Sidecar exits at startup](#sidecar-exits-at-startup) |
[All requests denied](#all-requests-denied) |
[firma-run can't reach the sidecar](#firma-run-cant-reach-the-sidecar) |
[HTTPS calls fail with cert errors inside sandbox](#https-calls-fail-with-cert-errors-inside-sandbox) |
[Performance regressions](#performance-regressions)

## Sidecar exits at startup

### Bind address in use

**Cause:** Another process is already listening on `interceptor.listen_addr`.

**Symptom:** `ERROR address already in use` in the startup log.

**Fix:** Change `listen_addr` in the Sidecar config, or identify and stop the
conflicting process with `lsof -i :<port>` (macOS/Linux) or
`netstat -ano | findstr :<port>` (Windows).

### Mapping rules duplicate tuple

**Cause:** Two mapping files define the same `(method, host, path)` tuple.

**Symptom:** `ERROR duplicate mapping rule` at startup.

**Fix:** Remove the duplicate entry from the secondary mapping file, or split
the rules into non-overlapping files so each `(method, host, path)` combination
appears in exactly one file.

### Authority unreachable at boot

**Cause:** `firma-authority` is not running or `authority_addr` in the Sidecar
config points at the wrong address or port.

**Symptom:** `ERROR failed to connect to authority` or a similar gRPC connection
error during the Sidecar pre-flight phase.

**Fix:** Start the Authority before the Sidecar. Verify that `authority_addr`
matches the `listen_addr` configured in `firma-authority`'s config file.

## All requests denied

### No capability for action\_class

**Cause:** The `CapabilityMap` holds no token whose action set covers the
requested `action_class`.

**Symptom:** Stage 1 returns `Deny(NoCapability)` for the affected action class.

**Fix:** Issue a capability token that includes the required `action_class` in
its action set, and ensure the token is loaded into the `CapabilityMap` before
the agent makes requests.

### Bundle stale

**Cause:** The Authority is unreachable and the policy bundle TTL configured in
`bundle_ttl_seconds` has expired.

**Symptom:** Stage 2 returns `Deny(BundleStale)` for all requests.

**Fix:** Restore connectivity to the Authority. If the Authority is permanently
unavailable, reduce `bundle_ttl_seconds` to match the acceptable staleness
window, or investigate the network partition.

### Cedar policy parse failure

**Cause:** A Cedar policy file in `policy_dir` contains a syntax error.

**Symptom:** Startup error: `ERROR failed to load policy bundle`.

**Fix:** Validate the `.cedar` files with the Cedar CLI:

```bash
cedar validate --schema <schema-file> --policies <policy-dir>
```

Fix any reported syntax or schema violations, then restart the Authority so it
can reload the corrected bundle.

## firma-run can't reach the sidecar

### UDS path mismatch

**Cause:** `firma-run` and `firma-sidecar` are configured with different Unix
domain socket paths (or TCP addresses).

**Symptom:** `ERROR failed to connect to sidecar` in the `firma-run` startup
log.

**Fix:** Ensure both the Sidecar and `firma-run` are configured with the same
UDS path (or TCP address and port). Check both config files for
`interceptor.listen_addr` and the corresponding `sidecar_addr` in the
`firma-run` config.

### Sidecar boot order

**Cause:** The `firma-run` sandbox is launched before the Sidecar has finished
binding its listen address.

**Symptom:** The agent process fails immediately with a connection error before
executing any outbound call.

**Fix:** `firma-run` performs a pre-flight reachability check against the
Sidecar before launching the agent. If the Sidecar is not ready, `firma-run`
refuses to launch. Start the Sidecar first and wait for its startup log to
confirm it is listening before invoking `firma-run`.

## HTTPS calls fail with cert errors inside sandbox

### Root CA not mounted

**Cause:** The Sidecar's MITM CA certificate is not trusted by the TLS client
runtime inside the sandbox.

**Symptom:** TLS handshake error: `certificate signed by unknown authority` or
equivalent in the client library's error output.

**Fix:** Inject the Sidecar CA certificate into the client trust store:

- Python: set `REQUESTS_CA_BUNDLE` to the CA cert path.
- Node.js: set `NODE_EXTRA_CA_CERTS` to the CA cert path.
- curl: pass `--cacert <path>` on the command line.

### intercept\_hosts mismatch

**Cause:** The target host is not listed in `intercept_hosts`, so the Sidecar
passes the CONNECT tunnel through without performing MITM inspection.

**Symptom:** The request succeeds but the audit log shows only CONNECT-level
enforcement with no `action_class` classification.

**Fix:** Add the target hostname to `[interceptor.https_mitm.intercept_hosts]`
in the Sidecar config, then restart the Sidecar.

### Pinned client

**Cause:** The HTTP client inside the sandbox uses certificate pinning and
rejects the Sidecar's dynamically issued MITM certificate.

**Symptom:** TLS error originating from the client library itself, not from the
CA chain validation (the CA may be trusted, but the leaf certificate hash does
not match the pin).

**Fix:** Add the host to `bypass_hosts` to allow the CONNECT tunnel to pass
uninspected, or set `strict_hosts` to explicitly deny requests from pinned
clients that cannot be inspected.

## Performance regressions

To bisect a performance regression:

1. Run `cargo bench -p firma-sidecar` on the current commit and the last known
   good commit.
2. Use `--save-baseline before` on the good commit and `--save-baseline after`
   on the regressed commit.
3. Compare the two baselines with `critcmp before after` to identify which
   benchmarks regressed and by how much.
4. Cross-reference results against the budget thresholds in
   [Performance Targets](../architecture/performance.md).
