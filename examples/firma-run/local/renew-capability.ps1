#!/usr/bin/env pwsh
# Issues canonical CapabilitySeed TOML for `firma run --capability-file`.
# Run exports only the seed's raw token and path; a locally autostarted Sidecar
# loads and watches the same file.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [string]$AuthorityConfig = ".local/firma.toml",
  [string]$AgentId = "agt_01j0000000e008000000000001",
  [string]$SessionId = "",
  [string]$Action = "communication.external.send",
  [string]$ResourceScope = "*",
  [int]$TtlSeconds = 3600,
  [string]$Output = ""
)

function Write-Ok([string]$Message) { Write-Host "[ok] $Message" }
function Fail([string]$Message) { throw "[fail] $Message" }

if (-not $SessionId) {
  if ($env:FIRMA_RUN_SESSION_ID) {
    $SessionId = $env:FIRMA_RUN_SESSION_ID
  } else {
    $SessionId = "demo-session"
  }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  Fail "cargo is required"
}
if (-not $SessionId) {
  Fail "session id must not be empty"
}
if (-not $Output) {
  Fail "--output is required (example: --output .local/capability-codex.toml)"
}

Write-Ok "issuing capability token (agent=$AgentId session=$SessionId ttl=${TtlSeconds}s)"
cargo run -p firma -- authority --config $AuthorityConfig issue `
  --agent-id $AgentId `
  --session-id $SessionId `
  --action $Action `
  --resource-scope $ResourceScope `
  --ttl-seconds $TtlSeconds `
  --output $Output

Write-Ok "capability written: $Output"
Write-Ok "pass this canonical seed with firma run --capability-file"
