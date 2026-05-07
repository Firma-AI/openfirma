#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [string]$AuthorityConfig = ".local/authority.toml",
  [string]$AgentId = "example-agent",
  [string]$SessionId = "",
  [string]$Action = "communication.external.send",
  [string]$ResourceScope = "*",
  [int]$TtlSeconds = 3600,
  [string]$Output = ""
)

function Write-Ok([string]$Message) { Write-Host "[ok] $Message" }
function Write-Warn([string]$Message) { Write-Host "[warn] $Message" }
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
cargo run -p firma-authority -- --config $AuthorityConfig issue `
  --agent-id $AgentId `
  --session-id $SessionId `
  --action $Action `
  --resource-scope $ResourceScope `
  --ttl-seconds $TtlSeconds `
  --output $Output

Write-Ok "capability written: $Output"
Write-Warn "if sidecar uses capability_seed, restart sidecar to reload the renewed token"
