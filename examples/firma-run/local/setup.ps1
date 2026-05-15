#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Ok([string]$Message) {
  Write-Host "[ok] $Message"
}

function Write-Warn([string]$Message) {
  Write-Host "[warn] $Message"
}

function Fail([string]$Message) {
  Write-Error "[fail] $Message"
  exit 1
}

$rootDir = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
$localDir = Join-Path $rootDir ".local"
$examplesDir = Join-Path $PSScriptRoot "assets"

$mappingSrc = Join-Path $examplesDir "mapping-rules.local.example.toml"
$sidecarSrcDefault = Join-Path $examplesDir "firma.local.example.toml"
$sidecarSrcObservability = Join-Path $examplesDir "firma.local.observability.example.toml"
$mappingDst = Join-Path $localDir "mapping-rules.toml"
$sidecarDst = Join-Path $localDir "firma.toml"
$auditKeyDst = Join-Path $localDir "audit-key.pem"
$setupMode = "default"

foreach ($arg in $args) {
  if ($arg -eq "--observability") {
    $setupMode = "observability"
    continue
  }

  Fail "unknown argument: $arg (supported: --observability)"
}

$sidecarSrc = if ($setupMode -eq "observability") { $sidecarSrcObservability } else { $sidecarSrcDefault }

New-Item -ItemType Directory -Path $localDir -Force | Out-Null
Write-Ok "ensured local runtime directory: $localDir"

if (-not (Test-Path -Path $mappingDst -PathType Leaf)) {
  Copy-Item -Path $mappingSrc -Destination $mappingDst
  Write-Ok "created $mappingDst from example template"
} else {
  Write-Warn "keeping existing $mappingDst"
}

if (-not (Test-Path -Path $sidecarDst -PathType Leaf)) {
  Copy-Item -Path $sidecarSrc -Destination $sidecarDst
  Write-Ok "created $sidecarDst from $setupMode example template"
} else {
  Write-Warn "keeping existing $sidecarDst"
}

if (-not (Test-Path -Path $auditKeyDst -PathType Leaf)) {
  $openssl = Get-Command openssl -ErrorAction SilentlyContinue
  if ($null -eq $openssl) {
    Fail "openssl not found; install openssl or create $auditKeyDst manually"
  }

  & $openssl.Source genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $auditKeyDst | Out-Null
  Write-Ok "generated audit signing key at $auditKeyDst"
} else {
  Write-Warn "keeping existing $auditKeyDst"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "1) Start sidecar:"
Write-Host "   cargo run -p firma -- sidecar -c .local/firma.toml"
Write-Host ""
Write-Host "2) In a new terminal, run Codex through the wrapper:"
Write-Host "   cargo run -p firma -- run --profile codex -- codex"
Write-Host ""
Write-Host "3) Optional structural E2E smoke (Linux-only):"
Write-Host "   examples/firma-run/e2e/run.sh"
