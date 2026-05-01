#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($args.Count -lt 1) {
  Write-Host "usage: scripts/firma-run-local.ps1 -- <command> [args...]"
  exit 1
}

$commandArgs = @($args)
if ($commandArgs[0] -eq "--") {
  if ($commandArgs.Count -eq 1) {
    Write-Host "usage: scripts/firma-run-local.ps1 -- <command> [args...]"
    exit 1
  }
  $commandArgs = $commandArgs[1..($commandArgs.Count - 1)]
}

& cargo run -p firma-run -- run -- @commandArgs
exit $LASTEXITCODE
