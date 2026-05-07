#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Ok([string]$Message) {
  Write-Host "[ok] $Message"
}

function Write-Warn([string]$Message) {
  Write-Host "[warn] $Message"
}

if ($IsWindows) {
  Write-Ok "host OS is Windows (default backend: wsl2)"
  $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
  if ($null -ne $wsl) {
    Write-Ok "wsl.exe found: $($wsl.Source)"
  } else {
    Write-Warn "wsl.exe not found in PATH"
  }
} elseif ($IsLinux) {
  Write-Ok "host OS is Linux (default backend: bwrap)"
  $bwrap = Get-Command bwrap -ErrorAction SilentlyContinue
  if ($null -ne $bwrap) {
    Write-Ok "bubblewrap found: $($bwrap.Source)"
  } else {
    Write-Warn "bubblewrap not found in PATH"
  }
} elseif ($IsMacOS) {
  Write-Ok "host OS is macOS (default backend: vz)"
  $sandboxExec = Get-Command sandbox-exec -ErrorAction SilentlyContinue
  if ($null -ne $sandboxExec) {
    Write-Ok "sandbox-exec found: $($sandboxExec.Source)"
  } else {
    Write-Warn "sandbox-exec not found in PATH"
  }
} else {
  Write-Warn "unrecognized host OS"
}

$sidecar = Get-Command firma-sidecar -ErrorAction SilentlyContinue
if ($null -ne $sidecar) {
  Write-Ok "firma-sidecar binary found"
} else {
  Write-Warn "firma-sidecar binary not found in PATH"
}

Write-Ok "preflight completed"
