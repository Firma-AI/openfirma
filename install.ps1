<#
.SYNOPSIS
    Install the firma CLI on Windows.

.DESCRIPTION
    Usage:
        iwr -useb https://<host>/install.ps1 | iex
        iwr -useb https://<host>/install.ps1 | iex -- -NoInit
        .\install.ps1 -Version v0.7.0 -InstallDir 'C:\Tools\firma'
#>
#Requires -Version 5
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost', '',
    Justification = 'Installer chrome is user-facing; redirecting Write-Output would interleave with download progress and break piped invocations.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSReviewUnusedParameter', 'Version',
    Justification = 'Read inside helper functions via $script:Version after parameter binding.'
)]
param(
    [string]$Version       = $env:FIRMA_VERSION,
    [string]$InstallDir    = $env:FIRMA_INSTALL_DIR,
    [switch]$NoModifyPath,
    [switch]$NoInit,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$QuickstartUrl = 'https://firma-ai.github.io/openfirma/quickstart/'
$GitHubRepo    = 'Firma-AI/openfirma'

function Write-Info ($msg) { Write-Host "[firma-installer] $msg" }
function Write-Warn ($msg) { Write-Warning "[firma-installer] $msg" }
function Stop-Install {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Terminal error helper; ShouldProcess semantics do not apply.'
    )]
    param([string]$msg)
    Write-Host "[firma-installer] error: $msg" -ForegroundColor Red
    exit 1
}

function Show-Usage {
@'
Install the firma CLI on Windows.

Usage: install.ps1 [options]

Options:
  -Version <v>          Install a specific release tag (e.g. v0.7.0).
                        Default: latest. Env: FIRMA_VERSION.
  -InstallDir <path>    Install location.
                        Default: %LOCALAPPDATA%\Programs\firma\bin.
                        Env: FIRMA_INSTALL_DIR.
  -NoModifyPath         Do not edit the User PATH.
  -NoInit               Do not prompt to run 'firma stack init'.
  -Force                Overwrite an existing install without prompting.
  -DryRun               Print planned actions only.
  -Help                 Show this message.

Quickstart: https://firma-ai.github.io/openfirma/quickstart/
'@ | Write-Host
}

if ($Help) { Show-Usage; exit 0 }

if (-not $NoModifyPath -and $env:FIRMA_NO_MODIFY_PATH -eq '1') { $NoModifyPath = $true }
if (-not $NoInit       -and $env:FIRMA_NO_INIT        -eq '1') { $NoInit       = $true }
if (-not $Force        -and $env:FIRMA_FORCE          -eq '1') { $Force        = $true }
if (-not $DryRun       -and $env:FIRMA_DRY_RUN        -eq '1') { $DryRun       = $true }

if (-not $InstallDir -or $InstallDir.Length -eq 0) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\firma\bin'
}

function Invoke-Step ([string]$Description, [scriptblock]$Action) {
    if ($DryRun) {
        Write-Host "[dry-run] $Description"
    } else {
        & $Action
    }
}

function Get-Target {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    switch ($arch) {
        'X64'   { return 'x86_64-pc-windows-msvc' }
        'Arm64' { return 'aarch64-pc-windows-msvc' }
        default { Stop-Install "unsupported windows arch: $arch" }
    }
}

function Resolve-FirmaVersion {
    if ($script:Version) {
        if ($script:Version -notmatch '^v') { $script:Version = "v$script:Version" }
        Write-Info "version (pinned): $script:Version"
        return
    }
    Write-Info 'resolving latest release ...'
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$GitHubRepo/releases/latest")
    $req.AllowAutoRedirect = $false
    $req.Method = 'HEAD'
    $location = $null
    try {
        $resp = $req.GetResponse()
        $location = $resp.Headers['Location']
        $resp.Close()
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp) {
            $location = $resp.Headers['Location']
            $resp.Close()
        }
    }
    if (-not $location) { Stop-Install 'could not resolve latest release URL' }
    $candidate = ($location -split '/')[-1]
    if ($candidate -notmatch '^v[0-9]') {
        Stop-Install "unexpected latest-release URL: $location"
    }
    $script:Version = $candidate
    Write-Info "version: $script:Version"
}

function Test-Existing {
    $cmd = Get-Command firma -ErrorAction SilentlyContinue
    if (-not $cmd) { return }
    $verLine = (& firma --version 2>$null)
    $current = if ($verLine) { ($verLine -split ' ')[1] } else { 'unknown' }
    $targetVer = $script:Version.TrimStart('v')
    if ($current -eq $targetVer -and -not $Force) {
        Write-Info "firma $current already installed. Use -Force to reinstall."
        exit 0
    }
    if ($Force) {
        Write-Info "replacing firma $current with $targetVer (-Force)"
        return
    }
    if ([Environment]::UserInteractive) {
        $ans = Read-Host "[firma-installer] replace firma $current with $targetVer? [y/N]"
        if ($ans -notmatch '^(y|Y|yes|YES)$') { Stop-Install 'aborted by user' }
    } else {
        Stop-Install "firma $current already on PATH. Re-run with -Force or -Version."
    }
}

function New-TempDir {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal scratch-dir helper; the script-level -DryRun flag already gates real work.'
    )]
    param()
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) "firma-installer-$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Get-FirmaArchive ($TmpDir) {
    # Release tag carries the v prefix (v0.7.0); asset filenames do not.
    $versionBare = $script:Version.TrimStart('v')
    $script:ArchiveName  = "firma-$versionBare-$script:Target.zip"
    $script:ArchivePath  = Join-Path $TmpDir $script:ArchiveName
    $script:ChecksumPath = "$script:ArchivePath.sha256"
    $base = "https://github.com/$GitHubRepo/releases/download/$script:Version"
    Write-Info "downloading $script:ArchiveName ..."
    Invoke-Step "Invoke-WebRequest $base/$script:ArchiveName" {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$script:ArchiveName"        -OutFile $script:ArchivePath
    }
    Invoke-Step "Invoke-WebRequest $base/$script:ArchiveName.sha256" {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$script:ArchiveName.sha256" -OutFile $script:ChecksumPath
    }
}

function Test-FirmaChecksum {
    Write-Info 'verifying checksum ...'
    if ($DryRun) { Write-Info '(dry-run) skipping verification'; return }
    $expected = (Get-Content $script:ChecksumPath -Raw).Trim().Split()[0]
    if (-not $expected) { Stop-Install "empty checksum file: $script:ChecksumPath" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $script:ArchivePath).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) {
        Stop-Install "checksum mismatch: expected $expected, got $actual"
    }
    Write-Info 'checksum ok'
}

function Install-FirmaBinary ($TmpDir) {
    $extractDir = Join-Path $TmpDir 'extract'
    Invoke-Step "Expand-Archive $script:ArchivePath" {
        Expand-Archive -Path $script:ArchivePath -DestinationPath $extractDir -Force
    }
    if ($DryRun) {
        $binarySrc = Join-Path $extractDir 'firma.exe'
    } else {
        $binarySrc = (Get-ChildItem -Path $extractDir -Filter 'firma.exe' -Recurse | Select-Object -First 1).FullName
        if (-not $binarySrc) { Stop-Install "could not find firma.exe inside $script:ArchiveName" }
    }
    Invoke-Step "New-Item -Path $InstallDir" {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    $dest = Join-Path $InstallDir 'firma.exe'
    Invoke-Step "Move-Item $binarySrc -> $dest" {
        Move-Item -Force -Path $binarySrc -Destination $dest
    }
    Write-Info "installed: $dest"
}

function Add-FirmaToPath {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $segments = $userPath -split ';' | Where-Object { $_ -ne '' }
    if ($segments -contains $InstallDir) {
        Write-Info "$InstallDir already on User PATH"
        return
    }
    if ($NoModifyPath) {
        Write-Warn "$InstallDir not on PATH. Add it manually via System Properties or:"
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$userPath;$InstallDir`", 'User')"
        return
    }
    $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
    Invoke-Step "set User PATH (+= $InstallDir)" {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    Write-Info 'open a new shell to pick up the updated PATH.'
}

function Invoke-PostInstall {
    Write-Info 'firma installed.'
    Write-Info "quickstart: $QuickstartUrl"
    if ($NoInit -or -not [Environment]::UserInteractive) {
        Write-Info 'next step: firma stack init'
        return
    }
    $ans = Read-Host '[firma-installer] run `firma stack init` now? [Y/n]'
    if ($ans -match '^(y|Y|yes|YES|)$') {
        if ($DryRun) { Write-Info '(dry-run) would invoke: firma stack init'; return }
        & (Join-Path $InstallDir 'firma.exe') stack init
    } else {
        Write-Info 'next step: firma stack init'
    }
}

function Main {
    Write-Info "install dir: $InstallDir"
    if ($DryRun) { Write-Info 'dry-run mode: no files will be written' }
    $script:Target = Get-Target
    Write-Info "target: $script:Target"
    Resolve-FirmaVersion
    Test-Existing

    $tmp = New-TempDir
    try {
        Get-FirmaArchive $tmp
        Test-FirmaChecksum
        Install-FirmaBinary $tmp
    } finally {
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    }

    Add-FirmaToPath
    Invoke-PostInstall
}

Main
