$ErrorActionPreference = "Stop"

$metadataPath = Join-Path (Split-Path $env:NEXTEST_ENV) "architecture-metadata.json"
$process = Start-Process cargo `
    -ArgumentList "metadata", "--all-features", "--format-version", "1" `
    -NoNewWindow `
    -PassThru `
    -RedirectStandardOutput $metadataPath `
    -Wait

if ($process.ExitCode -ne 0) {
    exit $process.ExitCode
}

Add-Content -Path $env:NEXTEST_ENV -Value "FIRMA_ARCHITECTURE_METADATA=$metadataPath" -Encoding utf8
