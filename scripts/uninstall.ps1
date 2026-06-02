# Licensing POC — Windows Uninstall Script
# Clears all license state so a fresh activate can run cleanly.
# Run from any directory; paths are resolved from %APPDATA% and the registry.

Param(
    [string]$LicenseDir = $PSScriptRoot + "\..",
    [switch]$Quiet
)

$ErrorActionPreference = "SilentlyContinue"

function Remove-IfExists($path) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force
        if (-not $Quiet) { Write-Host "  removed: $path" }
    }
}

Write-Host "`nLicensing POC — clearing license state (Windows)`n"

# 1. Local working-directory files
$root = (Resolve-Path "$LicenseDir").Path
Remove-IfExists "$root\license.json"
Remove-IfExists "$root\last_seen.json"
Remove-IfExists "$root\public_key.pem"
Remove-IfExists "$root\fingerprint.txt"

# 2. APPDATA mirror + boot anchor
$mirror = "$env:APPDATA\LicensePOC"
Remove-IfExists $mirror          # removes last_seen.json + boot_anchor.json inside

# 3. Registry anchors
# HKLM (requires admin — failure is silent)
try {
    Remove-Item "HKLM:\Software\LicensePOC" -Recurse -Force
    if (-not $Quiet) { Write-Host "  removed: HKLM:\Software\LicensePOC" }
} catch {}

# HKCU (always accessible)
try {
    Remove-Item "HKCU:\Software\LicensePOC" -Recurse -Force
    if (-not $Quiet) { Write-Host "  removed: HKCU:\Software\LicensePOC" }
} catch {}

Write-Host "`nDone. Run 'poc-license activate --activation-key YOUR-KEY' to re-activate."
