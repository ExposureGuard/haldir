# Haldir demo installer — Windows.
#
#   irm https://raw.githubusercontent.com/ExposureGuard/haldir/main/install.ps1 | iex
#
# Fetches the matching binary from the latest demo release and tells you how to
# run it. Nothing is installed system-wide and nothing is left running: the
# binary is one file, and it cleans up after itself when you stop it.
#
# Set $env:HALDIR_DEMO_DIR to choose where it lands (default: current directory).
# Set $env:HALDIR_DEMO_TAG to pin a release instead of taking the latest.

$ErrorActionPreference = 'Stop'

$Repo = 'ExposureGuard/haldir'
$Dir  = if ($env:HALDIR_DEMO_DIR) { $env:HALDIR_DEMO_DIR } else { '.' }

# Newest demo release, so this does not need editing each time one is cut.
# `/releases/latest` is no good: the demo releases are prerelease, so it
# returns the product release, which has no binaries attached.
$Tag = $env:HALDIR_DEMO_TAG
if (-not $Tag) {
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=30" -UseBasicParsing
        $Tag = ($releases | Where-Object { $_.tag_name -like 'demo-*' } | Select-Object -First 1).tag_name
    } catch {
        # Anonymous API calls are rate-limited per address; fall back rather
        # than failing the install over a lookup.
        $Tag = $null
    }
}
if (-not $Tag) { $Tag = 'demo-preview-2' }

function Say  ($m) { Write-Host "[*] $m" }
function Good ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Die  ($m) { Write-Host "[-] $m" -ForegroundColor Red; exit 1 }

# One build for Windows, so there is no architecture to branch on here — but
# the check catches an ARM64 machine, where an x64 build would run under
# emulation and be worth saying out loud rather than leaving to be discovered.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq 'ARM64') {
    Say 'ARM64 detected — this is an x64 build and will run under emulation.'
}

$Asset = 'haldir-demo-windows-x86_64.exe'
$Url   = "https://github.com/$Repo/releases/download/$Tag/$Asset"

Say "fetching: $Url"

if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
$Target = Join-Path $Dir 'haldir-demo.exe'

try {
    # -UseBasicParsing avoids the IE engine dependency on older PowerShell.
    Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing
} catch {
    Die "download failed: $($_.Exception.Message)"
}

$size = (Get-Item $Target).Length
if ($size -lt 1000000) {
    Die "the downloaded file is $size bytes, which is not the binary. The release or tag name is probably wrong."
}
$mb = [math]::Round($size / 1MB, 1)

Good "downloaded to $Target ($mb MB)"
Write-Host ""
Write-Host "  Run the three probes:"
Write-Host "      & '$Target'"
Write-Host ""
Write-Host "  Or keep an instance up to poke at, printing a URL and an API key:"
Write-Host "      & '$Target' --keep"
Write-Host ""
Write-Host "  Windows SmartScreen may warn once — More info, then Run anyway."
Write-Host ""
