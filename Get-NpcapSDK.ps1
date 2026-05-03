<#
.SYNOPSIS
    Downloads and extracts the Npcap SDK into the project's Npcap/ directory.

.DESCRIPTION
    Fetches the latest (or a pinned) Npcap SDK zip from npcap.com and unpacks
    it so that Npcap/Include/ and Npcap/Lib/ match the layout expected by
    build.rs and Cargo.

.PARAMETER Version
    SDK version to download, e.g. "1.16".  Defaults to the value of the
    NPCAP_SDK_VERSION environment variable, or "1.16" if neither is set.

.PARAMETER Destination
    Root of the Npcap tree to populate.  Defaults to the "Npcap" folder
    that sits next to this script's parent directory (i.e. the repo root).

.EXAMPLE
    # Developer — run from repo root:
    .\scripts\Get-NpcapSDK.ps1

.EXAMPLE
    # Pin a specific version:
    .\scripts\Get-NpcapSDK.ps1 -Version 1.16
#>

[CmdletBinding()]
param(
    [string] $Version     = $env:NPCAP_SDK_VERSION ?? "1.16",
    [string] $Destination = (Join-Path $PSScriptRoot ".." "Npcap")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Derived values ────────────────────────────────────────────────────────────
$sdkUrl  = "https://npcap.com/dist/npcap-sdk-$Version.zip"
$zipPath = Join-Path $env:TEMP "npcap-sdk-$Version.zip"
$Destination = [IO.Path]::GetFullPath($Destination)

# ── Idempotency guard ─────────────────────────────────────────────────────────
# Skip if the expected layout already exists (e.g. cached between CI runs).
$headerCheck = Join-Path $Destination "Include" "pcap" "pcap.h"
if (Test-Path $headerCheck) {
    Write-Host "Npcap SDK already present at '$Destination' — skipping download."
    exit 0
}

# ── Download ──────────────────────────────────────────────────────────────────
Write-Host "Downloading Npcap SDK v$Version from $sdkUrl ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sdkUrl -OutFile $zipPath -UseBasicParsing

# ── Extract ───────────────────────────────────────────────────────────────────
$extractDir = Join-Path $env:TEMP "npcap-sdk-$Version"
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }

Write-Host "Extracting to '$extractDir' ..."
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

# ── Locate SDK root inside the zip ───────────────────────────────────────────
# The zip may or may not have a top-level folder; find the one that contains
# an Include/ subdirectory.
$sdkRoot = Get-ChildItem $extractDir -Recurse -Directory -Filter "Include" |
    Select-Object -First 1 |
    ForEach-Object { $_.Parent.FullName }

if (-not $sdkRoot) {
    # Flat layout — the extract dir itself is the SDK root
    $sdkRoot = $extractDir
}

Write-Host "SDK root detected: '$sdkRoot'"

# ── Copy into project tree ────────────────────────────────────────────────────
# Preserve existing files that aren't being replaced (e.g. hand-edited headers).
foreach ($subdir in @("Include", "Lib")) {
    $src = Join-Path $sdkRoot $subdir
    $dst = Join-Path $Destination $subdir

    if (-not (Test-Path $src)) {
        Write-Warning "Expected subdirectory '$subdir' not found in SDK — skipping."
        continue
    }

    Write-Host "Copying $subdir -> '$dst' ..."
    # robocopy: /E=recurse empty dirs, /XO=skip older, exit 0-7 are success
    $rc = (robocopy $src $dst /E /XO /NJH /NJS /NFL /NDL)
    if ($LASTEXITCODE -gt 7) {
        Write-Error "robocopy failed with exit code $LASTEXITCODE"
    }
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Remove-Item $zipPath    -Force -ErrorAction SilentlyContinue
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Npcap SDK v$Version installed to '$Destination'."