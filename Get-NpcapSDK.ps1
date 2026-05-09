#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and extracts the Npcap SDK into the project's Npcap/ directory.

.DESCRIPTION
    Fetches the Npcap SDK zip from npcap.com and unpacks it so that
    Npcap/Include/ and Npcap/Lib/ match the layout expected by build.rs.

.PARAMETER Version
    SDK version to download, e.g. "1.16". Defaults to NPCAP_SDK_VERSION env
    var, or "1.16" if neither is set.

.PARAMETER Destination
    Root of the Npcap tree to populate. Defaults to the "Npcap" folder at the
    repo root (one level above the directory containing this script).

.EXAMPLE
    .\scripts\Get-NpcapSDK.ps1

.EXAMPLE
    .\scripts\Get-NpcapSDK.ps1 -Version 1.16
#>
param(
    [string] $Version = "",
    [string] $Destination = (Join-Path (Join-Path $PSScriptRoot ".") "Npcap")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Version) {
    if ($env:NPCAP_SDK_VERSION) {
        $Version = $env:NPCAP_SDK_VERSION
    } else {
        $Version = "1.16"
    }
}

$sdkUrl      = "https://npcap.com/dist/npcap-sdk-$Version.zip"
$zipPath     = Join-Path $env:TEMP "npcap-sdk-$Version.zip"
$Destination = [IO.Path]::GetFullPath($Destination)

# Skip if already present
$headerCheck = Join-Path (Join-Path (Join-Path $Destination "Include") "pcap") "pcap.h"
if (Test-Path $headerCheck) {
    Write-Host "Npcap SDK already present at '$Destination' -- skipping download."
    exit 0
}

# Download
Write-Host "Downloading Npcap SDK v$Version ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sdkUrl -OutFile $zipPath -UseBasicParsing

# Extract
$extractDir = Join-Path $env:TEMP "npcap-sdk-$Version"
if (Test-Path $extractDir) {
    Remove-Item $extractDir -Recurse -Force
}
Write-Host "Extracting to '$extractDir' ..."
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

# Locate the SDK root (handles both flat and single-subfolder zip layouts)
$includeDir = Get-ChildItem $extractDir -Recurse -Directory -Filter "Include" |
    Select-Object -First 1
if ($includeDir) {
    $sdkRoot = $includeDir.Parent.FullName
} else {
    $sdkRoot = $extractDir
}
Write-Host "SDK root: '$sdkRoot'"

# Copy Include/ and Lib/ into project tree
foreach ($subdir in @("Include", "Lib")) {
    $src = Join-Path $sdkRoot $subdir
    $dst = Join-Path $Destination $subdir
    if (-not (Test-Path $src)) {
        Write-Warning "Expected '$subdir' not found in SDK zip -- skipping."
        continue
    }
    Write-Host "Copying $subdir -> '$dst' ..."
    robocopy $src $dst /E /XO /NJH /NJS /NFL /NDL | Out-Null
    $robocopyExit = $LASTEXITCODE
    if ($robocopyExit -gt 7) {
        Write-Error "robocopy exited with code $robocopyExit"
    }
}

# Cleanup
Remove-Item $zipPath    -Force -ErrorAction SilentlyContinue
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Npcap SDK v$Version installed to '$Destination'."