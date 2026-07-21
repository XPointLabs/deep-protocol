[CmdletBinding()]
param(
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function Get-StreamSha256 {
    param([System.IO.Stream]$Stream)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Stream)) `
            -replace "-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$manifest = Get-Content -LiteralPath `
    (Join-Path $RepositoryRoot "eng\p14e2-native-assets.json") -Raw |
    ConvertFrom-Json
if ($manifest.schema -ne "deep-p14e2-libsodium-native-assets-v1" -or
    $manifest.assets.Count -ne 5) {
    throw "The P14E2 native asset manifest schema or exact count is invalid."
}

$expectedRids = @(
    "win-arm64",
    "win-x64",
    "linux-arm64",
    "linux-x64",
    "android-arm64"
)
$actualRids = @($manifest.assets | ForEach-Object { [string]$_.rid })
if ($null -ne (Compare-Object `
    ($expectedRids | Sort-Object) `
    ($actualRids | Sort-Object)) -or
    ($actualRids | Sort-Object -Unique).Count -ne $expectedRids.Count) {
    throw "The P14E2 native RID set differs from the exact allowlist."
}

$package = Get-Item -LiteralPath (Join-Path $RepositoryRoot `
    "vendor\p14-profile-carrier\packages\$($manifest.package.name)")
if ($package.Length -ne [long]$manifest.package.bytes) {
    throw "The exact libsodium package byte length differs."
}
$packageHash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).
    Hash.ToLowerInvariant()
if ($packageHash -ne [string]$manifest.package.sha256) {
    throw "The exact libsodium package SHA-256 differs."
}

$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    foreach ($asset in $manifest.assets) {
        $matches = @($archive.Entries | Where-Object {
            $_.FullName -ceq [string]$asset.path
        })
        if ($matches.Count -ne 1) {
            throw "The exact native asset must occur once: $($asset.rid)."
        }
        $entry = $matches[0]
        if ($entry.Length -ne [long]$asset.bytes) {
            throw "The native asset byte length differs: $($asset.rid)."
        }
        $stream = $entry.Open()
        try {
            $hash = Get-StreamSha256 $stream
        }
        finally {
            $stream.Dispose()
        }
        if ($hash -ne [string]$asset.sha256) {
            throw "The native asset SHA-256 differs: $($asset.rid)."
        }
        Write-Output (
            "rid=$($asset.rid) native-asset-path=$($asset.path) " +
            "bytes=$($asset.bytes) native-asset-sha256=$hash")
    }
}
finally {
    $archive.Dispose()
}

Write-Output "CROSS-RID-EXECUTION-PENDING"
