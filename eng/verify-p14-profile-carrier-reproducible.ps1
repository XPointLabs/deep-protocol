[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "deep-p14-carrier-reproducible")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Checked {
    param([string]$File, [string[]]$Arguments, [string]$WorkingDirectory)
    Push-Location $WorkingDirectory
    try {
        & $File @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$File failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Assert-Equal {
    param([string]$First, [string]$Second, [string]$Label)
    if ($First -ne $Second) {
        throw "$Label differs across the two clean randomized source paths."
    }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$dirty = & git -C $RepositoryRoot status --porcelain=v1
if ($LASTEXITCODE -ne 0 -or $null -ne $dirty) {
    throw "The reproducibility gate requires an exact clean committed HEAD."
}
$head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch "^[0-9a-f]{40}$") {
    throw "The exact repository commit could not be resolved."
}
$version = "0.1.0-p14.$($head.Substring(0, 7))"

$workBase = [System.IO.Path]::GetFullPath($WorkRoot)
New-Item -ItemType Directory -Path $workBase -Force | Out-Null
$runRoot = Join-Path $workBase "run-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $runRoot | Out-Null
$identityScript = Join-Path $RepositoryRoot `
    "eng\Get-P14ProfileCarrierNormalizedIdentity.ps1"
$results = @()

foreach ($label in @(
    "a-$([Guid]::NewGuid().ToString('N'))",
    "second-clean-randomized-extraction-path-$([Guid]::NewGuid().ToString('N'))"
)) {
    $root = Join-Path $runRoot $label
    $archive = Join-Path $root "source.zip"
    $source = Join-Path $root "source"
    New-Item -ItemType Directory -Path $source -Force | Out-Null
    Invoke-Checked "git" @(
        "-C", $RepositoryRoot,
        "archive", "--format=zip",
        "-o", $archive,
        $head
    ) $RepositoryRoot
    Expand-Archive -LiteralPath $archive -DestinationPath $source

    $cliHome = Join-Path $root "empty-cli-home"
    $packagesHome = Join-Path $root "empty-packages"
    New-Item -ItemType Directory -Path $cliHome, $packagesHome | Out-Null
    $env:DOTNET_CLI_HOME = $cliHome
    $env:NUGET_PACKAGES = $packagesHome
    $env:NUGET_HTTP_CACHE_PATH = (Join-Path $root "empty-http-cache")
    $env:HTTP_PROXY = "http://127.0.0.1:9"
    $env:HTTPS_PROXY = "http://127.0.0.1:9"
    $env:ALL_PROXY = "http://127.0.0.1:9"
    $env:NO_PROXY = ""
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:DOTNET_NOLOGO = "1"

    $project = Join-Path $source `
        "src\Deep.Protocol.ProfileCarrier\Deep.Protocol.ProfileCarrier.csproj"
    $config = Join-Path $source "eng\p14-profile-carrier.NuGet.Config"
    $output = Join-Path $root "package"
    New-Item -ItemType Directory -Path $output | Out-Null
    $properties = @(
        "-p:Version=$version",
        "-p:PackageVersion=$version",
        "-p:RepositoryCommit=$head",
        "-p:Deterministic=true",
        "-p:ContinuousIntegrationBuild=true"
    )
    Invoke-Checked "dotnet" (@(
        "restore", $project,
        "--configfile", $config,
        "--locked-mode",
        "--packages", $packagesHome,
        "-p:RestoreNoCache=true"
    ) + $properties) $source
    Invoke-Checked "dotnet" (@(
        "build", $project,
        "--no-restore",
        "--configuration", "Release"
    ) + $properties) $source
    Invoke-Checked "dotnet" (@(
        "pack", $project,
        "--no-restore",
        "--no-build",
        "--configuration", "Release",
        "--output", $output
    ) + $properties) $source

    $dll = Join-Path $source `
        "src\Deep.Protocol.ProfileCarrier\bin\Release\net10.0\Deep.Protocol.ProfileCarrier.dll"
    $pdb = Join-Path $source `
        "src\Deep.Protocol.ProfileCarrier\bin\Release\net10.0\Deep.Protocol.ProfileCarrier.pdb"
    $package = Join-Path $output "Deep.Protocol.ProfileCarrier.$version.nupkg"
    $identity = & $identityScript `
        -PackagePath $package `
        -ExpectedRepositoryCommit $head
    $results += [PSCustomObject]@{
        DllHash = Get-Sha256 $dll
        PdbHash = Get-Sha256 $pdb
        NormalizedHash = $identity.Hash
        NormalizedManifest = $identity.Manifest
        RawPackageHash = Get-Sha256 $package
        Package = $package
    }
}

Assert-Equal $results[0].DllHash $results[1].DllHash "DLL SHA-256"
Assert-Equal $results[0].PdbHash $results[1].PdbHash "PDB SHA-256"
Assert-Equal `
    $results[0].NormalizedManifest `
    $results[1].NormalizedManifest `
    "Normalized package manifest"
Assert-Equal `
    $results[0].NormalizedHash `
    $results[1].NormalizedHash `
    "Normalized source identity SHA-256"

Write-Output "PASS version=$version repository-commit=$head"
Write-Output "dll-sha256=$($results[0].DllHash)"
Write-Output "pdb-sha256=$($results[0].PdbHash)"
Write-Output "normalized-source-identity-sha256=$($results[0].NormalizedHash)"
Write-Output "pack-a-exact-carrier-file-only-sha256=$($results[0].RawPackageHash)"
Write-Output "pack-b-exact-carrier-file-only-sha256=$($results[1].RawPackageHash)"
