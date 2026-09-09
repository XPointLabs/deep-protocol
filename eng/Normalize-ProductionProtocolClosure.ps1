[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InputDirectory,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [Parameter(Mandatory = $true)] [string] $Version,
    [Parameter(Mandatory = $true)] [string] $SourceCommit,
    [Parameter(Mandatory = $true)] [string] $SourceRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'ProductionProtocolClosure.Common.ps1')

$numeric = '(?:0|[1-9][0-9]*)'
$prerelease = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
if ($Version.Length -gt 128 -or $Version -notmatch "^$numeric\.$numeric\.$numeric(?:-$prerelease(?:\.$prerelease)*)?$") {
    Throw-ClosureError 'Version is not canonical path-safe SemVer.'
}
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { Throw-ClosureError 'SourceCommit is not canonical.' }

$inputRoot = (Resolve-Path -LiteralPath $InputDirectory -ErrorAction Stop).Path
$sourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
$outputRoot = Get-CanonicalFullPath $OutputDirectory
if (Test-Path -LiteralPath $outputRoot) { Throw-ClosureError 'Normalizer OutputDirectory must be new.' }
$outputParent = Split-Path -Parent $outputRoot
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) { Throw-ClosureError 'Normalizer output parent is missing.' }
Assert-NoReparseDescendants $inputRoot 'Raw package input'
Assert-NoReparseDescendants $sourceRoot 'Archived source snapshot'
Assert-NoReparseAncestors $outputParent 'Normalizer output parent'
Assert-PrivateExclusiveDirectory $outputParent 'Normalizer output parent'

$policyPath = Join-Path $PSScriptRoot $script:ClosurePolicyFileName
$schemaPath = Join-Path $PSScriptRoot $script:ClosurePolicySchemaFileName
$policy = Read-ClosurePolicy $policyPath $schemaPath
$normalizer = Join-Path $PSScriptRoot 'Normalize-NuGetPackage.ps1'
if (-not (Test-Path -LiteralPath $normalizer -PathType Leaf)) { Throw-ClosureError 'Archived NuGet normalizer is missing.' }

$files = @(Get-ChildItem -LiteralPath $inputRoot -File -Filter '*.nupkg')
$debris = @(Get-ChildItem -LiteralPath $inputRoot -Force | Where-Object { $_.PSIsContainer -or $_.Extension -cne '.nupkg' })
if ($files.Count -ne 3 -or $debris.Count -ne 0) {
    Throw-ClosureError 'Raw closure must contain exactly three root nupkg files and no debris.'
}

$graphs = @{}
foreach ($package in $policy.packages) {
    [void] (Get-EvaluatedProjectContract $sourceRoot $policy $package $Version)
    $graphs[$package.id] = Get-LockedGraph $sourceRoot $package
}

$rawById = @{}
foreach ($file in $files) {
    $candidatePackages = @($policy.packages | Where-Object { $file.Name -ceq "$($_.id).$Version.nupkg" })
    if ($candidatePackages.Count -ne 1) { Throw-ClosureError "Raw package filename is outside policy: $($file.Name)" }
    $metadata = Read-PackageMetadata $file.FullName ([string] $candidatePackages[0].targetFramework)
    $matches = @($policy.packages | Where-Object { $_.id -ceq $metadata.id })
    if ($matches.Count -ne 1 -or $rawById.ContainsKey($metadata.id) -or
        $metadata.version -cne $Version -or $metadata.commit -cne $SourceCommit -or
        $metadata.repositoryUrl -cne $policy.repositoryUrl -or
        $file.Name -cne "$($metadata.id).$Version.nupkg") {
        Throw-ClosureError "Raw package identity/provenance is outside policy: $($file.Name)"
    }
    Assert-PackagePackTargets $file.FullName $matches[0] $sourceRoot
    $rawById[$metadata.id] = [PSCustomObject]@{ file = $file; metadata = $metadata }
}
if ($rawById.Count -ne 3) { Throw-ClosureError 'Raw package identity set is incomplete.' }

New-PrivateDirectoryAtomic $outputRoot
foreach ($package in $policy.packages) {
    $raw = $rawById[$package.id]
    $contract = Get-DependencyContract $package $graphs[$package.id] $Version
    $destination = Join-Path $outputRoot "$($package.id).$Version.nupkg"
    [IO.File]::Copy($raw.file.FullName, $destination, $false)
    Set-ExactNuspecDependencies $destination $contract ([string] $package.targetFramework)
    $exactDependencies = @($contract.Keys | Sort-Object | ForEach-Object { "$_=$($contract[$_])" })
    & $normalizer -Path $destination -ExactDependency $exactDependencies -ExactDependencyPrefix 'Deep.Protocol'
    if ($LASTEXITCODE -ne 0) { Throw-ClosureError "Package normalization failed: $($package.id)" }

    $verified = Read-PackageMetadata $destination ([string] $package.targetFramework)
    if ($verified.id -cne $package.id -or $verified.version -cne $Version -or
        $verified.commit -cne $SourceCommit -or $verified.repositoryUrl -cne $policy.repositoryUrl -or
        $verified.dependencies.Count -ne $contract.Count) {
        Throw-ClosureError "Normalized package identity/provenance changed: $($package.id)"
    }
    foreach ($id in $contract.Keys) {
        if (@($verified.dependencies | Where-Object { $_.id -ceq $id -and $_.version -ceq "[$($contract[$id])]" }).Count -ne 1) {
            Throw-ClosureError "Normalized direct dependency is not exact: $($package.id) -> $id"
        }
    }
    Assert-PackagePackTargets $destination $package $sourceRoot
}

$normalized = @(Get-ChildItem -LiteralPath $outputRoot -File -Filter '*.nupkg')
if ($normalized.Count -ne 3 -or @(Get-ChildItem -LiteralPath $outputRoot -Force).Count -ne 3) {
    Throw-ClosureError 'Normalized closure is not exactly three nupkg files.'
}
Write-Output "PASS normalized exact-three policy closure $Version"
