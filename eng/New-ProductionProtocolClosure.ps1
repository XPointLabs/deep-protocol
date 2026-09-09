[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('survival', 'production')]
    [string] $Mode,

    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [string] $RepositoryRoot = '',

    [switch] $ValidateOnly
)

# Local-only materialization. There is deliberately no publish, source registration,
# consumer repin, historic-commit mode, or repository-URL override.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'ProductionProtocolClosure.Common.ps1')

function Invoke-ArchivedBuild {
    param([string] $SourceRoot, [string] $RawPackages, [string] $Version, [string] $Commit, [Collections.IDictionary] $Policy)
    $config = Join-Path $SourceRoot 'eng/production-protocol-closure.NuGet.Config'
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { Throw-ClosureError 'Archived hermetic NuGet.Config is missing.' }
    foreach ($package in $Policy.packages) {
        $properties = @(Get-HermeticMsBuildProperties $SourceRoot $package $Version $Policy $Commit)
        [void] (Get-EvaluatedProjectContract $SourceRoot $Policy $package $Version)
        [void] (Get-LockedGraph $SourceRoot $package)
        $project = Join-Path $SourceRoot $package.project
        Invoke-Checked dotnet (@('restore', $project, '--locked-mode', '--configfile', $config) + $properties) "locked restore $($package.project)"
        Assert-HermeticEvaluatedInputClosure $SourceRoot $Policy $package $Version $Commit
    }
    foreach ($package in $Policy.packages) {
        Invoke-HermeticAuditedTarget $SourceRoot $Policy $package $Version $Commit Build
    }
    New-PrivateDirectoryAtomic $RawPackages
    foreach ($package in $Policy.packages) {
        Invoke-HermeticAuditedTarget $SourceRoot $Policy $package $Version $Commit Pack $RawPackages
    }
}

function Invoke-LockedRestoreValidation {
    param([string] $SourceRoot, [string] $Version, [string] $Commit, [Collections.IDictionary] $Policy)
    $config = Join-Path $SourceRoot 'eng/production-protocol-closure.NuGet.Config'
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { Throw-ClosureError 'Archived hermetic NuGet.Config is missing.' }
    foreach ($package in $Policy.packages) {
        $properties = @(Get-HermeticMsBuildProperties $SourceRoot $package $Version $Policy $Commit)
        $project = Join-Path $SourceRoot $package.project
        [void] (Get-LockedGraph $SourceRoot $package)
        [void] (Get-EvaluatedProjectContract $SourceRoot $Policy $package $Version)
        Invoke-Checked dotnet (@('restore', $project, '--locked-mode', '--configfile', $config) + $properties) "locked restore validation $($package.project)"
        Assert-HermeticEvaluatedInputClosure $SourceRoot $Policy $package $Version $Commit
    }
}

function Convert-LockedGraphToManifest($Locked) {
    return @($Locked.Values | Sort-Object id | ForEach-Object {
        $node = $_
        [ordered]@{
            id = $node.id
            type = $node.type
            version = if ($node.type -ceq 'Project') { $null } else { $node.version }
            contentHash = if ($node.type -ceq 'Project') { $null } else { $node.contentHash }
            requested = if ($node.type -ceq 'Direct') { $node.requested } else { $null }
            dependencies = @($node.dependencies.Keys | Sort-Object | ForEach-Object {
                [ordered]@{ id = [string] $_; requested = [string] $node.dependencies[$_] }
            })
        }
    })
}

function Get-ReproducibilityManifest {
    param([string] $SourceRoot, [string] $NormalizedPackages, [string] $Version, [Collections.IDictionary] $Policy)
    $records = @()
    foreach ($package in $Policy.packages) {
        foreach ($extension in @('dll', 'pdb')) {
            $projectDirectory = Split-Path -Parent (Join-Path $SourceRoot $package.project)
            $path = Join-Path $projectDirectory "bin/Release/$($package.targetFramework)/$($package.id).$extension"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                Throw-ClosureError "Reproducibility output is missing: $path"
            }
            $records += [ordered]@{ name = "$($package.id).$extension"; sha256 = Get-FileDigest $path; sha512 = Get-FileDigest $path 'SHA512' }
        }
        $packagePath = Join-Path $NormalizedPackages "$($package.id).$Version.nupkg"
        if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
            Throw-ClosureError "Reproducibility package is missing: $packagePath"
        }
        $records += [ordered]@{ name = "$($package.id).nupkg"; sha256 = Get-FileDigest $packagePath; sha512 = Get-FileDigest $packagePath 'SHA512' }
    }
    return @($records | Sort-Object { $_.name })
}

$numeric = '(?:0|[1-9][0-9]*)'
$prerelease = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
if ($Version.Length -gt 128 -or $Version -notmatch "^$numeric\.$numeric\.$numeric(?:-$prerelease(?:\.$prerelease)*)?$") {
    Throw-ClosureError 'Version is not canonical path-safe SemVer.'
}
$Mode = $Mode.ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$repository = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
$output = Assert-SafeNewOutput $OutputDirectory $repository

$topLevel = Get-CheckedGitText $repository @('rev-parse', '--show-toplevel') 'Git worktree root discovery'
if (-not $script:ClosurePathComparer.Equals($topLevel.TrimEnd('\', '/'), $repository.TrimEnd('\', '/'))) { Throw-ClosureError 'RepositoryRoot is not the Git worktree root.' }
$resolvedCommit = Get-CheckedGitText $repository @('rev-parse', '--verify', "$Commit^{commit}") 'Commit resolution'
$head = Get-CheckedGitText $repository @('rev-parse', 'HEAD') 'HEAD resolution'
if ($resolvedCommit -cne $Commit -or $head -cne $Commit) { Throw-ClosureError 'Commit must be the exact canonical current HEAD.' }
$status = Get-CheckedGitText $repository @('status', '--porcelain=v1', '--untracked-files=all') 'Clean-tree assertion'
if (-not [string]::IsNullOrWhiteSpace($status)) { Throw-ClosureError 'Working tree must be clean, including untracked files.' }
$tree = Get-CheckedGitText $repository @('rev-parse', "$Commit^{tree}") 'HEAD tree resolution'
if ($tree -cnotmatch '^[0-9a-f]{40}$') { Throw-ClosureError 'HEAD tree ID is not canonical.' }

$trackedEntries = @(Assert-TrackedTreeNoReparse $repository $Commit)
foreach ($required in @(
    "eng/$script:ClosurePolicyFileName", "eng/$script:ClosurePolicySchemaFileName",
    'eng/production-protocol-closure.NuGet.Config',
    'eng/New-ProductionProtocolClosure.ps1', 'eng/ProductionProtocolClosure.Common.ps1', 'eng/Normalize-ProductionProtocolClosure.ps1',
    'eng/Normalize-NuGetPackage.ps1', 'eng/ProductionProtocolClosure.InputAudit.targets')) {
    if (@($trackedEntries | Where-Object path -ceq $required).Count -ne 1) {
        Throw-ClosureError "Required materializer input is not tracked at exact HEAD: $required"
    }
}
$stage = New-PrivateClosureStage $output.Parent
$stageSucceeded = $false
try {
    $sourceRoot = Join-Path $stage.Path "source-$([Guid]::NewGuid().ToString('N'))"
    $secondSourceRoot = Join-Path $stage.Path "source-$([Guid]::NewGuid().ToString('N'))"
    $rawPackages = Join-Path $stage.Path "raw-packages-$([Guid]::NewGuid().ToString('N'))"
    $secondRawPackages = Join-Path $stage.Path "raw-packages-$([Guid]::NewGuid().ToString('N'))"
    $normalized = Join-Path $stage.Path "normalized-$([Guid]::NewGuid().ToString('N'))"
    $secondNormalized = Join-Path $stage.Path "normalized-$([Guid]::NewGuid().ToString('N'))"
    $published = Join-Path $stage.Path 'published'
    $snapshot = New-ExactGitSnapshot $repository $Commit $sourceRoot $trackedEntries
    Assert-PrivateExclusiveDirectory $sourceRoot 'Extracted exact-HEAD snapshot'
    $secondSnapshot = New-ExactGitSnapshot $repository $Commit $secondSourceRoot $trackedEntries
    Assert-PrivateExclusiveDirectory $secondSourceRoot 'Second extracted exact-HEAD snapshot'
    if (($snapshot | ConvertTo-Json -Compress) -cne ($secondSnapshot | ConvertTo-Json -Compress)) {
        Throw-ClosureError 'Independent extracted exact-HEAD snapshots differ.'
    }

    $archivedPolicy = Read-ExactSnapshotPolicy $sourceRoot $trackedEntries
    foreach ($package in $archivedPolicy.packages) {
        foreach ($required in @($package.project, $package.lockFile) + @($package.packInputs | Where-Object { -not $_.StartsWith('build:', [StringComparison]::Ordinal) })) {
            if (@($trackedEntries | Where-Object path -ceq $required).Count -ne 1) {
                Throw-ClosureError "Policy build input is not tracked at exact HEAD: $required"
            }
        }
    }
    if ($ValidateOnly) {
        # Validation-only uses the same exact-Git-blob snapshot, isolated import
        # controls, private package root, strict lock graph, and locked restore.
        Invoke-LockedRestoreValidation $sourceRoot $Version $Commit $archivedPolicy
        Remove-VerifiedStage $stage
        $stageSucceeded = $true
        Write-Output "PASS validation-only exact clean policy closure ($Mode $Version $Commit)"
        return
    }
    Invoke-ArchivedBuild $sourceRoot $rawPackages $Version $Commit $archivedPolicy
    $archivedNormalizer = Join-Path $sourceRoot 'eng/Normalize-ProductionProtocolClosure.ps1'
    & $archivedNormalizer -InputDirectory $rawPackages -OutputDirectory $normalized -Version $Version -SourceCommit $Commit -SourceRoot $sourceRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { Throw-ClosureError 'Archived exact-three normalization failed.' }
    $secondPolicy = Read-ExactSnapshotPolicy $secondSourceRoot $trackedEntries
    if ($secondPolicy.policySha256 -cne $archivedPolicy.policySha256 -or $secondPolicy.schemaSha256 -cne $archivedPolicy.schemaSha256) {
        Throw-ClosureError 'Second archived strict policy/schema hashes differ.'
    }
    Invoke-ArchivedBuild $secondSourceRoot $secondRawPackages $Version $Commit $secondPolicy
    $secondNormalizer = Join-Path $secondSourceRoot 'eng/Normalize-ProductionProtocolClosure.ps1'
    & $secondNormalizer -InputDirectory $secondRawPackages -OutputDirectory $secondNormalized -Version $Version -SourceCommit $Commit -SourceRoot $secondSourceRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { Throw-ClosureError 'Second archived exact-three normalization failed.' }
    $firstReproducibility = @(Get-ReproducibilityManifest $sourceRoot $normalized $Version $archivedPolicy)
    $secondReproducibility = @(Get-ReproducibilityManifest $secondSourceRoot $secondNormalized $Version $secondPolicy)
    if (($firstReproducibility | ConvertTo-Json -Depth 4 -Compress) -cne ($secondReproducibility | ConvertTo-Json -Depth 4 -Compress)) {
        Throw-ClosureError 'Two independent random-root builds differ in DLL, PDB, or normalized nupkg bytes.'
    }

    New-PrivateDirectoryAtomic $published
    $packageManifest = @()
    foreach ($package in $archivedPolicy.packages) {
        $sourcePackage = Join-Path $normalized "$($package.id).$Version.nupkg"
        $destination = Join-Path $published ([IO.Path]::GetFileName($sourcePackage))
        [IO.File]::Copy($sourcePackage, $destination, $false)
        $metadata = Read-PackageMetadata $destination ([string] $package.targetFramework)
        $locked = Get-LockedGraph $sourceRoot $package
        $contract = Get-DependencyContract $package $locked $Version
        if ($metadata.repositoryUrl -cne $archivedPolicy.repositoryUrl -or $metadata.repositoryType -cne $archivedPolicy.repositoryType -or $metadata.commit -cne $Commit) {
            Throw-ClosureError "Final package repository type/URL/commit differ from policy and exact HEAD: $($package.id)"
        }
        Assert-PackagePackTargets $destination $package $sourceRoot
        $packageManifest += [ordered]@{
            id = $package.id
            version = $Version
            file = [IO.Path]::GetFileName($destination)
            repositoryUrl = $metadata.repositoryUrl
            commit = $metadata.commit
            sha256 = Get-FileDigest $destination 'SHA256'
            sha512 = Get-FileDigest $destination 'SHA512'
            directDependencies = @($contract.Keys | Sort-Object | ForEach-Object {
                $entry = if ($locked.ContainsKey($_) -and $locked[$_].type -ne 'Project') { $locked[$_] } else { $null }
                [ordered]@{
                    id = [string] $_
                    requested = if ($null -eq $entry) { $null } else { $entry.requested }
                    version = [string] $contract[$_]
                    contentHash = if ($null -eq $entry) { $null } else { $entry.contentHash }
                }
            })
            lockedGraph = Convert-LockedGraphToManifest $locked
            packInputs = @($package.packInputs)
            packTargets = @($package.packTargets)
        }
    }
    if (@(Get-ChildItem -LiteralPath $published -File -Filter '*.nupkg').Count -ne 3 -or
        @(Get-ChildItem -LiteralPath $published -Force).Count -ne 3) {
        Throw-ClosureError 'Candidate publication is not exactly three nupkg files.'
    }

    $manifest = [ordered]@{
        format = 'deep-production-protocol-closure/v2'
        mode = $Mode
        version = $Version
        threatModel = [ordered]@{
            required = 'trusted exclusive build principal and process; output parent excludes other writable principals'
            outOfScope = 'compromise or a malicious concurrent process running as the same OS principal'
        }
        policy = [ordered]@{ schema = $archivedPolicy.schema; policySha256 = $archivedPolicy.policySha256; schemaSha256 = $archivedPolicy.schemaSha256 }
        source = [ordered]@{
            repositoryUrl = $archivedPolicy.repositoryUrl
            commit = $Commit
            tree = $tree
            snapshot = $snapshot
        }
        reproducibility = [ordered]@{
            independentRandomRootBuilds = 2
            byteIdenticalArtifacts = $firstReproducibility
        }
        packages = $packageManifest
    }
    $manifestPath = Join-Path $published $script:ClosureManifestFileName
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
    if (@(Get-ChildItem -LiteralPath $published -File -Filter '*.nupkg').Count -ne 3 -or
        @(Get-ChildItem -LiteralPath $published -Force).Count -ne 4) {
        Throw-ClosureError 'Candidate publication must contain exactly three nupkg files plus the v2 manifest.'
    }
    $expectedFiles = @(Get-DirectoryFileManifest $published)
    Move-PublishedStage $published $output $expectedFiles
    Remove-VerifiedStage $stage
    $stageSucceeded = $true
}
catch {
    $failure = $_
    $quarantine = if (-not $stageSucceeded -and (Test-Path -LiteralPath $stage.Path)) { Move-StageToQuarantine $stage } else { 'not applicable' }
    throw "New-ProductionProtocolClosure failed. Work stage was not recursively deleted; quarantine: $quarantine. Cause: $($failure.Exception.Message)"
}

Write-Output "PASS local exact-three $Mode closure materialized at $($output.Path)"
