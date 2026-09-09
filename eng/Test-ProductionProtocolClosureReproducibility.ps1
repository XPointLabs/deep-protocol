[CmdletBinding()]
param([string] $RepositoryRoot = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$repository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
. (Join-Path $repository 'eng/ProductionProtocolClosure.Common.ps1')

function Invoke-ReproducibilityBuild([string] $SourceRoot, [string] $RawPackages, [string] $Normalized, [string] $Version, [string] $Commit) {
    $policy = Read-ClosurePolicy (Join-Path $SourceRoot 'eng/production-protocol-closure.policy.json') (Join-Path $SourceRoot 'eng/production-protocol-closure.policy.schema.json')
    $config = Join-Path $SourceRoot 'eng/production-protocol-closure.NuGet.Config'
    foreach ($package in $policy.packages) {
        [void] (Get-LockedGraph $SourceRoot $package)
        [void] (Get-EvaluatedProjectContract $SourceRoot $policy $package $Version)
        $properties = @(Get-HermeticMsBuildProperties $SourceRoot $package $Version $policy $Commit)
        $project = Join-Path $SourceRoot $package.project
        Invoke-Checked dotnet (@('restore', $project, '--locked-mode', '--configfile', $config) + $properties) "reproducibility restore $($package.id)" | Out-Host
        Assert-HermeticEvaluatedInputClosure $SourceRoot $policy $package $Version $Commit
    }
    foreach ($package in $policy.packages) {
        Invoke-HermeticAuditedTarget $SourceRoot $policy $package $Version $Commit Build
    }
    New-PrivateDirectoryAtomic $RawPackages
    foreach ($package in $policy.packages) {
        Invoke-HermeticAuditedTarget $SourceRoot $policy $package $Version $Commit Pack $RawPackages
    }
    & (Join-Path $SourceRoot 'eng/Normalize-ProductionProtocolClosure.ps1') -InputDirectory $RawPackages -OutputDirectory $Normalized -Version $Version -SourceCommit $Commit -SourceRoot $SourceRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { Throw-ClosureError 'Reproducibility normalization failed.' }
    return $policy
}

function Get-ArtifactManifest([string] $SourceRoot, [string] $Normalized, [string] $Version, [Collections.IDictionary] $Policy) {
    $records = @()
    foreach ($package in $Policy.packages) {
        foreach ($extension in @('dll', 'pdb')) {
            $projectDirectory = Split-Path -Parent (Join-Path $SourceRoot $package.project)
            $path = Join-Path $projectDirectory "bin/Release/$($package.targetFramework)/$($package.id).$extension"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Throw-ClosureError "Reproducibility output is missing: $path" }
            $records += "$($package.id).$extension=$((Get-FileDigest $path))"
        }
        $path = Join-Path $Normalized "$($package.id).$Version.nupkg"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Throw-ClosureError "Reproducibility package is missing: $path" }
        $records += "$($package.id).nupkg=$((Get-FileDigest $path))"
    }
    return @($records | Sort-Object)
}

$stage = New-PrivateClosureStage
$succeeded = $false
try {
    $workspaceEntries = @(Get-CanonicalWorkspaceEntries $repository)
    $sourceA = Join-Path $stage.Path "source-$([Guid]::NewGuid().ToString('N'))"
    $sourceB = Join-Path $stage.Path "source-$([Guid]::NewGuid().ToString('N'))"
    $sourceManifestA = Copy-CanonicalWorkspaceSnapshot $repository $sourceA $workspaceEntries
    $sourceManifestB = Copy-CanonicalWorkspaceSnapshot $repository $sourceB $workspaceEntries
    if (($sourceManifestA | ConvertTo-Json -Compress) -cne ($sourceManifestB | ConvertTo-Json -Compress)) {
        Throw-ClosureError 'Independent canonical current-workspace snapshots differ before build.'
    }
    $version = '9.9.9-reproducibility'
    $commit = '0000000000000000000000000000000000000000'
    $rawA = Join-Path $stage.Path "raw-$([Guid]::NewGuid().ToString('N'))"
    $rawB = Join-Path $stage.Path "raw-$([Guid]::NewGuid().ToString('N'))"
    $normalizedA = Join-Path $stage.Path "normalized-$([Guid]::NewGuid().ToString('N'))"
    $normalizedB = Join-Path $stage.Path "normalized-$([Guid]::NewGuid().ToString('N'))"
    $policyA = Invoke-ReproducibilityBuild $sourceA $rawA $normalizedA $version $commit
    $policyB = Invoke-ReproducibilityBuild $sourceB $rawB $normalizedB $version $commit
    $manifestA = @(Get-ArtifactManifest $sourceA $normalizedA $version $policyA)
    $manifestB = @(Get-ArtifactManifest $sourceB $normalizedB $version $policyB)
    if (($manifestA -join "`n") -cne ($manifestB -join "`n")) {
        Throw-ClosureError "Independent random-root DLL/PDB/nupkg hashes differ.`nA:`n$($manifestA -join "`n")`nB:`n$($manifestB -join "`n")"
    }
    Remove-VerifiedStage $stage
    $succeeded = $true
    Write-Output "PASS two independent complete-current-workspace random-root DLL/PDB/nupkg builds are byte-identical ($($manifestA.Count) artifacts; $($sourceManifestA.fileCount) source inputs)"
}
catch {
    $failure = $_
    $quarantine = if (-not $succeeded -and (Test-Path -LiteralPath $stage.Path)) { Move-StageToQuarantine $stage } else { 'not applicable' }
    throw "Reproducibility gate failed; quarantine: $quarantine. Cause: $($failure.Exception.Message) Stack: $($failure.ScriptStackTrace)"
}
