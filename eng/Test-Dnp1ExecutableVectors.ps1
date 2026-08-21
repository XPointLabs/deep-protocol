[CmdletBinding()]
param(
    [string] $NormativeRoot = '',
    [string] $ManifestPath = '',
    [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Release',
    [switch] $NoBuild,
    [switch] $IntegrityOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($NormativeRoot)) {
    $NormativeRoot = Join-Path (Split-Path $root -Parent) 'docs/survival-program/releases/v3.0.0/specs'
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $root 'tests/Deep.Protocol.GoldenVectors/Vectors/dnp1-classical-v1.executable.json'
}
$NormativeRoot = (Resolve-Path -LiteralPath $NormativeRoot).Path
$ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifestBytes = [IO.File]::ReadAllBytes($ManifestPath)
if ($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xef -and
    $manifestBytes[1] -eq 0xbb -and $manifestBytes[2] -eq 0xbf) {
    throw 'Executable vector manifest must be UTF-8 without BOM.'
}
$manifestText = [Text.Encoding]::UTF8.GetString($manifestBytes)
if ($manifestText.Contains("`r")) { throw 'Executable vector manifest must use LF line endings.' }
$manifest = $manifestText | ConvertFrom-Json

function Assert-ExactProperties([object] $Value, [string[]] $Expected, [string] $Name) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        throw "$Name has missing or additional properties."
    }
}

Assert-ExactProperties $manifest @(
    'schemaVersion', 'normativeCommit', 'protocolBaseCommit', 'normativeFiles',
    'implementationScope', 'implementationScopeSha256', 'mappings') 'Executable manifest'
if ([string]$manifest.schemaVersion -cne '1.0.0') { throw 'Executable vector manifest schema is unsupported.' }
if ([string]::IsNullOrWhiteSpace([string]$manifest.normativeCommit)) {
    throw 'Executable vector manifest has no normative commit.'
}
$normativeHead = (& git -C $NormativeRoot rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $normativeHead -cne [string]$manifest.normativeCommit) {
    throw 'Checked-out normative repository commit differs from the executable manifest.'
}
$normativeGitRoot = (& git -C $NormativeRoot rev-parse --show-toplevel 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the normative repository root.' }
$protocolBase = [string]$manifest.protocolBaseCommit
if ($protocolBase -notmatch '^[0-9a-f]{40}$') { throw 'Protocol base commit is invalid.' }
& git -C $root merge-base --is-ancestor $protocolBase HEAD
if ($LASTEXITCODE -ne 0) { throw 'Protocol base commit is not an ancestor of the checked-out source.' }

function Get-Sha256([string] $Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Get-RelativeWithin([string] $Base, [string] $Path) {
    $prefix = [IO.Path]::GetFullPath($Base).TrimEnd([IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the expected root: $full"
    }
    return $full.Substring($prefix.Length).Replace('\', '/')
}

function Get-BytesSha256([byte[]] $Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-', '') }
    finally { $algorithm.Dispose() }
}

function Assert-Sha256([string] $Value, [string] $Name) {
    if ($Value -notmatch '^[0-9A-Fa-f]{64}$') { throw "$Name is not an exact SHA-256 value." }
}

$normative = @($manifest.normativeFiles)
if ($normative.Count -lt 10) { throw 'Executable vector manifest omits normative/evidence files.' }
foreach ($entry in $normative) {
    Assert-ExactProperties $entry @('path', 'sha256') 'Normative binding'
    $relative = [string]$entry.path
    Assert-Sha256 ([string]$entry.sha256) "Normative digest for $relative"
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('..')) {
        throw "Unsafe normative path: $relative"
    }
    $path = Join-Path $NormativeRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Normative file missing: $relative" }
    $gitRelative = Get-RelativeWithin $normativeGitRoot $path
    $tracked = (& git -C $normativeGitRoot ls-files --error-unmatch -- $gitRelative 2>$null | Out-String).Trim()
    $trackedExit = $LASTEXITCODE
    $dirty = (& git -C $normativeGitRoot status --porcelain -- $gitRelative | Out-String).Trim()
    if ($trackedExit -ne 0 -or [string]::IsNullOrWhiteSpace($tracked) -or
        -not [string]::IsNullOrWhiteSpace($dirty)) {
        throw "Normative file is untracked or differs from the bound commit: $relative"
    }
    if ((Get-Sha256 $path) -cne ([string]$entry.sha256).ToUpperInvariant()) {
        throw "Normative file digest differs: $relative"
    }
}

$skeletonEntry = $normative | Where-Object { [string]$_.path -ceq 'dnp1-classical-v1.vectors.skeleton.json' }
if (@($skeletonEntry).Count -ne 1) { throw 'Executable vector manifest must bind one exact skeleton.' }
$skeletonPath = Join-Path $NormativeRoot ([string]$skeletonEntry.path)
$skeleton = Get-Content -Raw -LiteralPath $skeletonPath | ConvertFrom-Json
$cases = @($skeleton.cases)
$ownershipEntry = $normative | Where-Object {
    [string]$_.path -ceq 'dnp1-classical-v1.evidence-ownership.json' }
if (@($ownershipEntry).Count -ne 1) { throw 'Executable manifest must bind one exact ownership table.' }
$ownership = Get-Content -Raw -LiteralPath (
    Join-Path $NormativeRoot ([string]$ownershipEntry.path)) | ConvertFrom-Json
$ownershipRows = @($ownership.rows)
$packageRows = @($ownershipRows | Where-Object { $_.gate -ceq 'ProtocolPackageBlocking' })
$mappings = @($manifest.mappings)
$caseIds = @($cases | ForEach-Object { [string]$_.id })
$mappingIds = @($mappings | ForEach-Object { [string]$_.id })
if (($caseIds | Sort-Object -Unique).Count -ne $caseIds.Count) { throw 'Frozen skeleton IDs are not unique.' }
if ($caseIds.Count -ne 314 -or $ownershipRows.Count -ne 314 -or
    ((@($ownershipRows | ForEach-Object { [string]$_.id }) | Sort-Object) -join "`n") -cne
    (($caseIds | Sort-Object) -join "`n")) {
    throw 'Frozen vector and evidence-ownership sets are not exact314 and identical.'
}
if (($mappingIds | Sort-Object -Unique).Count -ne $mappingIds.Count) { throw 'Executable mapping IDs are not unique.' }
if ((@($mappings | ForEach-Object { [string]$_.testFqn } | Sort-Object -Unique)).Count -ne
    $mappings.Count) { throw 'Each frozen ID must map to its own independently discoverable xUnit FQN.' }
if (((@($packageRows | ForEach-Object { [string]$_.id }) | Sort-Object) -join "`n") -cne
    (($mappingIds | Sort-Object) -join "`n")) {
    throw 'Executable mappings have missing or extra package-gate IDs.'
}

$caseById = @{}
foreach ($case in $cases) { $caseById[[string]$case.id] = $case }
foreach ($mapping in $mappings) {
    Assert-ExactProperties $mapping @(
        'id', 'area', 'outcome', 'callbacks', 'testFqn', 'fixturePath', 'fixtureSha256') 'Vector mapping'
    Assert-ExactProperties $mapping.callbacks @(
        'signature', 'agreement', 'network', 'mutation') 'Vector callback contract'
    $id = [string]$mapping.id
    $case = $caseById[$id]
    if ([string]$mapping.area -cne [string]$case.area -or
        [string]$mapping.outcome -cne [string]$case.outcome) {
        throw "Area/outcome differs for vector '$id'."
    }
    foreach ($name in @('signature', 'agreement', 'network', 'mutation')) {
        if ([int64]$mapping.callbacks.$name -ne [int64]$case.callbacks.$name) {
            throw "Callback contract differs for vector '$id': $name."
        }
    }
    $fqn = [string]$mapping.testFqn
    if ($fqn -notmatch '^[A-Za-z0-9_.+`]+$') { throw "Invalid xUnit FQN for vector '$id'." }
    $fixture = [string]$mapping.fixturePath
    Assert-Sha256 ([string]$mapping.fixtureSha256) "Fixture digest for vector '$id'"
    if ([IO.Path]::IsPathRooted($fixture) -or $fixture.Contains('..')) {
        throw "Unsafe fixture path for vector '$id'."
    }
    $fixturePath = Join-Path $root $fixture
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf) -or
        (Get-Sha256 $fixturePath) -cne ([string]$mapping.fixtureSha256).ToUpperInvariant()) {
        throw "Fixture digest differs for vector '$id'."
    }
}

$scopePaths = @($manifest.implementationScope | ForEach-Object { [string]$_ })
if ($scopePaths.Count -eq 0 -or ($scopePaths | Sort-Object -Unique).Count -ne $scopePaths.Count) {
    throw 'Implementation scope is empty or duplicated.'
}
$manifestRelative = Get-RelativeWithin $root $ManifestPath
$scopeRows = foreach ($relative in $scopePaths | Sort-Object) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('..') -or
        $relative.Replace('\', '/') -ceq $manifestRelative) {
        throw "Unsafe or self-referential implementation scope path: $relative"
    }
    $path = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Scope file missing: $relative" }
    "{0}`t{1}`n" -f $relative.Replace('\', '/'), (Get-Sha256 $path)
}
$scopeBytes = [Text.Encoding]::UTF8.GetBytes(($scopeRows -join ''))
$scopeDigest = Get-BytesSha256 $scopeBytes
Assert-Sha256 ([string]$manifest.implementationScopeSha256) 'Implementation scope digest'
if ($scopeDigest -cne ([string]$manifest.implementationScopeSha256).ToUpperInvariant()) {
    throw 'Implementation/test scope digest differs.'
}

if ($IntegrityOnly) {
    Write-Host ("PASS executable DNP1 manifest integrity only; " +
        "NO executable case discovery or evidence was performed")
    return
}

$testProject = Join-Path $root 'tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj'
$listArguments = @('test', $testProject, '--configuration', $Configuration, '--list-tests')
if ($NoBuild) { $listArguments += '--no-build' }
$discovered = (& dotnet @listArguments 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "xUnit discovery failed.`n$discovered" }
$discoveredCases = @($discovered -split "`r?`n" | ForEach-Object { $_.Trim() } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$fqns = @($mappings | ForEach-Object { [string]$_.testFqn } | Sort-Object -Unique)
foreach ($fqn in $fqns) {
    if ($discoveredCases -cnotcontains $fqn) {
        throw "Mapped xUnit case is not discoverable: $fqn"
    }
}

for ($offset = 0; $offset -lt $fqns.Count; $offset += 24) {
    $batch = @($fqns[$offset..([Math]::Min($offset + 23, $fqns.Count - 1))])
    $filter = ($batch | ForEach-Object { "FullyQualifiedName=$_" }) -join '|'
    $arguments = @('test', $testProject, '--configuration', $Configuration, '--filter', $filter)
    if ($NoBuild) { $arguments += '--no-build' }
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) { throw "Executable vector xUnit batch failed at index $offset." }
}

Write-Host "PASS executable DNP1 package vectors ($($fqns.Count) of $($cases.Count) frozen IDs)"
