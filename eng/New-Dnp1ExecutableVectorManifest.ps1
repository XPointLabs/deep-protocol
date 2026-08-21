[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $MappingsPath,
    [Parameter(Mandatory)] [string] $ProtocolBaseCommit,
    [Parameter(Mandatory)] [string[]] $ImplementationScope,
    [string] $NormativeRoot = '',
    [string] $OutputPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($NormativeRoot)) {
    $NormativeRoot = Join-Path (Split-Path $root -Parent) 'docs/survival-program/releases/v3.0.0/specs'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root 'tests/Deep.Protocol.GoldenVectors/Vectors/dnp1-classical-v1.executable.json'
}
$NormativeRoot = (Resolve-Path -LiteralPath $NormativeRoot).Path
$MappingsPath = (Resolve-Path -LiteralPath $MappingsPath).Path
if ($ProtocolBaseCommit -notmatch '^[0-9a-f]{40}$') { throw 'Protocol base commit is invalid.' }
& git -C $root merge-base --is-ancestor $ProtocolBaseCommit HEAD
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

$normativeNames = @(
    'DNP1-CLASSICAL-IDENTITY-RESET-MRL2-V1.md',
    'dnp1-classical-v1.registry.json',
    'dnp1-classical-v1.registry.schema.json',
    'dnp1-classical-v1.vectors.schema.json',
    'dnp1-classical-v1.vectors.skeleton.json',
    'dnp1-classical-v1.evidence-ownership.json',
    'dnp1-classical-v1.evidence-ownership.schema.json',
    'dnp1-classical-v1.evidence-manifest.schema.json',
    'dnp1-classical-v1.evidence-attestation.schema.json',
    'dnp1-classical-v1.evidence-selftest-result.json')
$normativeGitRoot = (& git -C $NormativeRoot rev-parse --show-toplevel 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the normative repository root.' }
$normativeFiles = foreach ($name in $normativeNames) {
    $path = Join-Path $NormativeRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Normative file missing: $name" }
    $gitRelative = Get-RelativeWithin $normativeGitRoot $path
    $tracked = (& git -C $normativeGitRoot ls-files --error-unmatch -- $gitRelative 2>$null | Out-String).Trim()
    $trackedExit = $LASTEXITCODE
    $dirty = (& git -C $normativeGitRoot status --porcelain -- $gitRelative | Out-String).Trim()
    if ($trackedExit -ne 0 -or [string]::IsNullOrWhiteSpace($tracked) -or
        -not [string]::IsNullOrWhiteSpace($dirty)) {
        throw "Normative file is untracked or differs from HEAD: $name"
    }
    [ordered]@{ path = $name; sha256 = Get-Sha256 $path }
}
$normativeCommit = (& git -C $NormativeRoot rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $normativeCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve the normative repository commit.'
}

$skeleton = Get-Content -Raw -LiteralPath (
    Join-Path $NormativeRoot 'dnp1-classical-v1.vectors.skeleton.json') | ConvertFrom-Json
$cases = @($skeleton.cases)
$ownership = Get-Content -Raw -LiteralPath (
    Join-Path $NormativeRoot 'dnp1-classical-v1.evidence-ownership.json') | ConvertFrom-Json
$ownershipRows = @($ownership.rows)
$caseById = @{}
foreach ($case in $cases) {
    $id = [string]$case.id
    if ($caseById.ContainsKey($id)) { throw "Duplicate skeleton ID: $id" }
    $caseById[$id] = $case
}
if ($cases.Count -ne 314 -or $ownershipRows.Count -ne 314 -or
    (($caseById.Keys | Sort-Object) -join "`n") -cne
    ((@($ownershipRows | ForEach-Object { [string]$_.id }) | Sort-Object) -join "`n")) {
    throw 'Normative vector and evidence-ownership sets are not exact314 and identical.'
}
$packageRows = @($ownershipRows | Where-Object { $_.gate -ceq 'ProtocolPackageBlocking' })
if ($packageRows.Count -ne 219 -or
    @($packageRows | Where-Object executableOwner -ceq 'Protocol').Count -ne 216 -or
    @($packageRows | Where-Object executableOwner -ceq 'DevOpsWitness').Count -ne 3) {
    throw 'Normative package evidence is not Protocol216 plus DevOpsWitness3.'
}
$draft = Get-Content -Raw -LiteralPath $MappingsPath | ConvertFrom-Json
$draftMappings = @($draft.mappings)
$draftIds = @($draftMappings | ForEach-Object { [string]$_.id })
$draftFqns = @($draftMappings | ForEach-Object { [string]$_.testFqn })
if (($draftIds | Sort-Object -Unique).Count -ne $draftIds.Count -or
    ($draftFqns | Sort-Object -Unique).Count -ne $draftFqns.Count -or
    ((@($packageRows | ForEach-Object { [string]$_.id }) | Sort-Object) -join "`n") -cne
    (($draftIds | Sort-Object) -join "`n")) {
    throw 'Draft mappings have duplicate FQNs or duplicate, missing or extra package-gate IDs.'
}

$mappings = foreach ($draftMapping in $draftMappings) {
    $id = [string]$draftMapping.id
    $fqn = [string]$draftMapping.testFqn
    $fixture = [string]$draftMapping.fixturePath
    if ($fqn -notmatch '^[A-Za-z0-9_.+`]+$' -or [IO.Path]::IsPathRooted($fixture) -or
        $fixture.Contains('..')) { throw "Unsafe mapping for vector '$id'." }
    $fixturePath = Join-Path $root $fixture
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "Fixture missing for vector '$id': $fixture"
    }
    $case = $caseById[$id]
    [ordered]@{
        id = $id
        area = [string]$case.area
        outcome = [string]$case.outcome
        callbacks = [ordered]@{
            signature = [int64]$case.callbacks.signature
            agreement = [int64]$case.callbacks.agreement
            network = [int64]$case.callbacks.network
            mutation = [int64]$case.callbacks.mutation
        }
        testFqn = $fqn
        fixturePath = $fixture.Replace('\', '/')
        fixtureSha256 = Get-Sha256 $fixturePath
    }
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
} else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}
$outputRelative = Get-RelativeWithin $root $outputFullPath
$scope = @($ImplementationScope | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
if ($scope.Count -eq 0 -or ($scope | Sort-Object -Unique).Count -ne $scope.Count -or
    $scope.Contains($outputRelative)) { throw 'Implementation scope is empty, duplicated or self-referential.' }
$scopeRows = foreach ($relative in $scope) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('..')) {
        throw "Unsafe implementation scope path: $relative"
    }
    $path = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Scope file missing: $relative" }
    "{0}`t{1}`n" -f $relative, (Get-Sha256 $path)
}
$scopeDigest = Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes(($scopeRows -join '')))

$manifest = [ordered]@{
    schemaVersion = '1.0.0'
    normativeCommit = $normativeCommit
    protocolBaseCommit = $ProtocolBaseCommit
    normativeFiles = @($normativeFiles)
    implementationScope = $scope
    implementationScopeSha256 = $scopeDigest
    mappings = @($mappings)
}
$json = ($manifest | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
if (-not $json.EndsWith("`n", [StringComparison]::Ordinal)) { $json += "`n" }
$directory = Split-Path $outputFullPath -Parent
[IO.Directory]::CreateDirectory($directory) | Out-Null
[IO.File]::WriteAllText($outputFullPath, $json, [Text.UTF8Encoding]::new($false))
Write-Host "WROTE executable DNP1 package manifest ($($mappings.Count) of $($cases.Count) frozen IDs): $outputFullPath"
