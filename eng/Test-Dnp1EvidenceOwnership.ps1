[CmdletBinding()]
param(
    [string] $NormativeRoot = '',
    [string[]] $MappingPaths = @(),
    [string] $ExpectedNormativeCommit = '2562b11cdacdcc6e60cf79bdb6265b4f4687fbbe',
    [switch] $RequirePackageComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($NormativeRoot)) {
    $NormativeRoot = Join-Path (Split-Path $root -Parent) 'docs/survival-program/releases/v3.0.0/specs'
}
$NormativeRoot = (Resolve-Path -LiteralPath $NormativeRoot).Path
$normativeHead = (& git -C $NormativeRoot rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $normativeHead -cne $ExpectedNormativeCommit) {
    throw 'Checked-out normative repository is not the exact approved evidence-ownership commit.'
}
$normativeGitRoot = (& git -C $NormativeRoot rev-parse --show-toplevel 2>$null | Out-String).Trim()

$skeletonPath = Join-Path $NormativeRoot 'dnp1-classical-v1.vectors.skeleton.json'
$ownershipPath = Join-Path $NormativeRoot 'dnp1-classical-v1.evidence-ownership.json'
foreach ($path in @($skeletonPath, $ownershipPath)) {
    $prefix = [IO.Path]::GetFullPath($normativeGitRoot).TrimEnd('\','/') + '\'
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Normative evidence input is outside its repository: $full"
    }
    $relative = $full.Substring($prefix.Length).Replace('\','/')
    $dirty = (& git -C $normativeGitRoot status --porcelain -- $relative | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($dirty)) {
        throw "Normative evidence input differs from the approved commit: $relative"
    }
}
$skeleton = Get-Content -Raw -LiteralPath $skeletonPath | ConvertFrom-Json
$ownership = Get-Content -Raw -LiteralPath $ownershipPath | ConvertFrom-Json
$cases = @($skeleton.cases)
$rows = @($ownership.rows)
$caseIds = @($cases | ForEach-Object { [string]$_.id })
$rowIds = @($rows | ForEach-Object { [string]$_.id })
if ($cases.Count -ne 314 -or $rows.Count -ne 314 -or
    ($caseIds | Sort-Object -Unique).Count -ne 314 -or
    ($rowIds | Sort-Object -Unique).Count -ne 314 -or
    (($caseIds | Sort-Object) -join "`n") -cne (($rowIds | Sort-Object) -join "`n")) {
    throw 'The normative vector and ownership sets are not exact314 and identical.'
}

$ownerCounts = @{}
$gateCounts = @{}
foreach ($row in $rows) {
    $owner = [string]$row.executableOwner
    $gate = [string]$row.gate
    if (-not $ownerCounts.ContainsKey($owner)) { $ownerCounts[$owner] = 0 }
    if (-not $gateCounts.ContainsKey($gate)) { $gateCounts[$gate] = 0 }
    $ownerCounts[$owner] = 1 + [int]$ownerCounts[$owner]
    $gateCounts[$gate] = 1 + [int]$gateCounts[$gate]
}
$expectedOwners = [ordered]@{
    Protocol = 216; Registry = 15; XNode = 11; Shared = 2;
    DevOpsWitness = 12; CrossRepoE2E = 55; MAUI = 3
}
foreach ($entry in $expectedOwners.GetEnumerator()) {
    if ([int]$ownerCounts[$entry.Key] -ne $entry.Value) {
        throw "Evidence owner count differs for $($entry.Key)."
    }
}
if ([int]$gateCounts.ProtocolPackageBlocking -ne 219 -or
    [int]$gateCounts.CutoverFinalRelease -ne 95) {
    throw 'Evidence gate counts differ from exact package219/final95.'
}
$packageRows = @($rows | Where-Object { $_.gate -ceq 'ProtocolPackageBlocking' })
if (@($packageRows | Where-Object executableOwner -ceq 'Protocol').Count -ne 216 -or
    @($packageRows | Where-Object executableOwner -ceq 'DevOpsWitness').Count -ne 3 -or
    @($packageRows | Where-Object { $_.executableOwner -notin @('Protocol','DevOpsWitness') }).Count -ne 0) {
    throw 'The package evidence owner split is not Protocol216 plus DevOpsWitness3.'
}

$mappingIds = @()
foreach ($mappingPath in $MappingPaths) {
    $resolved = (Resolve-Path -LiteralPath $mappingPath).Path
    $fragment = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json
    if ([string]$fragment.normativeHead -cne $ExpectedNormativeCommit) {
        throw "Mapping fragment is not bound to the approved normative commit: $resolved"
    }
    $mappingIds += @($fragment.mappings |
        ForEach-Object { [string]$_.id })
}
if (@($mappingIds | Sort-Object -Unique).Count -ne $mappingIds.Count) {
    throw 'Mapping fragments contain duplicate semantic IDs.'
}
$unknown = @($mappingIds | Where-Object { $caseIds -cnotcontains $_ })
if ($unknown.Count -ne 0) { throw "Mapping fragments contain unknown IDs: $($unknown -join ', ')" }

$mapped = @{}; foreach ($id in $mappingIds) { $mapped[$id] = $true }
$missingPackage = @($packageRows | Where-Object { -not $mapped.ContainsKey([string]$_.id) })
if ($RequirePackageComplete -and $missingPackage.Count -ne 0) {
    throw "Package evidence is incomplete: $($missingPackage.Count) of 219 rows are missing."
}
Write-Host ("PASS DNP1 evidence ownership exact314/package219/final95; " +
    "mapped={0}; packageMissing={1}" -f $mappingIds.Count, $missingPackage.Count)
