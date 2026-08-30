[CmdletBinding()]
param(
    [switch] $Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$registryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.json'
$schemaPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.schema.json'
$resolvedRegistryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.resolved.json'
$resolvedSchemaPath = Join-Path $repoRoot 'registry/deep-protocol-v1.resolved.schema.json'
$outputPath = Join-Path $repoRoot 'src/Deep.Protocol/Generated/DeepProtocolRegistry.Generated.cs'
$artifactTypeOutputPath = Join-Path $repoRoot 'src/Deep.Protocol/Generated/Dnp1ArtifactType.Generated.cs'
$graphPolicyOutputPath = Join-Path $repoRoot 'eng/Dnp1ProductionGraph.Identity/DeepProtocolRegistryPolicy.Generated.cs'
$normativeRoot = Join-Path (Split-Path $repoRoot -Parent) 'docs/survival-program/releases/v3.0.0/specs'

. (Join-Path $PSScriptRoot 'Dnp1NormativeBinding.ps1')

function Get-ApprovedBlobBytes {
    param(
        [Parameter(Mandatory)] [string] $GitRoot,
        [Parameter(Mandatory)] [string] $Blob
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $GitRoot
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    [void]$start.ArgumentList.Add('cat-file')
    [void]$start.ArgumentList.Add('blob')
    [void]$start.ArgumentList.Add($Blob)
    $process = [Diagnostics.Process]::Start($start)
    if ($null -eq $process) { throw 'Cannot start git cat-file for approved registry blob.' }
    $stream = [IO.MemoryStream]::new()
    try {
        $process.StandardOutput.BaseStream.CopyTo($stream)
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Cannot read approved registry blob: $stderr" }
        return $stream.ToArray()
    }
    finally {
        $stream.Dispose()
        $process.Dispose()
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-NormalizedTextSha256 {
    param([Parameter(Mandatory)] [string] $Path)
    $normalized = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    return Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($normalized))
}

function Get-ProductionWireInventory {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [object] $Configuration
    )

    $map = [Collections.Generic.Dictionary[string, Collections.Generic.HashSet[string]]]::new(
        [StringComparer]::Ordinal)
    $manualLiterals = [Collections.Generic.Dictionary[string, Collections.Generic.HashSet[string]]]::new(
        [StringComparer]::Ordinal)
    foreach ($assembly in $Configuration.assemblies) {
        $assemblyRoot = Join-Path $Root "src/$assembly"
        if (-not (Test-Path -LiteralPath $assemblyRoot -PathType Container)) {
            throw "Production assembly source root is missing: $assembly"
        }
        foreach ($file in Get-ChildItem -LiteralPath $assemblyRoot -Filter '*.cs' -File -Recurse) {
            if ($file.FullName -match '[\\/]Generated[\\/]') { continue }
            $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
            $text = [IO.File]::ReadAllText($file.FullName)
            foreach ($match in [regex]::Matches(
                    $text,
                    '(?<![A-Za-z0-9_.])ProtocolMagic(?:Bytes)?[.](?<value>[A-Z0-9]{4})(?![A-Za-z0-9_])')) {
                $value = $match.Groups['value'].Value
                if (-not $map.ContainsKey($value)) {
                    $map[$value] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                }
                [void]$map[$value].Add($relative)
            }
            foreach ($match in [regex]::Matches($text, '"(?<value>[A-Z0-9]{4})"(?:u8)?')) {
                $value = $match.Groups['value'].Value
                if (-not $manualLiterals.ContainsKey($value)) {
                    $manualLiterals[$value] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                }
                [void]$manualLiterals[$value].Add($relative)
            }
        }
    }

    $protocolMap = [ordered]@{}
    foreach ($value in @($map.Keys | Sort-Object)) {
        $protocolMap[$value] = @($map[$value] | Sort-Object)
    }
    $canonical = (@($protocolMap.Keys | ForEach-Object {
                "$_`t$($protocolMap[$_] -join ',')"
            }) -join "`n") + "`n"
    return [pscustomobject]@{
        Map = $protocolMap
        Sha256 = Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($canonical))
        ManualLiterals = $manualLiterals
    }
}

function Get-BlobId {
    param(
        [Parameter(Mandatory)] [string] $GitRoot,
        [Parameter(Mandatory)] [string] $Commit,
        [Parameter(Mandatory)] [string] $Name
    )
    $relative = "docs/survival-program/releases/v3.0.0/specs/$Name"
    $value = (& git -C $GitRoot rev-parse "$Commit`:$relative" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40,64}$') {
        throw "Cannot resolve approved blob for $Name."
    }
    return $value
}

function Get-JsonPointerValue {
    param(
        [Parameter(Mandatory)] [object] $Root,
        [Parameter(Mandatory)] [string] $Pointer
    )
    $current = $Root
    foreach ($segment in $Pointer.TrimStart('/').Split('/')) {
        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) { throw "Missing imported JSON pointer: $Pointer" }
        $current = $property.Value
    }
    return $current
}

function Escape-CSharp {
    param([Parameter(Mandatory)] [string] $Value)
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Assert-SourceAnchor {
    param(
        [Parameter(Mandatory)] [object] $Entry,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Lifecycle,
        [Parameter(Mandatory)] [hashtable] $Sources,
        [Parameter(Mandatory)] [string] $Root
    )

    $anchor = $Entry.sourceAnchor
    if ($null -eq $anchor -or -not $Sources.ContainsKey([string]$anchor.anchorSourceId)) {
        throw "Allocation $Scope/$Id has no known source anchor."
    }
    $source = $Sources[[string]$anchor.anchorSourceId]
    if ($source.kind -eq 'production-source-scan') {
        throw "Allocation $Scope/$Id cannot use a production scan as a normative source anchor."
    }
    if ([string]$anchor.ownerSourceId -cne [string]$Entry.sourceId -or
        [string]$anchor.scope -cne $Scope -or [string]$anchor.id -cne $Id -or
        [string]$anchor.name -cne $Name -or [string]$anchor.lifecycle -cne $Lifecycle) {
        throw "Structured source binding differs for $Scope/$Id."
    }
    $lines = [IO.File]::ReadAllText((Join-Path $Root $source.path)).Replace("`r`n", "`n").Split("`n")
    $start = [int]$anchor.startLine
    $end = [int]$anchor.endLine
    if ($start -lt 1 -or $end -lt $start -or $end -gt $lines.Count -or ($end - $start) -gt 8) {
        throw "Source anchor range is invalid for $Scope/$Id."
    }
    $range = ($lines[($start - 1)..($end - 1)] -join "`n") + "`n"
    if ((Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($range))) -cne [string]$anchor.normalizedSha256) {
        throw "Source anchor digest is stale for $Scope/$Id."
    }
    $heading = $null
    for ($index = $start - 1; $index -ge 0; $index--) {
        if ($lines[$index] -match '^#{1,6} ') { $heading = $lines[$index]; break }
    }
    if ($heading -cne [string]$anchor.section) {
        throw "Source anchor section is stale for $Scope/$Id."
    }
    foreach ($token in @($anchor.evidenceTokens)) {
        if (-not $range.Contains([string]$token, [StringComparison]::Ordinal)) {
            throw "Source anchor evidence token '$token' is absent for $Scope/$Id."
        }
    }
}

function Add-ConstClass {
    param(
        [Parameter(Mandatory)] [Text.StringBuilder] $Builder,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [object[]] $Entries,
        [Parameter(Mandatory)] [scriptblock] $ValueExpression,
        [string] $Type = 'string'
    )
    [void]$Builder.AppendLine("    public static class $Name")
    [void]$Builder.AppendLine('    {')
    foreach ($entry in $Entries) {
        $value = & $ValueExpression $entry
        [void]$Builder.AppendLine("        public const $Type $($entry.symbol) = $value;")
    }
    [void]$Builder.AppendLine('    }')
    [void]$Builder.AppendLine()
}

if (-not (Test-Json -LiteralPath $registryPath -SchemaFile $schemaPath -ErrorAction Stop)) {
    throw 'Deep protocol registry does not satisfy its strict schema.'
}

$registryBytes = [IO.File]::ReadAllBytes($registryPath)
$registry = [Text.Encoding]::UTF8.GetString($registryBytes) | ConvertFrom-Json
$sourceRoot = Split-Path $repoRoot -Parent
$sources = @{}
foreach ($source in $registry.sources) {
    $sources[[string]$source.id] = $source
    if ($source.kind -eq 'production-source-scan') { continue }
    $sourcePath = Join-Path $sourceRoot $source.path
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Registry source is missing: $($source.path)"
    }
    if ((Get-NormalizedTextSha256 $sourcePath) -cne $source.normalizedSha256) {
        throw "Registry source digest is stale: $($source.path)"
    }
}
foreach ($entry in $registry.suites | Where-Object sourceId -NE 'dnp1-frozen') {
    Assert-SourceAnchor $entry "suite:$($entry.scope)" `
        "$($entry.scope):0x$('{0:X4}' -f [int]$entry.id)" ([string]$entry.canonicalName) `
        ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.magic | Where-Object sourceId -NE 'production-wire-source') {
    Assert-SourceAnchor $entry 'magic' ([string]$entry.value) ([string]$entry.value) `
        ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.carriers) {
    Assert-SourceAnchor $entry 'carrier' "0x$('{0:X4}' -f [int]$entry.id)" `
        ([string]$entry.canonicalName) ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.deploymentProfiles) {
    Assert-SourceAnchor $entry 'deployment-profile' "0x$('{0:X4}' -f [int]$entry.id)" `
        ([string]$entry.canonicalName) ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.callNames) {
    Assert-SourceAnchor $entry "call:$($entry.axis)" "$($entry.axis):$($entry.canonicalName)" `
        ([string]$entry.canonicalName) ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.interfaces) {
    Assert-SourceAnchor $entry 'interface' ([string]$entry.canonicalName) `
        ([string]$entry.canonicalName) ([string]$entry.lifecycle) $sources $sourceRoot
}
foreach ($entry in $registry.retiredAliases) {
    Assert-SourceAnchor $entry "alias:$($entry.namespace)" "$($entry.namespace):$($entry.alias)" `
        ([string]$entry.alias) 'RETIRED_REJECT' $sources $sourceRoot
}
$productionInventory = Get-ProductionWireInventory $repoRoot $registry.productionInventory
$productionSource = @($registry.sources | Where-Object kind -EQ 'production-source-scan')
if ($productionSource.Count -ne 1 -or
    $productionSource[0].normalizedSha256 -cne $productionInventory.Sha256) {
    throw 'Production wire allocation inventory digest is stale.'
}
$import = @($registry.imports)[0]
$binding = Get-Dnp1ApprovedNormativeBinding -NormativeRoot $normativeRoot `
    -ExpectedNormativeCommit $import.approvedCommit `
    -Names @($import.registry.path, $import.schema.path)

$registryBlob = Get-BlobId $binding.GitRoot $binding.Commit $import.registry.path
$schemaBlob = Get-BlobId $binding.GitRoot $binding.Commit $import.schema.path
$dnpBytes = Get-ApprovedBlobBytes $binding.GitRoot $registryBlob
$dnpSchemaBytes = Get-ApprovedBlobBytes $binding.GitRoot $schemaBlob

if ($registryBlob -cne $import.registry.gitBlob -or
    $schemaBlob -cne $import.schema.gitBlob -or
    (Get-Sha256Hex $dnpBytes) -cne $import.registry.sha256 -or
    (Get-Sha256Hex $dnpSchemaBytes) -cne $import.schema.sha256) {
    throw 'The local registry import metadata does not match the approved DNP1 Git blobs.'
}

$dnpRaw = [Text.Encoding]::UTF8.GetString($dnpBytes)
$dnp = $dnpRaw | ConvertFrom-Json

$allAllocatedMagic = @(
    $dnp.artifactTypes | Where-Object magic -Match '^[A-Z0-9]{4}$' | ForEach-Object magic
    $dnp.records.magic
    $registry.magic.value
) | Sort-Object -Unique
$excludedLiterals = @($registry.productionInventory.excludedLiterals.value)
foreach ($value in $productionInventory.ManualLiterals.Keys) {
    if ($excludedLiterals -ccontains $value) { continue }
    $paths = @($productionInventory.ManualLiterals[$value] | Sort-Object)
    if ($allAllocatedMagic -ccontains $value) {
        throw "Production source hand-authors registered magic $value instead of ProtocolMagic API: $($paths -join ', ')"
    }
    throw "Production source contains an unregistered four-character protocol literal $value`: $($paths -join ', ')"
}
foreach ($value in $productionInventory.Map.Keys) {
    if ($allAllocatedMagic -cnotcontains $value) {
        throw "Production wire magic is absent from the registry: $value"
    }
}
foreach ($entry in $registry.magic | Where-Object lifecycle -EQ 'CURRENT_PRE_CUTOVER') {
    if (-not $productionInventory.Map.Contains($entry.value)) {
        throw "CURRENT_PRE_CUTOVER magic has no production implementation: $($entry.value)"
    }
}
foreach ($entry in $registry.magic | Where-Object { $productionInventory.Map.Contains($_.value) }) {
    if ($entry.lifecycle -ne 'CURRENT_PRE_CUTOVER') {
        throw "Implemented local magic is not CURRENT_PRE_CUTOVER: $($entry.value)"
    }
}
foreach ($entry in $registry.magic | Where-Object lifecycle -EQ 'RETIRED_REJECT') {
    if ($productionInventory.Map.Contains($entry.value)) {
        throw "RETIRED_REJECT magic remains in production source: $($entry.value)"
    }
}

foreach ($suite in @($registry.suites | Where-Object { $_.PSObject.Properties.Name -contains 'importPointer' })) {
    $imported = Get-JsonPointerValue $dnp $suite.importPointer
    if ([uint64]$imported -ne [uint64]$suite.id) {
        throw "Suite $($suite.symbol) differs from approved DNP1 pointer $($suite.importPointer)."
    }
}

$dnpMagic = @(
    $dnp.artifactTypes | Where-Object { $_.magic -match '^[A-Z0-9]{4}$' } | ForEach-Object { $_.magic }
    $dnp.records | ForEach-Object { $_.magic }
) | Sort-Object -Unique
$normalLocalMagic = @($registry.magic | Where-Object { $_.lifecycle -ne 'RETIRED_REJECT' })
$retiredLocalMagic = @($registry.magic | Where-Object { $_.lifecycle -eq 'RETIRED_REJECT' })
$normalMagic = @(
    $dnpMagic | ForEach-Object {
        [pscustomobject]@{ value = $_; symbol = $_; lifecycle = 'FROZEN_TARGET_NOT_ACTIVE'; sourceId = 'dnp1-frozen' }
    }
    $normalLocalMagic
) | Sort-Object value

$resolvedRecords = [Collections.Generic.List[object]]::new()
foreach ($record in $dnp.records | Sort-Object magic) {
    $className = $null
    $suite = $null
    $visibility = 'public'
    foreach ($property in $dnp.recordClasses.PSObject.Properties) {
        if (@($property.Value.records) -ccontains $record.magic) {
            $className = $property.Name
            $suite = $property.Value.headerSuite
            if ($className -in @('protectedHmac', 'protectedAead')) {
                $visibility = 'protected-internal'
            }
            break
        }
    }
    if ($null -eq $className) { throw "Frozen DNP1 record class is missing: $($record.magic)" }
    $minimum = if ($record.PSObject.Properties.Name -contains 'fixedLength') {
        [int]$record.fixedLength
    }
    elseif ($record.PSObject.Properties.Name -contains 'baseLength') { [int]$record.baseLength }
    else { throw "Frozen DNP1 minimum length is missing: $($record.magic)" }
    $maximum = if ($record.PSObject.Properties.Name -contains 'maximumLength') {
        [int]$record.maximumLength
    }
    else { $minimum }
    [object[]]$paths = @()
    if ($productionInventory.Map.Contains($record.magic)) {
        $paths = [object[]]@($productionInventory.Map[$record.magic])
    }
    if ($className -ne 'fixedTranscript') {
        $paths = [object[]]@($paths + 'src/Deep.Protocol/DeepNative/Dnp1RecordDefinitions.cs' | Sort-Object -Unique)
    }
    $allowedSuites = @()
    if ($null -ne $suite) { $allowedSuites = @([int]$suite) }
    $resolvedRecords.Add([ordered]@{
            magic = [string]$record.magic
            version = [int]$record.version
            grammar = if ($className -eq 'fixedTranscript') {
                "fixed-transcript:$($record.framing)"
            }
            else { "dnp1-canonical:$className" }
            suiteNamespace = 'dnp1-header-u16'
            allowedSuites = $allowedSuites
            minBytes = $minimum
            maxBytes = $maximum
            visibility = $visibility
            normativeSource = 'dnp1-frozen'
            ownerPackage = 'Deep.Protocol'
            vectorOwner = [string]$dnp.evidenceOwnership.classificationPath
            schemaOwner = [string]$import.schema.path
            lifecycle = 'FROZEN_TARGET_NOT_ACTIVE'
            contractState = 'frozen-exact'
            implementationPaths = [object[]]$paths
            contractBlocker = $null
        })
}

$dnpRecordMagic = @($dnp.records.magic)
foreach ($artifact in $dnp.artifactTypes | Where-Object {
        $_.magic -match '^[A-Z0-9]{4}$' -and $dnpRecordMagic -cnotcontains $_.magic
    } | Sort-Object magic) {
    [object[]]$paths = @()
    if ($productionInventory.Map.Contains($artifact.magic)) {
        $paths = [object[]]@($productionInventory.Map[$artifact.magic])
    }
    $resolvedRecords.Add([ordered]@{
            magic = [string]$artifact.magic
            version = $null
            grammar = 'opaque-retained-artifact-reference'
            suiteNamespace = 'dnp1-header-u16'
            allowedSuites = @()
            minBytes = $null
            maxBytes = $null
            visibility = 'public'
            normativeSource = 'dnp1-frozen'
            ownerPackage = 'Deep.Protocol'
            vectorOwner = [string]$dnp.evidenceOwnership.classificationPath
            schemaOwner = [string]$import.schema.path
            lifecycle = 'FROZEN_TARGET_NOT_ACTIVE'
            contractState = 'current-source-bound'
            implementationPaths = [object[]]$paths
            contractBlocker = 'The approved DNP1 registry allocates this retained opaque artifact type but does not define a canonical record grammar or byte bounds.'
        })
}

foreach ($entry in $registry.magic | Where-Object { $dnpRecordMagic -cnotcontains $_.value } | Sort-Object value) {
    [object[]]$paths = @()
    if ($productionInventory.Map.Contains($entry.value)) {
        $paths = [object[]]@($productionInventory.Map[$entry.value])
    }
    $ownerPackage = 'Deep.Protocol'
    if ($paths | Where-Object { $_ -like 'src/Deep.Protocol.MembershipRoutes/*' }) {
        $ownerPackage = 'Deep.Protocol.MembershipRoutes'
    }
    elseif ($paths | Where-Object { $_ -like 'src/Deep.Protocol.ProfileCarrier/*' }) {
        $ownerPackage = 'Deep.Protocol.ProfileCarrier'
    }
    $isCurrent = $entry.lifecycle -eq 'CURRENT_PRE_CUTOVER'
    $blocker = if ($entry.lifecycle -eq 'RETIRED_REJECT') {
        $null
    }
    elseif ($isCurrent) {
        'Pre-cutover codec has no frozen REG-01 machine grammar/bounds; this source-bound inventory row cannot become V1 release-active.'
    }
    else {
        'Allocation has no frozen machine schema/vectors; the owning codec package must replace this allocation-only row before activation.'
    }
    $resolvedRecords.Add([ordered]@{
            magic = [string]$entry.value
            version = $null
            grammar = $null
            suiteNamespace = $null
            allowedSuites = @()
            minBytes = $null
            maxBytes = $null
            visibility = if ($isCurrent -and $ownerPackage -eq 'Deep.Protocol.ProfileCarrier') { 'transport' } elseif ($isCurrent) { 'public' } else { 'unfrozen' }
            normativeSource = [string]$entry.sourceId
            ownerPackage = $ownerPackage
            vectorOwner = "deep-protocol:$($entry.sourceId):vectors"
            schemaOwner = "deep-protocol:$($entry.sourceId):schema"
            lifecycle = [string]$entry.lifecycle
            contractState = if ($isCurrent) { 'current-source-bound' } else { 'allocation-only' }
            implementationPaths = [object[]]$paths
            contractBlocker = $blocker
        })
}

$retiredValues = [Collections.Generic.List[object]]::new()
foreach ($entry in $registry.magic | Where-Object {
        $_.lifecycle -eq 'RETIRED_REJECT'
    } | Sort-Object value) {
    $retiredValues.Add([ordered]@{
            namespace = 'magic'
            value = [string]$entry.value
            replacement = $null
        })
}

$plannedRetirements = [Collections.Generic.List[object]]::new()
foreach ($entry in $registry.magic | Where-Object {
        $_.lifecycle -eq 'CURRENT_PRE_CUTOVER' -and
        $_.PSObject.Properties.Name -contains 'targetLifecycle' -and $_.targetLifecycle -eq 'RETIRED_REJECT'
    } | Sort-Object value) {
    $plannedRetirements.Add([ordered]@{
            namespace = 'magic'
            value = [string]$entry.value
            targetLifecycle = 'RETIRED_REJECT'
        })
}
foreach ($entry in $registry.suites | Where-Object lifecycle -EQ 'RETIRED_REJECT' | Sort-Object scope,id) {
    $retiredValues.Add([ordered]@{
            namespace = "suite:$($entry.scope)"
            value = [string]$entry.canonicalName
            replacement = $null
        })
}
foreach ($entry in $registry.retiredAliases | Sort-Object namespace,alias) {
    $retiredValues.Add([ordered]@{
            namespace = [string]$entry.namespace
            value = [string]$entry.alias
            replacement = [string]$entry.replacement
        })
}

$contractBlockers = [Collections.Generic.List[object]]::new()
foreach ($record in $resolvedRecords | Where-Object { $null -ne $_.contractBlocker } | Sort-Object magic) {
    $contractBlockers.Add([ordered]@{ magic = $record.magic; reason = $record.contractBlocker })
}
foreach ($collision in $registry.productionInventory.knownCrossNamespaceCollisions | Sort-Object value) {
    $contractBlockers.Add([ordered]@{
            magic = [string]$collision.value
            reason = "Pre-cutover runtime prefix $($collision.runtimePrefix) still uses the frozen DNP1 allocation; clean-break replacement $($collision.replacement) is required before activation."
        })
}

$resolvedManifest = [ordered]@{
    '$schema' = './deep-protocol-v1.resolved.schema.json'
    schemaVersion = '1.0.0'
    registryGeneration = [int]$registry.registryGeneration
    registryId = 'deep-protocol-v1-resolved'
    sourceRegistrySha256 = Get-Sha256Hex $registryBytes
    dnp1ApprovedCommit = [string]$binding.Commit
    dnp1RegistrySha256 = Get-Sha256Hex $dnpBytes
    records = @($resolvedRecords | Sort-Object magic)
    suites = @($registry.suites | Sort-Object scope,id)
    carriers = @($registry.carriers | Sort-Object id)
    deploymentProfiles = @($registry.deploymentProfiles | Sort-Object id)
    callNames = @($registry.callNames | Sort-Object axis,canonicalName)
    publicInterfaces = @($registry.interfaces | Sort-Object canonicalName)
    retiredValues = @($retiredValues)
    plannedRetirements = @($plannedRetirements)
    contractBlockers = @($contractBlockers)
}
$resolvedExpected = ($resolvedManifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n") + "`n"
if (-not (Test-Json -Json $resolvedExpected -SchemaFile $resolvedSchemaPath -ErrorAction Stop)) {
    throw 'Resolved Deep protocol manifest does not satisfy its strict schema.'
}

$artifactTypeBuilder = [Text.StringBuilder]::new()
[void]$artifactTypeBuilder.AppendLine('// <auto-generated />')
[void]$artifactTypeBuilder.AppendLine('// Generated from the approved DNP1 registry. Do not edit by hand.')
[void]$artifactTypeBuilder.AppendLine()
[void]$artifactTypeBuilder.AppendLine('namespace Deep.Protocol.DeepNative;')
[void]$artifactTypeBuilder.AppendLine()
[void]$artifactTypeBuilder.AppendLine('public enum ArtifactType : ushort')
[void]$artifactTypeBuilder.AppendLine('{')
foreach ($artifact in $dnp.artifactTypes | Sort-Object id) {
    $name = if ($artifact.magic -eq 'D-G-SOURCE') { 'DgSource' } else {
        $artifact.magic.Substring(0, 1) + $artifact.magic.Substring(1).ToLowerInvariant()
    }
    [void]$artifactTypeBuilder.AppendLine("    $name = $($artifact.id),")
}
[void]$artifactTypeBuilder.AppendLine('}')
$artifactTypeExpected = $artifactTypeBuilder.ToString().Replace("`r`n", "`n")

$builder = [Text.StringBuilder]::new()
[void]$builder.AppendLine('// <auto-generated />')
[void]$builder.AppendLine('// Generated by eng/Generate-DeepProtocolRegistry.ps1. Do not edit by hand.')
[void]$builder.AppendLine('#nullable enable')
[void]$builder.AppendLine()
[void]$builder.AppendLine('namespace Deep.Protocol.Registry;')
[void]$builder.AppendLine()
[void]$builder.AppendLine('public enum ProtocolIdentifierLifecycle')
[void]$builder.AppendLine('{')
foreach ($lifecycle in $registry.lifecycleDefinitions) {
    [void]$builder.AppendLine("    $($lifecycle.name),")
}
[void]$builder.AppendLine('}')
[void]$builder.AppendLine()
[void]$builder.AppendLine('public static class DeepProtocolIdentifiers')
[void]$builder.AppendLine('{')

$normalSuites = @($registry.suites | Where-Object { $_.lifecycle -ne 'RETIRED_REJECT' } | Sort-Object scope,id)
[void]$builder.AppendLine('    public static class Suites')
[void]$builder.AppendLine('    {')
foreach ($entry in $normalSuites) {
    $type = if ($entry.scope -eq 'xpoint-onion-u8') { 'byte' } else { 'ushort' }
    [void]$builder.AppendLine("        public const $type $($entry.symbol) = ($type)$($entry.id);")
}
[void]$builder.AppendLine('    }')
[void]$builder.AppendLine()
Add-ConstClass $builder 'Magic' $normalMagic { param($entry) '"' + (Escape-CSharp $entry.value) + '"' }
[void]$builder.AppendLine('    public static class MagicBytes')
[void]$builder.AppendLine('    {')
foreach ($entry in $normalMagic) {
    [void]$builder.AppendLine("        public static System.ReadOnlySpan<byte> $($entry.symbol) => `"$($entry.value)`"u8;")
}
[void]$builder.AppendLine('    }')
[void]$builder.AppendLine()
Add-ConstClass $builder 'Carriers' @($registry.carriers | Sort-Object id) { param($entry) "(ushort)$($entry.id)" } 'ushort'
Add-ConstClass $builder 'CarrierNames' @($registry.carriers | Sort-Object id) { param($entry) '"' + (Escape-CSharp $entry.canonicalName) + '"' }
Add-ConstClass $builder 'DeploymentProfiles' @($registry.deploymentProfiles | Sort-Object id) { param($entry) "(ushort)$($entry.id)" } 'ushort'
Add-ConstClass $builder 'CallNames' @($registry.callNames | Sort-Object axis,canonicalName) { param($entry) '"' + (Escape-CSharp $entry.canonicalName) + '"' }
Add-ConstClass $builder 'Interfaces' @($registry.interfaces | Sort-Object canonicalName) { param($entry) '"' + (Escape-CSharp $entry.canonicalName) + '"' }
[void]$builder.AppendLine('}')
[void]$builder.AppendLine()
[void]$builder.AppendLine('internal readonly record struct GeneratedRegistryIdentifier(')
[void]$builder.AppendLine('    string Namespace, string CanonicalName, uint? NumericId, ProtocolIdentifierLifecycle Lifecycle);')
[void]$builder.AppendLine()
[void]$builder.AppendLine('internal static class DeepProtocolRegistryGenerated')
[void]$builder.AppendLine('{')
[void]$builder.AppendLine("    internal const string RegistrySha256 = `"$(Get-Sha256Hex $registryBytes)`";")
[void]$builder.AppendLine("    internal const string Dnp1RegistrySha256 = `"$(Get-Sha256Hex $dnpBytes)`";")
[void]$builder.AppendLine("    internal const string Dnp1ApprovedCommit = `"$($binding.Commit)`";")
[void]$builder.AppendLine()
[void]$builder.AppendLine('    internal static GeneratedRegistryIdentifier[] Identifiers { get; } =')
[void]$builder.AppendLine('    [')
foreach ($entry in $normalSuites) {
    [void]$builder.AppendLine("        new(`"suite:$($entry.scope)`", `"$(Escape-CSharp $entry.canonicalName)`", $($entry.id)u, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
foreach ($entry in $normalMagic) {
    [void]$builder.AppendLine("        new(`"magic`", `"$($entry.value)`", null, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
foreach ($entry in $registry.carriers | Sort-Object id) {
    [void]$builder.AppendLine("        new(`"carrier`", `"$(Escape-CSharp $entry.canonicalName)`", $($entry.id)u, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
foreach ($entry in $registry.deploymentProfiles | Sort-Object id) {
    [void]$builder.AppendLine("        new(`"deployment-profile`", `"$(Escape-CSharp $entry.canonicalName)`", $($entry.id)u, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
foreach ($entry in $registry.callNames | Sort-Object axis,canonicalName) {
    [void]$builder.AppendLine("        new(`"call:$($entry.axis)`", `"$(Escape-CSharp $entry.canonicalName)`", null, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
foreach ($entry in $registry.interfaces | Sort-Object canonicalName) {
    [void]$builder.AppendLine("        new(`"interface`", `"$(Escape-CSharp $entry.canonicalName)`", null, ProtocolIdentifierLifecycle.$($entry.lifecycle)),")
}
[void]$builder.AppendLine('    ];')
[void]$builder.AppendLine()
[void]$builder.AppendLine('    internal static string[] Dnp1CanonicalRecordMagic { get; } =')
[void]$builder.AppendLine('    [')
foreach ($magic in $dnp.records | Where-Object {
        $_.PSObject.Properties.Name -notcontains 'framing' -or $_.framing -ne 'fixed-transcript'
    } | ForEach-Object magic | Sort-Object) {
    [void]$builder.AppendLine("        `"$magic`",")
}
[void]$builder.AppendLine('    ];')
[void]$builder.AppendLine()

$artifactIds = @($dnp.artifactTypes | Sort-Object id)
[void]$builder.AppendLine('    internal static bool IsKnownDnp1ArtifactType(ushort value) => value switch')
[void]$builder.AppendLine('    {')
foreach ($entry in $artifactIds) { [void]$builder.AppendLine("        $($entry.id) => true,") }
[void]$builder.AppendLine('        _ => false')
[void]$builder.AppendLine('    };')
[void]$builder.AppendLine()
[void]$builder.AppendLine('    internal static bool IsRetainedDnp1ArtifactType(ushort value) => value switch')
[void]$builder.AppendLine('    {')
foreach ($entry in $artifactIds | Where-Object {
        $_.PSObject.Properties.Name -contains 'retained' -and $_.retained -eq $true
    }) {
    [void]$builder.AppendLine("        $($entry.id) => true,")
}
[void]$builder.AppendLine('        _ => false')
[void]$builder.AppendLine('    };')
[void]$builder.AppendLine()
[void]$builder.AppendLine('    internal static string? GetDnp1ArtifactHashDomain(ushort value) => value switch')
[void]$builder.AppendLine('    {')
foreach ($entry in $artifactIds) {
    $domainProperty = $dnp.artifactHashDomains.PSObject.Properties[$entry.magic]
    if ($null -ne $domainProperty) {
        [void]$builder.AppendLine("        $($entry.id) => `"$(Escape-CSharp ([string]$domainProperty.Value))`",")
    }
}
[void]$builder.AppendLine('        _ => null')
[void]$builder.AppendLine('    };')
[void]$builder.AppendLine()
[void]$builder.AppendLine('    internal static string? GetDnp1ProtectedDomain(string magic) => magic switch')
[void]$builder.AppendLine('    {')
foreach ($magic in $dnp.recordClasses.protectedHmac.records | Sort-Object) {
    $property = $dnp.grammar.protectedHmacDomains.PSObject.Properties[$magic]
    if ($null -eq $property) { throw "Protected DNP1 record has no imported domain: $magic" }
    [void]$builder.AppendLine("        `"$magic`" => `"$(Escape-CSharp ([string]$property.Value))`",")
}
[void]$builder.AppendLine('        _ => null')
[void]$builder.AppendLine('    };')
[void]$builder.AppendLine('}')

$expected = $builder.ToString().Replace("`r`n", "`n")
$policyBuilder = [Text.StringBuilder]::new()
[void]$policyBuilder.AppendLine('// <auto-generated />')
[void]$policyBuilder.AppendLine('// Generated from registry/deep-protocol-v1.resolved.json. Do not edit by hand.')
[void]$policyBuilder.AppendLine()
[void]$policyBuilder.AppendLine('internal static class DeepProtocolRegistryPolicy')
[void]$policyBuilder.AppendLine('{')
[void]$policyBuilder.AppendLine('    internal static readonly string[] AllowedMagic =')
[void]$policyBuilder.AppendLine('    [')
foreach ($record in $resolvedRecords | Where-Object lifecycle -NE 'RETIRED_REJECT' | Sort-Object magic) {
    [void]$policyBuilder.AppendLine("        `"$($record.magic)`",")
}
[void]$policyBuilder.AppendLine('    ];')
[void]$policyBuilder.AppendLine()
[void]$policyBuilder.AppendLine('    internal static readonly string[] RetiredTokens =')
[void]$policyBuilder.AppendLine('    [')
foreach ($entry in $retiredValues | Sort-Object namespace,value) {
    [void]$policyBuilder.AppendLine("        `"$(Escape-CSharp ([string]$entry.value))`",")
}
[void]$policyBuilder.AppendLine('    ];')
[void]$policyBuilder.AppendLine()
[void]$policyBuilder.AppendLine('    internal static readonly string[] NonProtocolFourCharacterLiterals =')
[void]$policyBuilder.AppendLine('    [')
foreach ($entry in $registry.productionInventory.excludedLiterals | Sort-Object value) {
    [void]$policyBuilder.AppendLine("        `"$($entry.value)`",")
}
[void]$policyBuilder.AppendLine('    ];')
[void]$policyBuilder.AppendLine('}')
$graphPolicyExpected = $policyBuilder.ToString().Replace("`r`n", "`n")
if ($Check) {
    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        throw 'Checked-in generated registry source is missing.'
    }
    $actual = [IO.File]::ReadAllText($outputPath).Replace("`r`n", "`n")
    if ($actual -cne $expected) {
        throw 'Checked-in generated registry source is stale. Run eng/Generate-DeepProtocolRegistry.ps1.'
    }
    if (-not (Test-Path -LiteralPath $artifactTypeOutputPath -PathType Leaf)) {
        throw 'Checked-in generated DNP1 ArtifactType is missing.'
    }
    $artifactTypeActual = [IO.File]::ReadAllText($artifactTypeOutputPath).Replace("`r`n", "`n")
    if ($artifactTypeActual -cne $artifactTypeExpected) {
        throw 'Checked-in generated DNP1 ArtifactType is stale. Run eng/Generate-DeepProtocolRegistry.ps1.'
    }
    if (-not (Test-Path -LiteralPath $resolvedRegistryPath -PathType Leaf)) {
        throw 'Checked-in resolved Deep protocol manifest is missing.'
    }
    $resolvedActual = [IO.File]::ReadAllText($resolvedRegistryPath).Replace("`r`n", "`n")
    if ($resolvedActual -cne $resolvedExpected) {
        throw 'Checked-in resolved Deep protocol manifest is stale. Run eng/Generate-DeepProtocolRegistry.ps1.'
    }
    if (-not (Test-Path -LiteralPath $graphPolicyOutputPath -PathType Leaf) -or
        [IO.File]::ReadAllText($graphPolicyOutputPath).Replace("`r`n", "`n") -cne $graphPolicyExpected) {
        throw 'Checked-in production graph registry policy is stale. Run eng/Generate-DeepProtocolRegistry.ps1.'
    }
    Write-Host 'PASS checked-in Deep protocol registry source and resolved manifest are current.'
    return
}

$outputDirectory = Split-Path $outputPath -Parent
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
[IO.File]::WriteAllText($outputPath, $expected, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($artifactTypeOutputPath, $artifactTypeExpected, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($resolvedRegistryPath, $resolvedExpected, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($graphPolicyOutputPath, $graphPolicyExpected, [Text.UTF8Encoding]::new($false))
Write-Host "WROTE $outputPath"
Write-Host "WROTE $artifactTypeOutputPath"
Write-Host "WROTE $resolvedRegistryPath"
Write-Host "WROTE $graphPolicyOutputPath"
