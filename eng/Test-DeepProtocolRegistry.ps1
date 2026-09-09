[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$superprojectRoot = Split-Path $repoRoot -Parent
$registryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.json'
$schemaPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.schema.json'
$resolvedRegistryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.resolved.json'
$resolvedSchemaPath = Join-Path $repoRoot 'registry/deep-protocol-v1.resolved.schema.json'
$normativeRoot = Join-Path $superprojectRoot 'docs/survival-program/releases/v3.0.0/specs'

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Unique {
    param([object[]] $Values, [string] $Name, [switch] $CaseInsensitive)
    $normalized = if ($CaseInsensitive) {
        @($Values | ForEach-Object { ([string]$_).ToLowerInvariant() })
    }
    else { @($Values) }
    $duplicates = @($normalized | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    if ($duplicates.Count -ne 0) { throw "$Name collision: $($duplicates -join ', ')" }
}

function Copy-JsonObject {
    param([Parameter(Mandatory)] [object] $Value)
    return ($Value | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json
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
    param([Parameter(Mandatory)] [object] $Configuration)
    $map = [Collections.Generic.Dictionary[string, Collections.Generic.HashSet[string]]]::new(
        [StringComparer]::Ordinal)
    $manualLiterals = [Collections.Generic.Dictionary[string, Collections.Generic.HashSet[string]]]::new(
        [StringComparer]::Ordinal)
    foreach ($assembly in $Configuration.assemblies) {
        $assemblyRoot = Join-Path $repoRoot "src/$assembly"
        foreach ($file in Get-ChildItem -LiteralPath $assemblyRoot -Filter '*.cs' -File -Recurse) {
            if ($file.FullName -match '[\\/]Generated[\\/]' -or
                $file.Name.EndsWith('.Generated.cs', [StringComparison]::Ordinal)) { continue }
            $relative = [IO.Path]::GetRelativePath($repoRoot, $file.FullName).Replace('\', '/')
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

function Assert-SchemaRejects {
    param([Parameter(Mandatory)] [object] $Value, [Parameter(Mandatory)] [string] $Case)
    $json = $Value | ConvertTo-Json -Depth 100 -Compress
    $accepted = Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue
    if ($accepted) { throw "Registry schema accepted invalid boundary case: $Case" }
}

& (Join-Path $PSScriptRoot 'Generate-DeepProtocolRegistry.ps1') -Check
if ($LASTEXITCODE -ne 0) { throw 'Generated registry check failed.' }

Assert-True (Test-Json -LiteralPath $registryPath -SchemaFile $schemaPath -ErrorAction Stop) `
    'Registry does not satisfy its strict schema.'
$registry = Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json
Assert-True (Test-Json -LiteralPath $resolvedRegistryPath -SchemaFile $resolvedSchemaPath -ErrorAction Stop) `
    'Resolved registry does not satisfy its strict schema.'
$resolved = Get-Content -LiteralPath $resolvedRegistryPath -Raw | ConvertFrom-Json
Assert-True ($resolved.registryGeneration -eq $registry.registryGeneration) `
    'Resolved registry generation differs from its source registry.'
Assert-True ($resolved.sourceRegistrySha256 -ceq (Get-Sha256Hex ([IO.File]::ReadAllBytes($registryPath)))) `
    'Resolved registry source digest is stale.'

$expectedLifecycle = @(
    'FROZEN_TARGET_NOT_ACTIVE', 'CURRENT_PRE_CUTOVER', 'TARGET_UNFROZEN',
    'TARGET_RENAME_REQUIRED', 'DECISION_REQUIRED', 'RESERVED',
    'RETIRED_REJECT', 'RELEASE_ACTIVE'
)
Assert-Unique @($registry.lifecycleDefinitions.name) 'lifecycle'
Assert-True (@(Compare-Object $expectedLifecycle @($registry.lifecycleDefinitions.name)).Count -eq 0) `
    'Lifecycle registry is not the exact closed set.'
foreach ($item in $registry.lifecycleDefinitions) {
    Assert-True ($item.canReleaseEncode -eq ($item.name -eq 'RELEASE_ACTIVE')) `
        "Lifecycle release-encoder policy is invalid for $($item.name)."
}

Assert-Unique @($registry.sources.id) 'source id'
$sourceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($source in $registry.sources) {
    [void]$sourceIds.Add($source.id)
    $sourcePath = Join-Path $superprojectRoot $source.path
    if ($source.kind -eq 'production-source-scan') {
        Assert-True (Test-Path -LiteralPath $sourcePath -PathType Container) `
            "Registry production source root is missing: $($source.path)"
    }
    else {
        Assert-True (Test-Path -LiteralPath $sourcePath -PathType Leaf) `
            "Registry source is missing: $($source.path)"
        Assert-True ((Get-NormalizedTextSha256 $sourcePath) -ceq $source.normalizedSha256) `
            "Registry source digest is stale: $($source.path)"
    }
}

$usedSources = @(
    $registry.lifecycleDefinitions.sourceId
    $registry.imports.sourceId
    $registry.suiteScopes.sourceId
    $registry.suites.sourceId
    $registry.magic.sourceId
    $registry.carriers.sourceId
    $registry.deploymentProfiles.sourceId
    $registry.callNames.sourceId
    $registry.interfaces.sourceId
    $registry.retiredAliases.sourceId
    @($registry.sources | Where-Object kind -EQ 'production-source-scan').id
)
foreach ($sourceId in $usedSources) {
    Assert-True ($sourceIds.Contains($sourceId)) "Unknown sourceId: $sourceId"
}
foreach ($sourceId in $sourceIds) {
    Assert-True ($usedSources -ccontains $sourceId) "Unused registry source: $sourceId"
}

. (Join-Path $PSScriptRoot 'Dnp1NormativeBinding.ps1')
$import = @($registry.imports)[0]
$binding = Get-Dnp1ApprovedNormativeBinding -NormativeRoot $normativeRoot `
    -ExpectedNormativeCommit $import.approvedCommit `
    -Names @($import.registry.path, $import.schema.path)
$dnp = Get-Content -LiteralPath (Join-Path $normativeRoot $import.registry.path) -Raw | ConvertFrom-Json

Assert-Unique @($dnp.artifactTypes.id) 'DNP1 artifact id'
Assert-Unique @($dnp.artifactTypes.magic) 'DNP1 artifact magic' -CaseInsensitive
Assert-Unique @($dnp.records.magic) 'DNP1 record magic' -CaseInsensitive
$importedMagic = @(
    $dnp.artifactTypes | Where-Object magic -Match '^[A-Z0-9]{4}$' | ForEach-Object magic
    $dnp.records.magic
) | Sort-Object -Unique
$localMagic = @($registry.magic.value)
Assert-Unique $localMagic 'local magic' -CaseInsensitive
$crossFeed = @($localMagic | Where-Object { $importedMagic -ccontains $_ })
Assert-True ($crossFeed.Count -eq 0) "Local magic collides with frozen DNP1: $($crossFeed -join ', ')"

$inventory = Get-ProductionWireInventory $registry.productionInventory
$productionSource = @($registry.sources | Where-Object kind -EQ 'production-source-scan')
Assert-True ($productionSource.Count -eq 1) 'Registry must define exactly one production source scan.'
Assert-True ($inventory.Sha256 -ceq $productionSource[0].normalizedSha256) `
    'Production wire allocation source digest is stale.'
$allAllocatedMagic = @($importedMagic + $localMagic | Sort-Object -Unique)
$excludedLiterals = @($registry.productionInventory.excludedLiterals.value)
foreach ($value in $inventory.ManualLiterals.Keys) {
    $paths = @($inventory.ManualLiterals[$value] | Sort-Object)
    if ($excludedLiterals -ccontains $value) { continue }
    Assert-True ($allAllocatedMagic -cnotcontains $value) `
        "Production source hand-authors registered magic $value instead of ProtocolMagic API: $($paths -join ', ')"
    throw "Production source contains an unregistered four-character protocol literal $value`: $($paths -join ', ')"
}
$unregisteredProductionMagic = @($inventory.Map.Keys | Where-Object { $allAllocatedMagic -cnotcontains $_ })
Assert-True ($unregisteredProductionMagic.Count -eq 0) `
    "Production wire magic is absent from the global registry: $($unregisteredProductionMagic -join ', ')"
foreach ($entry in $registry.magic | Where-Object lifecycle -EQ 'CURRENT_PRE_CUTOVER') {
    Assert-True ($inventory.Map.Contains($entry.value)) `
        "CURRENT_PRE_CUTOVER magic has no production implementation: $($entry.value)"
}
foreach ($entry in $registry.magic | Where-Object { $inventory.Map.Contains($_.value) }) {
    Assert-True ($entry.lifecycle -in @(
            'CURRENT_PRE_CUTOVER',
            'FROZEN_TARGET_NOT_ACTIVE',
            'TARGET_UNFROZEN')) `
        "Implemented local magic has no implemented-but-release-gated lifecycle: $($entry.value)"
}
foreach ($entry in $registry.magic | Where-Object lifecycle -EQ 'RETIRED_REJECT') {
    Assert-True (-not $inventory.Map.Contains($entry.value)) `
        "RETIRED_REJECT magic remains accepted by production source: $($entry.value)"
}
$expectedRetiredValues = @(
    $registry.magic | Where-Object lifecycle -EQ 'RETIRED_REJECT' | ForEach-Object value
    $registry.suites | Where-Object lifecycle -EQ 'RETIRED_REJECT' | ForEach-Object canonicalName
    $registry.retiredAliases | ForEach-Object alias
) | Sort-Object
Assert-True ((@($resolved.retiredValues.value | Sort-Object) -join "`n") -ceq ($expectedRetiredValues -join "`n")) `
    'Resolved retired deny-list differs from actual RETIRED_REJECT allocations and aliases.'
$expectedPlannedRetirements = @($registry.magic | Where-Object {
        $_.lifecycle -eq 'CURRENT_PRE_CUTOVER' -and
        $_.PSObject.Properties.Name -contains 'targetLifecycle' -and $_.targetLifecycle -eq 'RETIRED_REJECT'
    } | ForEach-Object value | Sort-Object)
Assert-True ((@($resolved.plannedRetirements.value | Sort-Object) -join "`n") -ceq
    ($expectedPlannedRetirements -join "`n")) `
    'Planned retirements are conflated with the active retired deny-list.'
Assert-Unique @($registry.productionInventory.excludedLiterals.value) 'excluded production literal'
foreach ($literal in $registry.productionInventory.excludedLiterals) {
    Assert-True ($inventory.ManualLiterals.ContainsKey([string]$literal.value)) `
        "Excluded non-protocol literal is stale: $($literal.value)"
}
foreach ($collision in $registry.productionInventory.knownCrossNamespaceCollisions) {
    Assert-True ($importedMagic -ccontains $collision.value) `
        "Known cross-namespace collision is not owned by frozen DNP1: $($collision.value)"
    Assert-True ($localMagic -ccontains $collision.replacement) `
        "Known cross-namespace collision replacement is not allocated: $($collision.replacement)"
    $paths = @($inventory.Map[$collision.value])
    Assert-True (@($paths | Where-Object { $_.StartsWith($collision.runtimePrefix, [StringComparison]::Ordinal) }).Count -gt 0) `
        "Known cross-namespace collision runtime path is stale: $($collision.value)"
}

$expectedScopes = [ordered]@{
    'dnp1-header-u16' = 16
    'pairwise-messaging-u16' = 16
    'xpoint-onion-u8' = 8
}
Assert-Unique @($registry.suiteScopes.name) 'suite scope'
Assert-True ($registry.suiteScopes.Count -eq $expectedScopes.Count) 'Suite scope registry is not the exact closed set.'
foreach ($scope in $registry.suiteScopes) {
    Assert-True ($expectedScopes.Contains($scope.name)) "Unknown suite scope: $($scope.name)"
    Assert-True ([int]$scope.widthBits -eq [int]$expectedScopes[$scope.name]) `
        "Suite scope width is invalid: $($scope.name)"
}

$sourceAnchoredAllocations = @(
    $registry.suites | Where-Object sourceId -NE 'dnp1-frozen'
    $registry.magic | Where-Object sourceId -NE 'production-wire-source'
    $registry.carriers
    $registry.deploymentProfiles
    $registry.callNames
    $registry.interfaces
    $registry.retiredAliases
)
Assert-True (@($sourceAnchoredAllocations | Where-Object { $null -eq $_.sourceAnchor }).Count -eq 0) `
    'A non-imported allocation lacks its exact structured source anchor.'

$protocolRegistryLines = [IO.File]::ReadAllText(
    (Join-Path $superprojectRoot 'docs/architecture/PROTOCOL-REGISTRY-V1.md')).Replace("`r`n", "`n").Split("`n")
foreach ($entry in @($sourceAnchoredAllocations | Where-Object {
        $_.sourceAnchor.anchorSourceId -eq 'protocol-registry-v1' -and
        $_.sourceAnchor.scope -notlike 'alias:*'
    })) {
    $anchor = $entry.sourceAnchor
    Assert-True ([int]$anchor.startLine -eq [int]$anchor.endLine) `
        "Protocol-registry allocation anchor must be one canonical table row: $($anchor.scope)/$($anchor.id)"
    $row = $protocolRegistryLines[[int]$anchor.startLine - 1]
    $rowMatches = switch -Wildcard ([string]$anchor.scope) {
        'magic' { $row -match "^\|[^|]*``$([regex]::Escape([string]$anchor.id))``[^|]*\|"; break }
        'suite:*' {
            $id = ([string]$anchor.id).Split(':')[-1]
            $row -match "^\|\s*``$([regex]::Escape($id))``\s*\|"; break
        }
        'carrier' { $row -match "^\|\s*``$([regex]::Escape([string]$anchor.id))``\s*\|"; break }
        'deployment-profile' { $row -match "^\|\s*``$([regex]::Escape([string]$anchor.id))``\s*\|"; break }
        'call:*' {
            $axis = [regex]::Escape($anchor.scope.Substring(5).Replace('-', ' '))
            $name = [regex]::Escape([string]$anchor.name)
            $row -match "^\|\s*$axis\s*\|\s*``$name``\s*\|"; break
        }
        'interface' { $row -match "^\|\s*``$([regex]::Escape([string]$anchor.name))``\s*\|"; break }
        default { throw "Unhandled protocol-registry anchor scope: $($anchor.scope)" }
    }
    Assert-True $rowMatches "Protocol-registry anchor does not bind its canonical table row: $($anchor.scope)/$($anchor.id)"
}

foreach ($assembly in $registry.productionInventory.assemblies) {
    $aliasPath = Join-Path $repoRoot "src/$assembly/ProtocolRegistryAliases.cs"
    $aliasText = [IO.File]::ReadAllText($aliasPath).Replace("`r`n", "`n")
    Assert-True ($aliasText -ceq
        "global using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;`n" +
        "global using ProtocolMagicBytes = Deep.Protocol.Registry.DeepProtocolIdentifiers.MagicBytes;`n") `
        "Production assembly does not use the exact registry magic aliases: $assembly"
}

foreach ($group in $registry.suites | Group-Object scope) {
    Assert-Unique @($group.Group.id) "suite id in $($group.Name)"
    Assert-Unique @($group.Group.canonicalName) "suite name in $($group.Name)" -CaseInsensitive
}
Assert-Unique @($registry.carriers.id) 'carrier id'
Assert-Unique @($registry.carriers.canonicalName) 'carrier name' -CaseInsensitive
Assert-Unique @($registry.deploymentProfiles.id) 'deployment profile id'
Assert-Unique @($registry.deploymentProfiles.canonicalName) 'deployment profile name' -CaseInsensitive
foreach ($group in $registry.callNames | Group-Object axis) {
    Assert-Unique @($group.Group.canonicalName) "call name in $($group.Name)" -CaseInsensitive
}
Assert-Unique @($registry.interfaces.canonicalName) 'interface name' -CaseInsensitive
$allSymbols = @(
    $registry.suites.symbol
    $registry.magic.symbol
    $registry.carriers.symbol
    $registry.deploymentProfiles.symbol
    $registry.callNames.symbol
    $registry.interfaces.symbol
)
Assert-Unique $allSymbols 'generated C# symbol' -CaseInsensitive
$allCanonicalNames = @(
    $registry.suites.canonicalName
    $registry.carriers.canonicalName
    $registry.deploymentProfiles.canonicalName
    $registry.callNames.canonicalName
    $registry.interfaces.canonicalName
)
Assert-Unique $allCanonicalNames 'global canonical name' -CaseInsensitive

$canonicalByNamespace = @{
    carrier = @($registry.carriers.canonicalName)
    call = @($registry.callNames.canonicalName)
    interface = @($registry.interfaces.canonicalName)
}
foreach ($group in $registry.retiredAliases | Group-Object namespace) {
    Assert-Unique @($group.Group.alias) "retired alias in $($group.Name)" -CaseInsensitive
}
foreach ($alias in $registry.retiredAliases) {
    $canonical = @($canonicalByNamespace[$alias.namespace])
    Assert-True (-not ($canonical -icontains $alias.alias)) `
        "Retired alias is accepted as canonical: $($alias.alias)"
    Assert-True ($canonical -ccontains $alias.replacement) `
        "Retired alias replacement is not canonical: $($alias.replacement)"
}

$mutation = Copy-JsonObject $registry
($mutation.suites | Where-Object scope -EQ 'xpoint-onion-u8' | Select-Object -First 1).id = 256
Assert-SchemaRejects $mutation 'u8 suite max+1'
$mutation = Copy-JsonObject $registry
($mutation.suites | Where-Object scope -EQ 'dnp1-header-u16' | Select-Object -First 1).id = 65536
Assert-SchemaRejects $mutation 'u16 suite max+1'
$mutation = Copy-JsonObject $registry
$mutation.carriers[0].id = 65536
Assert-SchemaRejects $mutation 'carrier max+1'
$mutation = Copy-JsonObject $registry
$mutation.deploymentProfiles[0].id = 65536
Assert-SchemaRejects $mutation 'deployment profile max+1'
$mutation = Copy-JsonObject $registry
$mutation.magic[0].value = 'MAXP1'
Assert-SchemaRejects $mutation 'magic length max+1'
$mutation = Copy-JsonObject $registry
$mutation.suiteScopes[0].widthBits = 8
Assert-SchemaRejects $mutation 'dnp1 scope wrong width'
$mutation = Copy-JsonObject $registry
$mutation.suiteScopes += Copy-JsonObject $mutation.suiteScopes[0]
Assert-SchemaRejects $mutation 'suite scope duplicate/max+1'
$mutation = Copy-JsonObject $registry
($mutation.magic | Where-Object {
        $_.PSObject.Properties.Name -contains 'targetLifecycle' -and $_.targetLifecycle -eq 'RETIRED_REJECT'
    } | Select-Object -First 1).lifecycle = 'TARGET_UNFROZEN'
Assert-SchemaRejects $mutation 'target retirement without current pre-cutover lifecycle'
$mutation = Copy-JsonObject $registry
$mutation.carriers[0].sourceAnchor.PSObject.Properties.Remove('scope')
Assert-SchemaRejects $mutation 'structured source anchor missing scope'
$mutation = Copy-JsonObject $registry
$mutation.carriers[0].sourceAnchor | Add-Member -NotePropertyName unreviewed -NotePropertyValue $true
Assert-SchemaRejects $mutation 'structured source anchor additional property'

Assert-Unique @($resolved.records.magic) 'resolved record magic' -CaseInsensitive
Assert-True (@($resolved.records.magic).Count -eq @($resolved.records).Count) `
    'Resolved records contain a duplicate magic.'
$missingResolvedProduction = @($inventory.Map.Keys | Where-Object { $resolved.records.magic -cnotcontains $_ })
Assert-True ($missingResolvedProduction.Count -eq 0) `
    "Resolved manifest omits production records: $($missingResolvedProduction -join ', ')"
foreach ($record in $resolved.records | Where-Object contractState -EQ 'frozen-exact') {
    Assert-True ($null -ne $record.version -and $null -ne $record.grammar -and
        $null -ne $record.suiteNamespace -and $null -ne $record.minBytes -and
        $null -ne $record.maxBytes -and $null -eq $record.contractBlocker) `
        "Frozen resolved record is incomplete: $($record.magic)"
}
foreach ($record in $resolved.records | Where-Object {
        $_.contractState -ne 'frozen-exact' -and $_.lifecycle -ne 'RETIRED_REJECT'
    }) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($record.contractBlocker)) `
        "Unfrozen/source-bound record hides its contract blocker: $($record.magic)"
}

$artifactModelPath = Join-Path $repoRoot 'src/Deep.Protocol/Generated/Dnp1ArtifactType.Generated.cs'
$artifactSource = Get-Content -LiteralPath $artifactModelPath -Raw
$enumMatch = [regex]::Match($artifactSource, 'public enum ArtifactType : ushort\s*\{(?<body>.*?)\}', 'Singleline')
Assert-True $enumMatch.Success 'Cannot find production ArtifactType enum.'
$productionArtifacts = @{}
foreach ($match in [regex]::Matches($enumMatch.Groups['body'].Value, '(?<name>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?<id>[0-9]+)')) {
    $productionArtifacts[[int]$match.Groups['id'].Value] = $match.Groups['name'].Value
}
foreach ($artifact in $dnp.artifactTypes) {
    $expectedName = if ($artifact.magic -eq 'D-G-SOURCE') { 'DgSource' } else {
        $artifact.magic.Substring(0, 1) + $artifact.magic.Substring(1).ToLowerInvariant()
    }
    Assert-True ($productionArtifacts.ContainsKey([int]$artifact.id)) `
        "Production ArtifactType omits frozen id $($artifact.id)."
    Assert-True ($productionArtifacts[[int]$artifact.id] -ceq $expectedName) `
        "Production ArtifactType id $($artifact.id) is not frozen $expectedName."
}
Assert-True ($productionArtifacts.Count -eq @($dnp.artifactTypes).Count) `
    'Production ArtifactType contains a non-frozen identifier.'
$maximumArtifactId = [int](($dnp.artifactTypes.id | Measure-Object -Maximum).Maximum)
Assert-True (-not $productionArtifacts.ContainsKey($maximumArtifactId + 1)) `
    'Production ArtifactType accepts frozen max+1.'

$definitionsPath = Join-Path $repoRoot 'src/Deep.Protocol/DeepNative/Dnp1RecordDefinitions.cs'
$definitions = Get-Content -LiteralPath $definitionsPath -Raw
foreach ($magic in $dnp.records | Where-Object {
        $_.PSObject.Properties.Name -notcontains 'framing' -or $_.framing -ne 'fixed-transcript'
    } | ForEach-Object magic) {
    Assert-True ($definitions.Contains("ProtocolMagic.$magic", [StringComparison]::Ordinal)) `
        "RecordDefinitions does not consume generated magic $magic."
}
Assert-True (-not [regex]::IsMatch($definitions, '(Public|Unsigned|Protected)\("[A-Z0-9]{4}"')) `
    'RecordDefinitions contains a hand-authored constructor magic.'
Assert-True (-not [regex]::IsMatch($definitions, 'case\s+"[A-Z0-9]{4}"')) `
    'RecordDefinitions contains a hand-authored switch magic.'

$artifactRegistryPath = Join-Path $repoRoot 'src/Deep.Protocol/DeepNative/Dnp1ArtifactRegistry.cs'
$artifactRegistry = Get-Content -LiteralPath $artifactRegistryPath -Raw
Assert-True ($artifactRegistry.Contains('DeepProtocolRegistryGenerated', [StringComparison]::Ordinal)) `
    'ArtifactRegistry does not consume generated DNP1 registry data.'
Assert-True (-not [regex]::IsMatch($artifactRegistry, 'const ushort\s+\w+\s*=\s*0x[0-9a-fA-F]+')) `
    'ArtifactRegistry contains a hand-authored suite id.'

$summary = ("PASS Deep protocol registry: {0} frozen DNP1 artifacts, {1} imported/local magics, " +
    "{2} suites, {3} carriers, {4} deployment profiles, {5} retired aliases.") -f
    @($dnp.artifactTypes).Count, (@($importedMagic).Count + $localMagic.Count),
    @($registry.suites).Count, @($registry.carriers).Count,
    @($registry.deploymentProfiles).Count, @($registry.retiredAliases).Count
Write-Host $summary
