[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Debug',
    [string] $ProfileLockPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$solution = Get-Content -Raw (Join-Path $root 'Deep.Protocol.slnx')
$sourceProjects = [regex]::Matches($solution, 'src/([^/"<\r\n]+)/[^/"<\r\n]+\.csproj') |
    ForEach-Object { $_.Groups[1].Value }
$expected = @('Deep.Protocol', 'Deep.Protocol.MembershipRoutes', 'Deep.Protocol.ProfileCarrier')
if (@($sourceProjects).Count -ne 3 -or
    (@($sourceProjects | Sort-Object) -join '|') -cne (@($expected | Sort-Object) -join '|')) {
    throw 'Production solution source graph is not exact-three.'
}
if ($solution -match 'Native|Abstractions|Protobuf|reference/session-compatibility') {
    throw 'Production solution includes a dark or quarantined project.'
}
foreach ($removedDarkPath in @(
    'Deep.Protocol.Dark.slnx',
    'src/Deep.Protocol.Native/Deep.Protocol.Native.csproj',
    'src/Deep.Protocol.Native/DeepRecoveryV1.cs',
    'tests/Deep.Protocol.Native.Tests/Deep.Protocol.Native.Tests.csproj',
    'tests/Deep.Protocol.Native.Tests/DeepRecoveryV1Tests.cs')) {
    if (Test-Path -LiteralPath (Join-Path $root $removedDarkPath)) {
        throw "Clean-break dark identity path still exists: $removedDarkPath"
    }
}
$projectFiles = Get-ChildItem -LiteralPath $root -Recurse -Filter '*.csproj' -File |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' }
foreach ($projectFile in $projectFiles) {
    if ((Get-Content -Raw -LiteralPath $projectFile.FullName).IndexOf(
        'Deep.Protocol.Native', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "A project still references the removed dark identity package: $($projectFile.FullName)"
    }
}

[xml]$protocolProject = Get-Content -Raw (Join-Path $root 'src/Deep.Protocol/Deep.Protocol.csproj')
$projectReferences = @($protocolProject.SelectNodes('//ProjectReference'))
$packageReferences = @($protocolProject.SelectNodes('//PackageReference'))
if ($projectReferences.Count -ne 0 -or $packageReferences.Count -ne 1 -or
    [string]$packageReferences[0].Include -cne 'Sodium.Core') {
    throw 'Deep.Protocol is not Sodium-only.'
}

$forbidden = @(
    'Deep.Protocol.Abstractions', 'Deep.Protocol.Protobuf', 'Google.Protobuf',
    'Deep.Protocol.Native', 'SessionProtos', 'WebSocketProtos',
    'CompatibilityEnvelope', 'OpaqueBundle', 'NearbyHandshake',
    'NearbySecureChannel', 'LoRaFragment', 'DPE1', 'DPB1')
$productionFiles = @(
    'src/Deep.Protocol', 'src/Deep.Protocol.MembershipRoutes', 'src/Deep.Protocol.ProfileCarrier' |
    ForEach-Object { Get-ChildItem (Join-Path $root $_) -Recurse -File } |
    Where-Object {
        $_.Extension -in @('.cs', '.csproj', '.md') -and
        $_.FullName -notmatch '[\\/](bin|obj)[\\/]'
    })
$resolvedRegistry = Get-Content -Raw (Join-Path $root 'registry/deep-protocol-v1.resolved.json') |
    ConvertFrom-Json
$retiredRegistryTokens = @($resolvedRegistry.retiredValues.value)
foreach ($file in $productionFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    if ($null -eq $text) { continue }
    foreach ($token in $forbidden) {
        if ($text.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Production source contains quarantined token '$token': $($file.FullName)"
        }
    }
    if ($file.FullName -notmatch '[\\/]Generated[\\/]') {
        foreach ($token in $retiredRegistryTokens) {
            $pattern = '(?<![A-Za-z0-9_-])' + [regex]::Escape([string]$token) + '(?![A-Za-z0-9_-])'
            if ([regex]::IsMatch($text, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
                throw "Production source contains retired registry token '$token': $($file.FullName)"
            }
        }
    }
}

$lockPaths = @(
    'src/Deep.Protocol/packages.lock.json',
    'src/Deep.Protocol.MembershipRoutes/packages.lock.json',
    'tests/Deep.Protocol.GoldenVectors/packages.lock.json',
    'tests/Deep.Protocol.Tests/packages.lock.json',
    'tests/Deep.Protocol.MembershipRoutes.Tests/packages.lock.json')
if (-not [string]::IsNullOrWhiteSpace($ProfileLockPath)) {
    $lockPaths += (Resolve-Path -LiteralPath $ProfileLockPath).Path
}
foreach ($relative in $lockPaths) {
    $path = if ([IO.Path]::IsPathRooted($relative)) { $relative } else { Join-Path $root $relative }
    $text = Get-Content -Raw -LiteralPath $path
    foreach ($token in $forbidden) {
        if ($text.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Lock graph contains quarantined dependency '$token': $path"
        }
    }
}

$assemblies = @{
    'protocol-assembly' = Join-Path $root "src/Deep.Protocol/bin/$Configuration/net10.0/Deep.Protocol.dll"
    'routes-assembly' = Join-Path $root "src/Deep.Protocol.MembershipRoutes/bin/$Configuration/net10.0/Deep.Protocol.MembershipRoutes.dll"
    'carrier-assembly' = Join-Path $root "src/Deep.Protocol.ProfileCarrier/bin/$Configuration/net10.0/Deep.Protocol.ProfileCarrier.dll"
    'golden-assembly' = Join-Path $root "tests/Deep.Protocol.GoldenVectors/bin/$Configuration/net10.0/Deep.Protocol.GoldenVectors.dll"
}
foreach ($path in $assemblies.Values) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Built assembly missing: $path" }
}
$protocolAssemblyText = [Text.Encoding]::UTF8.GetString(
    [IO.File]::ReadAllBytes($assemblies['protocol-assembly']))
foreach ($requiredIdentityToken in @(
    'Deep.Protocol.Identity',
    'DeepRecoveryV1',
    'DeepRecoveryAccountCapabilities',
    'Deep.Protocol.Identity.Resources.Bip39.english.txt')) {
    if ($protocolAssemblyText.IndexOf($requiredIdentityToken, [StringComparison]::Ordinal) -lt 0) {
        throw "Production protocol assembly lacks identity token/resource '$requiredIdentityToken'."
    }
}
$outputDirectories = @(
    (Join-Path $root "src/Deep.Protocol/bin/$Configuration/net10.0"),
    (Join-Path $root "src/Deep.Protocol.MembershipRoutes/bin/$Configuration/net10.0"),
    (Join-Path $root "src/Deep.Protocol.ProfileCarrier/bin/$Configuration/net10.0"))
foreach ($directory in $outputDirectories) {
    foreach ($file in Get-ChildItem -LiteralPath $directory -File) {
        foreach ($token in $forbidden) {
            if ($file.Name.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "Build output contains quarantined artifact '$($file.Name)'."
            }
            if ($file.Extension -ceq '.json' -and
                (Get-Content -Raw -LiteralPath $file.FullName).IndexOf(
                    $token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "Build dependency/resource manifest contains '$token': $($file.FullName)"
            }
        }
    }
}
dotnet run --project (Join-Path $root 'eng/Dnp1ProductionGraph.Identity/Dnp1ProductionGraph.Identity.csproj') -- `
    --protocol-assembly $assemblies['protocol-assembly'] `
    --routes-assembly $assemblies['routes-assembly'] `
    --carrier-assembly $assemblies['carrier-assembly'] `
    --golden-assembly $assemblies['golden-assembly']
if ($LASTEXITCODE -ne 0) { throw 'Actual assembly/resource/public API graph validation failed.' }

Write-Output 'PASS exact-three production source/build/lock graph'
