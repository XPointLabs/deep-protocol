[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [string]$OutputPath,

    [switch]$Check,

    [switch]$AllowDirtyManifest,

    [switch]$AllowIncompleteEvidence,

    [string]$WindowsArm64AcceptancePath,

    [string]$AndroidArm64AcceptancePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repositoryRoot 'src\Deep.Protocol\MessagingCrypto\DeepMlKemApprovedAssets.Generated.cs'
}

$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
$manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1) {
    throw 'Unsupported Deep ML-KEM build-manifest schema.'
}
if ([bool]$manifest.deepSources.repositoryDirty -and -not $AllowDirtyManifest) {
    throw 'Approved ML-KEM assets cannot be generated from dirty build evidence.'
}
if ($AllowIncompleteEvidence -and -not $Check) {
    throw 'Incomplete ML-KEM evidence can only be used for a generated-file diff check.'
}
foreach ($sourceGate in @(
        'headRecheckedBeforeManifest',
        'repositoryStateRecheckedBeforeManifest',
        'exactBuildInputClosureRechecked',
        'managedRestoreLocked',
        'managedArtifactsIsolatedOrCleaned')) {
    if (-not [bool]$manifest.deepSources.$sourceGate) {
        throw "The ML-KEM manifest lacks source-evidence gate '$sourceGate'."
    }
}

$providerIdentifier = [string]$manifest.configuration.providerIdentifier
if ($providerIdentifier -notmatch '^[a-z0-9][a-z0-9._/-]{7,127}$') {
    throw 'The ML-KEM manifest does not contain an exact providerIdentifier.'
}

$targetMap = [ordered]@{
    'windows-x64' = [ordered]@{
        property = 'WindowsX64'
        rid = 'win-x64'
        relativePath = 'runtimes/win-x64/native/deep_mlkem.dll'
    }
    'windows-arm64' = [ordered]@{
        property = 'WindowsArm64'
        rid = 'win-arm64'
        relativePath = 'runtimes/win-arm64/native/deep_mlkem.dll'
    }
}
if (-not [string]::IsNullOrWhiteSpace($AndroidArm64AcceptancePath)) {
    $targetMap['android-arm64'] = [ordered]@{
        property = 'AndroidArm64'
        rid = 'android-arm64'
        relativePath = 'runtimes/android-arm64/native/libdeep_mlkem.so'
    }
}

$approved = @()
foreach ($target in $targetMap.Keys) {
    $matches = @($manifest.artifacts | Where-Object {
            [string]$_.target -ceq $target -and [string]$_.role -ceq 'shared-runtime'
        })
    if ($matches.Count -eq 0) { continue }
    if ($matches.Count -ne 1) {
        throw "Expected one shared-runtime artifact for $target."
    }
    $artifact = $matches[0]
    $requiredGates = @('exactExportSurface', 'finalRuntimeHardening')
    if ($target -ceq 'windows-x64') {
        $requiredGates += @(
            'nativeTestsExecuted',
            'managedProbeExecuted',
            'productionWrapperProbeExecuted')
    }
    if (-not $AllowIncompleteEvidence) {
        $requiredGates += 'cleanDistinctPathRebuildMatched'
    }
    foreach ($gate in $requiredGates) {
        if (-not [bool]$artifact.$gate) {
            throw "Artifact $target lacks required evidence '$gate'."
        }
    }
    $sha256 = [string]$artifact.sha256
    if ($sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Artifact $target has an invalid SHA-256 value."
    }
    $bytes = [long]$artifact.bytes
    if ($bytes -le 0) {
        throw "Artifact $target has an invalid byte length."
    }
    if ($target -ceq 'windows-arm64') {
        if ([string]::IsNullOrWhiteSpace($WindowsArm64AcceptancePath)) {
            throw 'Windows arm64 approval requires supplemental physical acceptance evidence.'
        }
        $acceptancePath = (Resolve-Path -LiteralPath $WindowsArm64AcceptancePath -ErrorAction Stop).Path
        $acceptance = Get-Content -LiteralPath $acceptancePath -Raw | ConvertFrom-Json
        $acceptedManifestPath = Join-Path (Split-Path -Parent $acceptancePath) 'build-manifest.v1.json'
        $acceptedManifestPath = (Resolve-Path -LiteralPath $acceptedManifestPath -ErrorAction Stop).Path
        $acceptedManifestSha256 = (Get-FileHash -LiteralPath $acceptedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $acceptedManifest = Get-Content -LiteralPath $acceptedManifestPath -Raw | ConvertFrom-Json
        $acceptedArtifacts = @($acceptedManifest.artifacts | Where-Object {
                [string]$_.target -ceq 'windows-arm64' -and
                [string]$_.role -ceq 'shared-runtime'
            })
        if ([string]$acceptance.schema -cne 'deep/windows-arm64-mlkem-acceptance/v1' -or
            [string]$acceptance.authority -cne 'Mr. X' -or
            [string]$acceptance.buildManifestSha256 -cne $acceptedManifestSha256 -or
            [string]$acceptance.sourceCommit -cne [string]$acceptedManifest.deepSources.repositoryCommit -or
            $acceptedArtifacts.Count -ne 1 -or
            [string]$acceptedArtifacts[0].sha256 -cne $sha256 -or
            [long]$acceptedArtifacts[0].bytes -ne $bytes -or
            -not [bool]$acceptedArtifacts[0].cleanDistinctPathRebuildMatched -or
            -not [bool]$acceptedArtifacts[0].exactExportSurface -or
            -not [bool]$acceptedArtifacts[0].finalRuntimeHardening -or
            [string]$acceptance.runtimeSha256 -cne $sha256 -or
            [long]$acceptance.runtimeBytes -ne $bytes -or
            [string]$acceptance.processRid -cne 'win-arm64' -or
            [string]$acceptance.gates.managedAbiKat -cne 'passed' -or
            [string]$acceptance.gates.productionWrapperProbe -cne 'passed') {
            throw 'Windows arm64 supplemental physical acceptance evidence is incomplete or does not bind the official artifact.'
        }
    }
    if ($target -ceq 'android-arm64') {
        $acceptancePath = (Resolve-Path -LiteralPath $AndroidArm64AcceptancePath -ErrorAction Stop).Path
        $acceptance = Get-Content -LiteralPath $acceptancePath -Raw | ConvertFrom-Json
        $acceptedManifestPath = Join-Path (Split-Path -Parent $acceptancePath) 'build-manifest.v1.json'
        $acceptedManifestPath = (Resolve-Path -LiteralPath $acceptedManifestPath -ErrorAction Stop).Path
        $acceptedManifestSha256 = (Get-FileHash -LiteralPath $acceptedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $acceptedManifest = Get-Content -LiteralPath $acceptedManifestPath -Raw | ConvertFrom-Json
        $acceptedArtifacts = @($acceptedManifest.artifacts | Where-Object {
                [string]$_.target -ceq 'android-arm64' -and
                [string]$_.role -ceq 'shared-runtime'
            })
        if ([string]$acceptance.schema -cne 'deep/android-arm64-mlkem-acceptance/v1' -or
            [string]$acceptance.authority -cne 'Mr. X' -or
            [string]$acceptance.buildManifestSha256 -cne $acceptedManifestSha256 -or
            [string]$acceptance.sourceCommit -cne [string]$acceptedManifest.deepSources.repositoryCommit -or
            $acceptedArtifacts.Count -ne 1 -or
            [string]$acceptedArtifacts[0].sha256 -cne $sha256 -or
            [long]$acceptedArtifacts[0].bytes -ne $bytes -or
            -not [bool]$acceptedArtifacts[0].cleanDistinctPathRebuildMatched -or
            -not [bool]$acceptedArtifacts[0].exactExportSurface -or
            -not [bool]$acceptedArtifacts[0].finalRuntimeHardening -or
            [string]$acceptance.runtimeSha256 -cne $sha256 -or
            [long]$acceptance.runtimeBytes -ne $bytes -or
            [string]$acceptance.processRid -cne 'android-arm64' -or
            [string]$acceptance.gates.managedAbiKat -cne 'passed' -or
            [string]$acceptance.gates.productionWrapperProbe -cne 'passed') {
            throw 'Android arm64 supplemental physical acceptance evidence is incomplete or does not bind the official artifact.'
        }
    }
    $approved += [ordered]@{
        target = $target
        property = $targetMap[$target].property
        rid = $targetMap[$target].rid
        relativePath = $targetMap[$target].relativePath
        bytes = $bytes
        sha256 = $sha256
    }
}
if ($approved.Count -eq 0) {
    throw 'The manifest contains no release-approved ML-KEM runtime.'
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('// Generated by eng/Generate-DeepMlKemApprovedAssets.ps1 from approved build evidence.')
$lines.Add('// Do not edit by hand; run the generator and commit the resulting diff.')
$lines.Add('namespace Deep.Protocol.MessagingCrypto;')
$lines.Add('')
$lines.Add('internal sealed record DeepMlKemApprovedAsset(')
$lines.Add('    string RuntimeIdentifier,')
$lines.Add('    string RelativePath,')
$lines.Add('    long Bytes,')
$lines.Add('    string Sha256,')
$lines.Add('    string Abi);')
$lines.Add('')
$lines.Add('internal static class DeepMlKemApprovedAssets')
$lines.Add('{')
$lines.Add("    internal const string ManifestProviderIdentifier = `"$providerIdentifier`";")
$lines.Add('')
foreach ($asset in $approved) {
    $lines.Add("    internal static DeepMlKemApprovedAsset $($asset.property) { get; } = new(")
    $lines.Add("        `"$($asset.rid)`",")
    $lines.Add("        `"$($asset.relativePath)`",")
    $lines.Add("        $($asset.bytes),")
    $lines.Add("        `"$($asset.sha256)`",")
    $lines.Add('        ManifestProviderIdentifier);')
    $lines.Add('')
}
$lines.Add('    internal static DeepMlKemApprovedAsset ForCurrentProcess()')
$lines.Add('    {')
$lines.Add('        if (OperatingSystem.IsWindows() &&')
$lines.Add('            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==')
$lines.Add('            System.Runtime.InteropServices.Architecture.X64)')
$lines.Add('            return WindowsX64;')
$lines.Add('')
$lines.Add('        if (OperatingSystem.IsWindows() &&')
$lines.Add('            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==')
$lines.Add('            System.Runtime.InteropServices.Architecture.Arm64)')
$lines.Add('            return WindowsArm64;')
$lines.Add('')
if (@($approved | Where-Object { $_.target -ceq 'android-arm64' }).Count -eq 1) {
    $lines.Add('        if (OperatingSystem.IsAndroid() &&')
    $lines.Add('            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==')
    $lines.Add('            System.Runtime.InteropServices.Architecture.Arm64)')
    $lines.Add('            return AndroidArm64;')
    $lines.Add('')
}
$lines.Add('        throw new PlatformNotSupportedException(')
$lines.Add('            "No release-approved Deep ML-KEM asset exists for the current process RID.");')
$lines.Add('    }')
$lines.Add('}')
$expected = ($lines -join "`n") + "`n"

if ($Check) {
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "Generated ML-KEM allowlist is absent: $OutputPath"
    }
    $actual = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $OutputPath).Path).Replace("`r`n", "`n")
    if ($actual -cne $expected) {
        $limit = [Math]::Min($actual.Length, $expected.Length)
        $difference = 0
        while ($difference -lt $limit -and $actual[$difference] -ceq $expected[$difference]) {
            $difference++
        }
        throw "Generated ML-KEM allowlist differs from the approved build manifest at character $difference " +
            "(actual length $($actual.Length), expected length $($expected.Length))."
    }
    Write-Host 'Deep ML-KEM generated allowlist check passed.'
    return
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutput
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
[IO.File]::WriteAllText($resolvedOutput, $expected, [Text.UTF8Encoding]::new($false))
Write-Host "Generated Deep ML-KEM allowlist: $resolvedOutput"
