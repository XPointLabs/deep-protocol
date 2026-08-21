[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$artifactsRoot = Join-Path $root 'artifacts/dnp1-devops-witness-runs'
[IO.Directory]::CreateDirectory($artifactsRoot) | Out-Null
$runRoot = Join-Path $artifactsRoot ([Guid]::NewGuid().ToString('N'))
$input = Join-Path $runRoot 'input'
$normalized = Join-Path $runRoot 'normalized'
$version = '0.0.0-dnp1witness'
$repositoryUrl = 'https://github.com/XPointLabs/deep-protocol.git'

function Invoke-DotNet {
    param([Parameter(Mandatory)] [string[]] $Arguments, [Parameter(Mandatory)] [string] $Label)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

function Invoke-DotNetMustFail {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $RequiredText,
        [Parameter(Mandatory)] [string] $Label)
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = (& dotnet @Arguments 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $priorPreference }
    if ($exitCode -eq 0) { throw "$Label unexpectedly passed." }
    if ($output.IndexOf($RequiredText, [StringComparison]::Ordinal) -lt 0) {
        throw "$Label failed for the wrong reason.`n$output"
    }
    Write-Host "PASS expected rejection: $Label"
}

try {
    [IO.Directory]::CreateDirectory($input) | Out-Null
    $projects = @(
        'src/Deep.Protocol/Deep.Protocol.csproj',
        'src/Deep.Protocol.MembershipRoutes/Deep.Protocol.MembershipRoutes.csproj',
        'src/Deep.Protocol.ProfileCarrier/Deep.Protocol.ProfileCarrier.csproj')
    foreach ($project in $projects) {
        $arguments = @(
            'pack', (Join-Path $root $project), '--configuration', $Configuration,
            '--no-build', '--no-restore', '--output', $input,
            "-p:Version=$version", "-p:PackageVersion=$version",
            "-p:RepositoryUrl=$repositoryUrl")
        if ($project -like '*ProfileCarrier*') {
            $arguments += "-p:DeepProtocolPackageVersion=[$version]"
        }
        Invoke-DotNet $arguments "dotnet pack $project"
    }

    $head = (& git -C $root rev-parse HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw 'Cannot bind the package witness to the protocol source commit.'
    }
    & (Join-Path $PSScriptRoot 'Normalize-ProductionProtocolClosure.ps1') `
        -InputDirectory $input `
        -OutputDirectory $normalized `
        -ProductionVersion $version `
        -ProfileCarrierVersion $version `
        -SourceCommit $head `
        -RepositoryUrl $repositoryUrl
    if ($LASTEXITCODE -ne 0) { throw 'Exact-three package normalization failed.' }

    $assemblies = [ordered]@{
        '--protocol-assembly' = Join-Path $root "src/Deep.Protocol/bin/$Configuration/net10.0/Deep.Protocol.dll"
        '--routes-assembly' = Join-Path $root "src/Deep.Protocol.MembershipRoutes/bin/$Configuration/net10.0/Deep.Protocol.MembershipRoutes.dll"
        '--carrier-assembly' = Join-Path $root "src/Deep.Protocol.ProfileCarrier/bin/$Configuration/net10.0/Deep.Protocol.ProfileCarrier.dll"
        '--golden-assembly' = Join-Path $root "tests/Deep.Protocol.GoldenVectors/bin/$Configuration/net10.0/Deep.Protocol.GoldenVectors.dll"
    }
    foreach ($assembly in $assemblies.Values) {
        if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) {
            throw "Required built assembly is missing: $assembly"
        }
    }
    $identityArguments = @(
        'run', '--project', (Join-Path $root 'eng/Dnp1ProductionGraph.Identity/Dnp1ProductionGraph.Identity.csproj'),
        '--configuration', $Configuration, '--',
        '--package-root', $normalized,
        '--protocol-version', $version,
        '--carrier-version', $version)
    foreach ($entry in $assemblies.GetEnumerator()) {
        $identityArguments += @($entry.Key, $entry.Value)
    }
    Invoke-DotNet $identityArguments 'actual package/assembly/resource/nuspec/public-API graph gate'

    $strippedProject = Join-Path $root 'eng/Dnp1ProductionGraph.StrippedFixture/Dnp1ProductionGraph.StrippedFixture.csproj'
    Invoke-DotNet @(
        'build', $strippedProject, '--configuration', $Configuration,
        "-p:WitnessAssemblyName=Deep.Protocol") 'stripped protocol fixture build'
    $strippedProtocolBuild = Join-Path $root "eng/Dnp1ProductionGraph.StrippedFixture/bin/$Configuration/net10.0/Deep.Protocol.dll"
    $strippedProtocol = Join-Path $runRoot 'Deep.Protocol.stripped.dll'
    [IO.File]::Copy($strippedProtocolBuild, $strippedProtocol, $false)
    Invoke-DotNet @(
        'build', $strippedProject, '--configuration', $Configuration,
        "-p:WitnessAssemblyName=Deep.Protocol.GoldenVectors") 'stripped resource fixture build'
    $strippedGoldenBuild = Join-Path $root "eng/Dnp1ProductionGraph.StrippedFixture/bin/$Configuration/net10.0/Deep.Protocol.GoldenVectors.dll"
    $strippedGolden = Join-Path $runRoot 'Deep.Protocol.GoldenVectors.stripped.dll'
    [IO.File]::Copy($strippedGoldenBuild, $strippedGolden, $false)

    $mutated = Join-Path $runRoot 'mutated-package'
    Copy-Item -LiteralPath $normalized -Destination $mutated -Recurse
    $protocolPackage = Join-Path $mutated "Deep.Protocol.$version.nupkg"
    $archive = [IO.Compression.ZipFile]::Open($protocolPackage, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = @($archive.Entries | Where-Object {
            $_.FullName -ceq 'lib/net10.0/Deep.Protocol.dll' })
        if ($entry.Count -ne 1) { throw 'Protocol mutation package has no unique assembly entry.' }
        $entry[0].Delete()
        $replacement = $archive.CreateEntry(
            'lib/net10.0/Deep.Protocol.dll', [IO.Compression.CompressionLevel]::Optimal)
        $stream = $replacement.Open()
        try {
            $bytes = [IO.File]::ReadAllBytes($strippedProtocol)
            $stream.Write($bytes, 0, $bytes.Length)
        }
        finally { $stream.Dispose() }
    }
    finally { $archive.Dispose() }
    $mutatedArguments = @($identityArguments)
    $packageRootIndex = [Array]::IndexOf($mutatedArguments, '--package-root')
    if ($packageRootIndex -lt 0) { throw 'Package gate arguments lost package-root.' }
    $mutatedArguments[$packageRootIndex + 1] = $mutated
    Invoke-DotNetMustFail $mutatedArguments `
        'public-API/resource/assembly snapshot differs' `
        'package ZIP with stripped retained public API'

    $resourceArguments = @(
        'run', '--project', (Join-Path $root 'eng/Dnp1ProductionGraph.Identity/Dnp1ProductionGraph.Identity.csproj'),
        '--configuration', $Configuration, '--',
        '--protocol-assembly', $assemblies['--protocol-assembly'],
        '--routes-assembly', $assemblies['--routes-assembly'],
        '--carrier-assembly', $assemblies['--carrier-assembly'],
        '--golden-assembly', $strippedGolden)
    Invoke-DotNetMustFail $resourceArguments `
        'public-API/resource/assembly snapshot differs' `
        'golden-vector assembly with stripped embedded resources'

    $crossFeedArguments = @(
        'run', '--project', (Join-Path $root 'eng/Dnp1ProductionGraph.Identity/Dnp1ProductionGraph.Identity.csproj'),
        '--configuration', $Configuration, '--',
        '--protocol-assembly', $assemblies['--protocol-assembly'],
        '--routes-assembly', $assemblies['--protocol-assembly'],
        '--carrier-assembly', $assemblies['--carrier-assembly'])
    Invoke-DotNetMustFail $crossFeedArguments `
        'assembly identity' `
        'assembly-slot cross-feed'
    Write-Host 'PASS DevOpsWitness package-exact-three-session-free actual package ZIP and assembly/resource graph'
}
finally {
    if (Test-Path -LiteralPath $runRoot) {
        $resolvedArtifacts = [IO.Path]::GetFullPath($artifactsRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
        $resolvedRun = [IO.Path]::GetFullPath($runRoot)
        if (-not $resolvedRun.StartsWith($resolvedArtifacts, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe witness cleanup path: $resolvedRun"
        }
        [IO.Directory]::Delete($resolvedRun, $true)
    }
}
