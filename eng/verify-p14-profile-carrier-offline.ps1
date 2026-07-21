[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "deep-p14-carrier-offline")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function Invoke-Checked {
    param([string]$File, [string[]]$Arguments, [string]$WorkingDirectory)
    Push-Location $WorkingDirectory
    try {
        & $File @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$File failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Assert-EqualSet {
    param([string[]]$Expected, [string[]]$Actual, [string]$Label)
    $difference = Compare-Object `
        ($Expected | Sort-Object -Unique) `
        ($Actual | Sort-Object -Unique)
    if ($null -ne $difference) {
        throw "$Label differs from the exact allowlist: $($difference | Out-String)"
    }
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$manifestPath = Join-Path $RepositoryRoot "eng\p14-profile-carrier.offline-packages.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne "deep-p14-profile-carrier-offline-packages-v1" -or
    $manifest.files.Count -ne 21) {
    throw "The offline package manifest schema or exact file count is invalid."
}

$packageRoot = Join-Path $RepositoryRoot "vendor\p14-profile-carrier\packages"
$actualPackages = @(Get-ChildItem -LiteralPath $packageRoot -File -Filter "*.nupkg")
Assert-EqualSet `
    @($manifest.files | ForEach-Object { $_.name }) `
    @($actualPackages | ForEach-Object { $_.Name }) `
    "Offline package file set"
foreach ($entry in $manifest.files) {
    $file = Get-Item -LiteralPath (Join-Path $packageRoot $entry.name)
    if ($file.Length -ne [long]$entry.size) {
        throw "Offline package size mismatch: $($entry.name)."
    }
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $entry.sha256) {
        throw "Offline package hash mismatch: $($entry.name)."
    }
}

$requiredNativeRids = @(
    "win-arm64",
    "win-x64",
    "linux-arm64",
    "linux-x64",
    "android-arm64"
)
$nativeAssetOutput = & (Join-Path $RepositoryRoot `
    "eng\verify-p14e2-native-assets.ps1") -RepositoryRoot $RepositoryRoot
foreach ($rid in $requiredNativeRids) {
    if (@($nativeAssetOutput | Where-Object {
        $_ -like "rid=$rid *native-asset-sha256=*"
    }).Count -ne 1) {
        throw "The exact native asset proof is missing for $rid."
    }
}
if (@($nativeAssetOutput | Where-Object {
    $_ -eq "CROSS-RID-EXECUTION-PENDING"
}).Count -ne 1) {
    throw "The cross-RID execution boundary was not recorded."
}
$nativeAssetOutput | Write-Output

$winArm64Output = & (Join-Path $RepositoryRoot `
    "eng\verify-p14e2-win-arm64-build.ps1") `
    -RepositoryRoot $RepositoryRoot `
    -WorkRoot (Join-Path ([System.IO.Path]::GetFullPath($WorkRoot)) `
        "win-arm64-build")
if (@($winArm64Output | Where-Object {
    $_ -like "win-arm64-build=PASS repository-commit=*"
}).Count -ne 1) {
    throw "The isolated win-arm64 build proof is missing."
}
$winArm64Output | Write-Output

$sdkJson = Get-Content -LiteralPath (Join-Path $RepositoryRoot "global.json") -Raw |
    ConvertFrom-Json
if ($sdkJson.sdk.version -ne "10.0.301" -or $sdkJson.sdk.rollForward -ne "disable") {
    throw "global.json must pin SDK 10.0.301 with rollForward disabled."
}

$head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch "^[0-9a-f]{40}$") {
    throw "A committed source revision is required."
}
$version = "0.2.0-p14.$($head.Substring(0, 7))"

$workBase = [System.IO.Path]::GetFullPath($WorkRoot)
New-Item -ItemType Directory -Path $workBase -Force | Out-Null
$resolvedWorkRoot = Join-Path $workBase "run-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $resolvedWorkRoot | Out-Null
$archive = Join-Path $resolvedWorkRoot "source.zip"
$sourceRoot = Join-Path $resolvedWorkRoot "isolation\source"
New-Item -ItemType Directory -Path (Split-Path -Parent $sourceRoot) | Out-Null
Invoke-Checked "git" @("-C", $RepositoryRoot, "archive", "--format=zip", "-o", $archive, "HEAD") $RepositoryRoot
Expand-Archive -LiteralPath $archive -DestinationPath $sourceRoot

$injectionRoot = Split-Path -Parent $sourceRoot
$marker = Join-Path $resolvedWorkRoot "ancestor-imported.marker"
$malicious = @"
<Project>
  <Target Name="P14AncestorInjection" BeforeTargets="BeforeBuild">
    <WriteLinesToFile File="$marker" Lines="ancestor imported" Overwrite="true" />
  </Target>
</Project>
"@
Set-Content -LiteralPath (Join-Path $injectionRoot "Directory.Build.props") -Value $malicious
Set-Content -LiteralPath (Join-Path $injectionRoot "Directory.Build.targets") -Value $malicious
Set-Content -LiteralPath (Join-Path $injectionRoot "Directory.Solution.props") -Value $malicious
Set-Content -LiteralPath (Join-Path $injectionRoot "Directory.Solution.targets") -Value $malicious
Set-Content -LiteralPath (Join-Path $injectionRoot "Directory.Packages.props") -Value $malicious
Set-Content -LiteralPath (Join-Path $injectionRoot "NuGet.Config") -Value `
    '<configuration><packageSources><add key="network" value="https://127.0.0.1:9/v3/index.json" /></packageSources></configuration>'

$cliHome = Join-Path $resolvedWorkRoot "empty-cli-home"
$packagesHome = Join-Path $resolvedWorkRoot "empty-packages"
$httpCache = Join-Path $resolvedWorkRoot "empty-http-cache"
$pluginsCache = Join-Path $resolvedWorkRoot "empty-plugins-cache"
New-Item -ItemType Directory -Path $cliHome, $packagesHome, $httpCache, $pluginsCache | Out-Null
$env:DOTNET_CLI_HOME = $cliHome
$env:NUGET_PACKAGES = $packagesHome
$env:NUGET_HTTP_CACHE_PATH = $httpCache
$env:NUGET_PLUGINS_CACHE_PATH = $pluginsCache
$env:HTTP_PROXY = "http://127.0.0.1:9"
$env:HTTPS_PROXY = "http://127.0.0.1:9"
$env:ALL_PROXY = "http://127.0.0.1:9"
$env:NO_PROXY = ""
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

$solution = Join-Path $sourceRoot "Deep.Protocol.slnx"
$config = Join-Path $sourceRoot "eng\p14-profile-carrier.NuGet.Config"
$safeProps = Join-Path $sourceRoot "eng\p14-empty.props"
$safeSolutionProps = Join-Path $sourceRoot "eng\p14-empty-solution.props"
$safeSolutionTargets = Join-Path $sourceRoot "eng\p14-empty-solution.targets"
$env:ImportDirectoryBuildProps = "false"
$env:ImportDirectoryBuildTargets = "false"
$env:DirectoryPackagesPropsPath = $safeProps
$env:DirectorySolutionPropsPath = $safeSolutionProps
$env:DirectorySolutionTargetsPath = $safeSolutionTargets
$isolationProperties = @(
    "-noAutoResponse",
    "-p:ImportDirectoryBuildProps=false",
    "-p:ImportDirectoryBuildTargets=false",
    "-p:DirectoryPackagesPropsPath=$safeProps",
    "-p:DirectorySolutionPropsPath=$safeSolutionProps",
    "-p:DirectorySolutionTargetsPath=$safeSolutionTargets",
    "-p:RestoreNoCache=true"
)

Invoke-Checked "dotnet" (@(
    "restore", $solution,
    "--configfile", $config,
    "--locked-mode",
    "--packages", $packagesHome
) + $isolationProperties) $sourceRoot

$expectedAssets = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($package in $actualPackages) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    try {
        $nuspec = $zip.Entries | Where-Object { $_.FullName -like "*.nuspec" } |
            Select-Object -First 1
        $reader = [System.IO.StreamReader]::new($nuspec.Open())
        try {
            [xml]$xml = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
        [void]$expectedAssets.Add("$($xml.package.metadata.id)/$($xml.package.metadata.version)")
    }
    finally {
        $zip.Dispose()
    }
}
$actualAssets = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter "project.assets.json" |
    ForEach-Object {
        $assets = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        foreach ($property in $assets.libraries.PSObject.Properties) {
            if ($property.Value.type -eq "package") {
                [void]$actualAssets.Add($property.Name)
            }
        }
    }
Assert-EqualSet @($expectedAssets) @($actualAssets) "Resolved package asset set"

foreach ($configuration in @("Debug", "Release")) {
    Invoke-Checked "dotnet" (@(
        "build", $solution, "--no-restore",
        "--configuration", $configuration
    ) + $isolationProperties) $sourceRoot
    Invoke-Checked "dotnet" (@(
        "test", $solution, "--no-restore", "--no-build",
        "--configuration", $configuration
    ) + $isolationProperties) $sourceRoot
}
Invoke-Checked "dotnet" (@(
    "msbuild", $solution,
    "-graphBuild",
    "-t:Build",
    "-p:Configuration=Release",
    "-p:Restore=false",
    "-v:minimal"
) + $isolationProperties) $sourceRoot
Invoke-Checked "dotnet" (@(
    "format", $solution, "--no-restore", "--verify-no-changes"
)) $sourceRoot

if (Test-Path -LiteralPath $marker) {
    throw "An ancestor MSBuild injection file was imported."
}

$packageOutput = Join-Path $resolvedWorkRoot "package"
New-Item -ItemType Directory -Path $packageOutput | Out-Null
$carrierProject = Join-Path $sourceRoot "src\Deep.Protocol.ProfileCarrier\Deep.Protocol.ProfileCarrier.csproj"
Invoke-Checked "dotnet" (@(
    "pack", $carrierProject,
    "--no-restore",
    "--configuration", "Release",
    "--output", $packageOutput,
    "-p:Version=$version",
    "-p:PackageVersion=$version",
    "-p:RepositoryCommit=$head",
    "-p:ContinuousIntegrationBuild=true"
) + $isolationProperties) $sourceRoot

$nupkg = Get-Item -LiteralPath (Join-Path $packageOutput "Deep.Protocol.ProfileCarrier.$version.nupkg")
$extractRoot = Join-Path $resolvedWorkRoot "package-inspection"
[System.IO.Compression.ZipFile]::ExtractToDirectory($nupkg.FullName, $extractRoot)
[xml]$packedNuspec = Get-Content -LiteralPath `
    (Get-ChildItem -LiteralPath $extractRoot -Filter "*.nuspec" | Select-Object -First 1).FullName
if ($packedNuspec.package.metadata.version -ne $version) {
    throw "The nuspec version does not match the exact commit-derived version."
}
if ($packedNuspec.package.metadata.repository.commit -ne $head) {
    throw "The nuspec repository commit does not match the verified full HEAD."
}
$dll = Get-Item -LiteralPath (Join-Path $extractRoot "lib\net10.0\Deep.Protocol.ProfileCarrier.dll")
$productVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dll.FullName).ProductVersion
if ($productVersion -ne $version) {
    throw "The package DLL InformationalVersion does not match the nuspec version."
}

$identity = & (Join-Path $RepositoryRoot `
    "eng\Get-P14ProfileCarrierNormalizedIdentity.ps1") `
    -PackagePath $nupkg.FullName `
    -ExpectedRepositoryCommit $head
$packageHash = (Get-FileHash -LiteralPath $nupkg.FullName -Algorithm SHA256).Hash.ToLowerInvariant()

$reproducibleOutput = & (Join-Path $RepositoryRoot `
    "eng\verify-p14-profile-carrier-reproducible.ps1") `
    -RepositoryRoot $RepositoryRoot `
    -WorkRoot (Join-Path $workBase "two-clean-pack")
$normalizedLine = $reproducibleOutput |
    Where-Object { $_ -like "normalized-source-identity-sha256=*" } |
    Select-Object -Last 1
$reproducedIdentity = $normalizedLine -replace `
    "^normalized-source-identity-sha256=", ""
if ($reproducedIdentity -ne $identity.Hash) {
    throw "The full offline pack and two-clean normalized identities differ."
}

Write-Output "PASS version=$version repository-commit=$head package=$($nupkg.FullName)"
Write-Output "normalized-source-identity-sha256=$($identity.Hash)"
Write-Output "exact-carrier-file-only-sha256=$packageHash"
$reproducibleOutput | Write-Output
