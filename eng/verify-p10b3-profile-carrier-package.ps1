[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CarrierSourceCommit,
    [string]$RepositoryRoot = "",
    [string]$ProtocolPackageRoot = "",
    [string]$WorkRootA = "",
    [string]$WorkRootB = "",
    [string]$PublishedRoot = "",
    [string]$ProvenancePath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$protocolSourceCommit = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
$protocolVersion = "0.3.0-p10b3.60ce2e3"
$carrierVersion = "0.2.0-p10b3.60ce2e3"
$normalizerSha256 = "18ad526c7676a7458c86c42ca4d85365694f7b627addad1ad09ae1d2c47c911d"
$normalizerSha512 = "33953c302cac1c3d9e8c09341231db414130de482e5160eece4dee89a75a2e9f6e1c992e35f1353b19891244d9cca70e0c2e80328c7ead67989cda53d22058d9"

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$workspaceRoot = Split-Path -Parent (Split-Path -Parent $RepositoryRoot)
if ([string]::IsNullOrWhiteSpace($ProtocolPackageRoot)) {
    $ProtocolPackageRoot = Join-Path $RepositoryRoot `
        "artifacts\survival\P10B3\60ce2e3\packages"
}
$ProtocolPackageRoot = (Resolve-Path -LiteralPath $ProtocolPackageRoot).Path
if ([string]::IsNullOrWhiteSpace($WorkRootA)) {
    $WorkRootA = Join-Path $workspaceRoot `
        "artifacts\deep-protocol-p10b3-carrier\external-a"
}
if ([string]::IsNullOrWhiteSpace($WorkRootB)) {
    $WorkRootB = Join-Path $workspaceRoot `
        "artifacts\deep-protocol-p10b3-carrier\external-b"
}
if ([string]::IsNullOrWhiteSpace($PublishedRoot)) {
    $PublishedRoot = Join-Path $RepositoryRoot `
        "artifacts\survival\P10B3\60ce2e3\profile-carrier"
}
$WorkRootA = [IO.Path]::GetFullPath($WorkRootA)
$WorkRootB = [IO.Path]::GetFullPath($WorkRootB)
$PublishedRoot = [IO.Path]::GetFullPath($PublishedRoot)
if (![string]::IsNullOrWhiteSpace($ProvenancePath)) {
    $ProvenancePath = (Resolve-Path -LiteralPath $ProvenancePath).Path
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

function Get-Hash {
    param([string]$Path, [string]$Algorithm)
    return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

function Assert-Equal {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "$Label differs."
    }
}

function Assert-ExternalDistinctRoots {
    $repositoryPrefix = $RepositoryRoot.TrimEnd("\") + "\"
    foreach ($root in @($WorkRootA, $WorkRootB)) {
        if ($root.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            $root.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Both build WorkRoots must be external to the repository."
        }
    }
    if ($WorkRootA.Equals($WorkRootB, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The two external build WorkRoots must be distinct."
    }
}

function Copy-PackageSet {
    param([string]$From, [string]$To)
    Get-ChildItem -LiteralPath $From -File -Filter "*.nupkg" |
        ForEach-Object {
            Copy-Item -LiteralPath $_.FullName `
                -Destination (Join-Path $To $_.Name) -Force
        }
}

function Set-IsolatedEnvironment {
    param([string]$Root)
    $env:DOTNET_CLI_HOME = Join-Path $Root "cli-home"
    $env:APPDATA = Join-Path $Root "appdata"
    $env:NUGET_PACKAGES = Join-Path $Root "packages-home"
    $env:NUGET_HTTP_CACHE_PATH = Join-Path $Root "http-cache"
    $env:HTTP_PROXY = "http://127.0.0.1:9"
    $env:HTTPS_PROXY = "http://127.0.0.1:9"
    $env:ALL_PROXY = "http://127.0.0.1:9"
    $env:NO_PROXY = ""
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:DOTNET_NOLOGO = "1"
}

function New-LocalConfig {
    param([string]$Path, [string]$Feed)
    $feedUri = [Uri]::new($Feed).AbsoluteUri
    Set-Content -LiteralPath $Path -NoNewline -Encoding utf8 @"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$feedUri" /></packageSources></configuration>
"@
}

function Invoke-CarrierBuild {
    param([string]$ExternalRoot, [string]$Label, [string]$InvocationId)
    $root = Join-Path $ExternalRoot "$InvocationId-$Label"
    $source = Join-Path $root "source"
    $feed = Join-Path $root "feed"
    $output = Join-Path $root "output"
    New-Item -ItemType Directory -Path $source, $feed, $output -Force |
        Out-Null
    $archive = Join-Path $root "accepted-carrier-source.zip"
    Invoke-Checked "git" @(
        "-C", $RepositoryRoot,
        "archive", "--format=zip",
        "-o", $archive,
        $CarrierSourceCommit
    ) $RepositoryRoot | Out-Host
    Expand-Archive -LiteralPath $archive -DestinationPath $source

    $normalizer = Join-Path $source "eng\Normalize-NuGetPackage.ps1"
    Assert-Equal $normalizerSha256 `
        (Get-Hash $normalizer "SHA256") `
        "$Label accepted normalizer SHA-256"
    Assert-Equal $normalizerSha512 `
        (Get-Hash $normalizer "SHA512") `
        "$Label accepted normalizer SHA-512"

    Copy-PackageSet `
        (Join-Path $source "vendor\p14-profile-carrier\packages") `
        $feed
    Copy-PackageSet $ProtocolPackageRoot $feed
    $config = Join-Path $root "NuGet.Config"
    New-LocalConfig $config $feed
    Set-IsolatedEnvironment $root

    $project = Join-Path $source `
        "src\Deep.Protocol.ProfileCarrier\Deep.Protocol.ProfileCarrier.csproj"
    $sourceLink = Join-Path $root "carrier.sourcelink.json"
    Set-Content -LiteralPath $sourceLink -NoNewline -Encoding utf8 @"
{"documents":{"/_/Deep.Protocol.ProfileCarrier/*":"https://raw.githubusercontent.com/XPointLabs/deep-protocol/$CarrierSourceCommit/src/Deep.Protocol.ProfileCarrier/*"}}
"@
    $properties = @(
        "-p:Version=$carrierVersion",
        "-p:PackageVersion=$carrierVersion",
        "-p:RepositoryCommit=$CarrierSourceCommit",
        "-p:SourceRevisionId=$CarrierSourceCommit",
        "-p:SourceLink=$sourceLink",
        "-p:DeepProtocolPackageVersion=[$protocolVersion]",
        "-p:Deterministic=true",
        "-p:ContinuousIntegrationBuild=true",
        "-p:RestoreLockedMode=false"
    )
    Invoke-Checked "dotnet" (@(
        "restore", $project,
        "--configfile", $config,
        "--packages", $env:NUGET_PACKAGES,
        "--force-evaluate"
    ) + $properties) $source | Out-Host
    Invoke-Checked "dotnet" (@(
        "build", $project,
        "--no-restore",
        "--configuration", "Release"
    ) + $properties) $source | Out-Host
    Invoke-Checked "dotnet" (@(
        "pack", $project,
        "--no-restore",
        "--no-build",
        "--configuration", "Release",
        "--output", $output
    ) + $properties) $source | Out-Host
    $package = Join-Path $output `
        "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
    Invoke-Checked "powershell" @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $normalizer,
        "-Path", $package
    ) $source | Out-Host
    return [PSCustomObject]@{
        Root = $root
        Source = $source
        Feed = $feed
        Config = $config
        Package = $package
        Bytes = (Get-Item -LiteralPath $package).Length
        Sha256 = Get-Hash $package "SHA256"
        Sha512 = Get-Hash $package "SHA512"
    }
}

Assert-ExternalDistinctRoots
$dirty = & git -C $RepositoryRoot status --porcelain=v1
if ($LASTEXITCODE -ne 0 -or $null -ne $dirty) {
    throw "The gate requires a clean current repository."
}
$resolvedCarrierCommit = (& git -C $RepositoryRoot rev-parse `
    "$CarrierSourceCommit`^{commit}").Trim()
if ($LASTEXITCODE -ne 0 -or $resolvedCarrierCommit -ne $CarrierSourceCommit -or
    $CarrierSourceCommit -notmatch "^[0-9a-f]{40}$") {
    throw "CarrierSourceCommit must be an available exact full commit."
}
if ($CarrierSourceCommit -eq $protocolSourceCommit) {
    throw "Carrier and protocol source commits must remain separate identities."
}
& git -C $RepositoryRoot merge-base --is-ancestor `
    $CarrierSourceCommit HEAD
if ($LASTEXITCODE -ne 0) {
    throw "The accepted carrier source commit must be an ancestor of current HEAD."
}

$protocolProvenance = Get-Content -LiteralPath `
    (Join-Path $RepositoryRoot "eng\p10b3-package-provenance.json") `
    -Raw | ConvertFrom-Json
Assert-Equal $protocolSourceCommit `
    ([string]$protocolProvenance.sourceCommit) `
    "Protocol contract source commit"
foreach ($id in @(
    "Deep.Protocol",
    "Deep.Protocol.Abstractions",
    "Deep.Protocol.Protobuf"
)) {
    $entry = @($protocolProvenance.packages |
        Where-Object { $_.id -eq $id })
    if ($entry.Count -ne 1) {
        throw "The P10B3 package provenance is missing $id."
    }
    $path = Join-Path $ProtocolPackageRoot $entry[0].file
    Assert-Equal ([string]$entry[0].bytes) `
        ([string](Get-Item -LiteralPath $path).Length) `
        "$id package byte length"
    Assert-Equal ([string]$entry[0].sha256) `
        (Get-Hash $path "SHA256") `
        "$id package SHA-256"
    Assert-Equal ([string]$entry[0].sha512) `
        (Get-Hash $path "SHA512") `
        "$id package SHA-512"
}

New-Item -ItemType Directory -Path `
    $WorkRootA, $WorkRootB, $PublishedRoot -Force | Out-Null
$invocationId = [Guid]::NewGuid().ToString("N")
$a = Invoke-CarrierBuild $WorkRootA "a" $invocationId
$b = Invoke-CarrierBuild $WorkRootB "b" $invocationId
Assert-Equal ([string]$a.Bytes) ([string]$b.Bytes) `
    "External build A/B byte length"
Assert-Equal $a.Sha256 $b.Sha256 "External build A/B SHA-256"
Assert-Equal $a.Sha512 $b.Sha512 "External build A/B SHA-512"

$publishedPackage = Join-Path $PublishedRoot `
    "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
Copy-Item -LiteralPath $a.Package -Destination $publishedPackage -Force
Assert-Equal ([string]$a.Bytes) `
    ([string](Get-Item -LiteralPath $publishedPackage).Length) `
    "Published package byte length"
Assert-Equal $a.Sha256 `
    (Get-Hash $publishedPackage "SHA256") `
    "Published package SHA-256"
Assert-Equal $b.Sha512 `
    (Get-Hash $publishedPackage "SHA512") `
    "Published package SHA-512"

$smokeRoot = Join-Path $a.Root "locked-install-smoke"
$smokeFeed = Join-Path $smokeRoot "feed"
New-Item -ItemType Directory -Path $smokeRoot, $smokeFeed -Force |
    Out-Null
Copy-PackageSet `
    (Join-Path $a.Source "vendor\p14-profile-carrier\packages") `
    $smokeFeed
Copy-PackageSet $ProtocolPackageRoot $smokeFeed
Copy-Item -LiteralPath $publishedPackage `
    -Destination (Join-Path $smokeFeed `
        "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg") `
    -Force
$smokeConfig = Join-Path $smokeRoot "NuGet.Config"
New-LocalConfig $smokeConfig $smokeFeed
$smokeProject = Join-Path $smokeRoot "locked-install-smoke.csproj"
Set-Content -LiteralPath $smokeProject -NoNewline -Encoding utf8 @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup><PackageReference Include="Deep.Protocol.ProfileCarrier" Version="[$carrierVersion]" /><PackageReference Include="Deep.Protocol" Version="[$protocolVersion]" /></ItemGroup></Project>
"@
Set-Content -LiteralPath (Join-Path $smokeRoot "Program.cs") `
    -NoNewline -Encoding utf8 `
    "System.Console.WriteLine(typeof(Program).Assembly.GetName().Name);"
Set-IsolatedEnvironment $smokeRoot
Invoke-Checked "dotnet" @(
    "restore", $smokeProject,
    "--configfile", $smokeConfig,
    "--packages", $env:NUGET_PACKAGES,
    "--force-evaluate"
) $smokeRoot
Invoke-Checked "dotnet" @(
    "restore", $smokeProject,
    "--configfile", $smokeConfig,
    "--packages", $env:NUGET_PACKAGES,
    "--locked-mode"
) $smokeRoot
Invoke-Checked "dotnet" @(
    "build", $smokeProject,
    "--no-restore",
    "--configuration", "Release"
) $smokeRoot
Invoke-Checked "dotnet" @(
    "run", "--project", $smokeProject,
    "--no-build",
    "--configuration", "Release"
) $smokeRoot
$smokeLock = Join-Path $smokeRoot "packages.lock.json"
$publishedLock = Join-Path $PublishedRoot `
    "install-smoke.packages.lock.json"
Copy-Item -LiteralPath $smokeLock -Destination $publishedLock -Force

$identityProject = Join-Path $a.Source `
    "eng\P10B3ProfileCarrier.Identity\P10B3ProfileCarrier.Identity.csproj"
Set-IsolatedEnvironment (Join-Path $a.Root "identity")
Invoke-Checked "dotnet" @(
    "restore", $identityProject,
    "--configfile", $a.Config,
    "--packages", $env:NUGET_PACKAGES
) $a.Source
$identityArguments = @(
    "run", "--project", $identityProject,
    "--no-restore",
    "--configuration", "Release",
    "--",
    "--package", $publishedPackage,
    "--lock", $publishedLock,
    "--carrier-source", $CarrierSourceCommit,
    "--protocol-source", $protocolSourceCommit,
    "--carrier-version", $carrierVersion,
    "--protocol-version", $protocolVersion,
    "--package-sha256", $a.Sha256,
    "--package-sha512", $a.Sha512,
    "--lock-sha256", (Get-Hash $publishedLock "SHA256"),
    "--lock-sha512", (Get-Hash $publishedLock "SHA512"),
    "--self-test"
)
if (![string]::IsNullOrWhiteSpace($ProvenancePath)) {
    $identityArguments += @("--provenance", $ProvenancePath)
}
Invoke-Checked "dotnet" $identityArguments $a.Source

Write-Output "PASS carrier-source-commit=$CarrierSourceCommit protocol-source-commit=$protocolSourceCommit"
Write-Output "external-work-root-a=$($a.Root)"
Write-Output "external-work-root-b=$($b.Root)"
Write-Output "package=$publishedPackage"
Write-Output "bytes=$($a.Bytes)"
Write-Output "sha256=$($a.Sha256)"
Write-Output "sha512=$($a.Sha512)"
Write-Output "external-a-b-final-byte-identical=true"
Write-Output "locked-install-smoke-lock=$publishedLock"
Write-Output "lock-bytes=$((Get-Item -LiteralPath $publishedLock).Length)"
Write-Output "lock-sha256=$(Get-Hash $publishedLock 'SHA256')"
Write-Output "lock-sha512=$(Get-Hash $publishedLock 'SHA512')"
