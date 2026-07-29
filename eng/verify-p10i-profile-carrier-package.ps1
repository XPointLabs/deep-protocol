[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$ProtocolPackageRoot = "",
    [string]$WorkRootA = "",
    [string]$WorkRootB = "",
    [string]$PublishedRoot = "",
    [string]$ProvenancePath = "",
    [switch]$PolicySelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$carrierSourceCommit = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
$protocolSourceCommit = "a9b7a10a555758d4b2e30707a70d271f010b6c30"
$protocolVersion = "0.3.0-p10i.a9b7a10"
$carrierVersion = "0.2.0-p10i.a9b7a10"
$normalizerSha256 = "18ad526c7676a7458c86c42ca4d85365694f7b627addad1ad09ae1d2c47c911d"
$normalizerSha512 = "33953c302cac1c3d9e8c09341231db414130de482e5160eece4dee89a75a2e9f6e1c992e35f1353b19891244d9cca70e0c2e80328c7ead67989cda53d22058d9"

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$workspaceRoot = Split-Path -Parent (Split-Path -Parent $RepositoryRoot)
if ([string]::IsNullOrWhiteSpace($ProtocolPackageRoot)) {
    $ProtocolPackageRoot = Join-Path $RepositoryRoot `
        "vendor\p10i-profile-carrier\packages"
}
$ProtocolPackageRoot = (Resolve-Path -LiteralPath $ProtocolPackageRoot).Path
if ([string]::IsNullOrWhiteSpace($WorkRootA)) {
    $WorkRootA = Join-Path $workspaceRoot `
        "artifacts\deep-protocol-p10i-carrier\external-a"
}
if ([string]::IsNullOrWhiteSpace($WorkRootB)) {
    $WorkRootB = Join-Path $workspaceRoot `
        "artifacts\deep-protocol-p10i-carrier\external-b"
}
if ([string]::IsNullOrWhiteSpace($PublishedRoot)) {
    $PublishedRoot = Join-Path $RepositoryRoot `
        "artifacts\survival\P10I\a9b7a10\profile-carrier"
}
$WorkRootA = [IO.Path]::GetFullPath($WorkRootA)
$WorkRootB = [IO.Path]::GetFullPath($WorkRootB)
$PublishedRoot = [IO.Path]::GetFullPath($PublishedRoot)
if ([string]::IsNullOrWhiteSpace($ProvenancePath)) {
    throw "ProvenancePath is required and must name the accepted P10I carrier provenance."
}
$acceptedProvenancePath = (Resolve-Path -LiteralPath (Join-Path $RepositoryRoot `
    "eng\p10i-profile-carrier-package-provenance.json")).Path
$ProvenancePath = (Resolve-Path -LiteralPath $ProvenancePath).Path
if (!$ProvenancePath.Equals(
        $acceptedProvenancePath,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "ProvenancePath must resolve to the accepted P10I carrier provenance."
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

function Get-ContentHash {
    param([string]$Path)
    $algorithm = [Security.Cryptography.SHA512]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try {
            return [Convert]::ToBase64String($algorithm.ComputeHash($stream))
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $algorithm.Dispose()
    }
}

function Assert-AcceptedCarrierSource {
    param([string]$Candidate)
    Assert-Equal $carrierSourceCommit $Candidate "Fixed carrier source commit"
}

function Assert-CarrierProvenanceStatic {
    param([object]$Value)
    Assert-Equal "deep-protocol-profile-carrier-package-provenance.v2" `
        ([string]$Value.schema) `
        "Carrier provenance schema"
    Assert-Equal $carrierSourceCommit `
        ([string]$Value.carrierSourceCommit) `
        "Provenance carrier source commit"
    Assert-Equal $protocolSourceCommit `
        ([string]$Value.protocolContractSourceCommit) `
        "Provenance protocol contract source commit"
    Assert-Equal $carrierVersion `
        ([string]$Value.carrierPackageVersion) `
        "Provenance carrier package version"
    Assert-Equal "[$protocolVersion]" `
        ([string]$Value.protocolDependency) `
        "Provenance protocol dependency"
    Assert-Equal $carrierSourceCommit `
        ([string]$Value.identity.nuspecRepositoryCommit) `
        "Provenance nuspec carrier identity"
    Assert-Equal $carrierSourceCommit `
        ([string]$Value.identity.pdbSourceLinkCommit) `
        "Provenance PDB SourceLink identity"
    if (!$Value.identity.peCodeViewMatchesPortablePdb -or
        !$Value.identity.protocolSourceIdentityCoherent -or
        !$Value.reproducibility.distinctExternalWorkRoots -or
        !$Value.reproducibility.externalBuildAByteIdentical -or
        !$Value.reproducibility.externalBuildBByteIdentical -or
        !$Value.reproducibility.publishedPackageByteIdentical -or
        !$Value.reproducibility.carrierSourceDriftRejected -or
        !$Value.reproducibility.packageByteDriftRejected -or
        !$Value.reproducibility.installLockDriftRejected) {
        throw "Carrier provenance does not record every required identity/reproducibility proof."
    }
    Assert-Equal $normalizerSha256 `
        ([string]$Value.normalization.acceptedSnapshotSha256) `
        "Carrier provenance normalizer SHA-256"
    Assert-Equal $normalizerSha512 `
        ([string]$Value.normalization.acceptedSnapshotSha512) `
        "Carrier provenance normalizer SHA-512"
    Assert-Equal "Deep.Protocol.ProfileCarrier" `
        ([string]$Value.package.id) `
        "Carrier provenance package id"
    Assert-Equal `
        "artifacts/survival/P10I/a9b7a10/profile-carrier/Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg" `
        ([string]$Value.package.file) `
        "Carrier provenance package file"
    Assert-Equal `
        "artifacts/survival/P10I/a9b7a10/profile-carrier/install-smoke.packages.lock.json" `
        ([string]$Value.lockedInstallSmoke.artifact) `
        "Carrier provenance install-lock file"
}

function Assert-CarrierProvenancePackage {
    param([object]$Value, [string]$PackagePath)
    Assert-Equal ([string]$Value.package.bytes) `
        ([string](Get-Item -LiteralPath $PackagePath).Length) `
        "Carrier provenance package byte length"
    Assert-Equal ([string]$Value.package.sha256) `
        (Get-Hash $PackagePath "SHA256") `
        "Carrier provenance package SHA-256"
    Assert-Equal ([string]$Value.package.sha512) `
        (Get-Hash $PackagePath "SHA512") `
        "Carrier provenance package SHA-512"
    Assert-Equal ([string]$Value.package.contentHash) `
        (Get-ContentHash $PackagePath) `
        "Carrier provenance package content hash"
}

function Assert-CarrierProvenanceLock {
    param([object]$Value, [string]$LockPath)
    Assert-Equal ([string]$Value.lockedInstallSmoke.bytes) `
        ([string](Get-Item -LiteralPath $LockPath).Length) `
        "Carrier provenance install-lock byte length"
    Assert-Equal ([string]$Value.lockedInstallSmoke.sha256) `
        (Get-Hash $LockPath "SHA256") `
        "Carrier provenance install-lock SHA-256"
    Assert-Equal ([string]$Value.lockedInstallSmoke.sha512) `
        (Get-Hash $LockPath "SHA512") `
        "Carrier provenance install-lock SHA-512"
    Assert-Equal ([string]$Value.lockedInstallSmoke.contentHash) `
        (Get-ContentHash $LockPath) `
        "Carrier provenance install-lock content hash"
}

function Copy-JsonObject {
    param([object]$Value)
    return $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json
}

function Expect-Rejected {
    param([scriptblock]$Action, [string]$Label)
    try {
        & $Action
    }
    catch {
        Write-Output "$Label-rejection=PASS"
        return
    }
    throw "The deliberate $Label mutation was accepted."
}

function Invoke-PolicySelfTest {
    param([object]$AcceptedProvenance)
    $ancestor = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
    & git -C $RepositoryRoot merge-base --is-ancestor $ancestor $carrierSourceCommit
    if ($LASTEXITCODE -ne 0) {
        throw "The policy self-test ancestor fixture is not an ancestor."
    }
    Expect-Rejected {
        Assert-AcceptedCarrierSource $ancestor
    } "alternate-ancestor-source"

    $descendant = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $descendant -eq $carrierSourceCommit) {
        throw "The policy self-test requires a descendant HEAD."
    }
    Expect-Rejected {
        Assert-AcceptedCarrierSource $descendant
    } "alternate-descendant-source"

    $sourceMutation = Copy-JsonObject $AcceptedProvenance
    $sourceMutation.carrierSourceCommit = $ancestor
    Expect-Rejected {
        Assert-CarrierProvenanceStatic $sourceMutation
    } "tampered-carrier-source"

    $versionMutation = Copy-JsonObject $AcceptedProvenance
    $versionMutation.carrierPackageVersion = "0.2.0-p10i.tampered"
    Expect-Rejected {
        Assert-CarrierProvenanceStatic $versionMutation
    } "tampered-carrier-version"

    $dependencyMutation = Copy-JsonObject $AcceptedProvenance
    $dependencyMutation.protocolDependency = "[0.3.0-p10i.tampered]"
    Expect-Rejected {
        Assert-CarrierProvenanceStatic $dependencyMutation
    } "tampered-protocol-dependency"

    $hashMutation = Copy-JsonObject $AcceptedProvenance
    $hashMutation.package.sha256 = ("0" * 64)
    $acceptedPackage = Join-Path $ProtocolPackageRoot `
        "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
    Expect-Rejected {
        Assert-CarrierProvenancePackage $hashMutation $acceptedPackage
    } "tampered-package-hash"
    Write-Output "P10I carrier package policy self-test PASS"
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
        $carrierSourceCommit
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
    $sourceLinkJson = @"
{"documents":{"/_/Deep.Protocol.ProfileCarrier/*":"https://raw.githubusercontent.com/XPointLabs/deep-protocol/$carrierSourceCommit/src/Deep.Protocol.ProfileCarrier/*"}}
"@
    [IO.File]::WriteAllText(
        $sourceLink,
        $sourceLinkJson,
        [Text.UTF8Encoding]::new($false))
    $properties = @(
        "-p:Version=$carrierVersion",
        "-p:PackageVersion=$carrierVersion",
        "-p:RepositoryCommit=$carrierSourceCommit",
        "-p:SourceRevisionId=$carrierSourceCommit",
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
Assert-AcceptedCarrierSource $carrierSourceCommit
$resolvedCarrierCommit = (& git -C $RepositoryRoot rev-parse `
    "$carrierSourceCommit`^{commit}").Trim()
if ($LASTEXITCODE -ne 0 -or $resolvedCarrierCommit -ne $carrierSourceCommit -or
    $carrierSourceCommit -notmatch "^[0-9a-f]{40}$") {
    throw "The fixed carrier source must be an available exact full commit."
}
& git -C $RepositoryRoot merge-base --is-ancestor `
    $carrierSourceCommit HEAD
if ($LASTEXITCODE -ne 0) {
    throw "The exact archived carrier source commit must be an ancestor of current HEAD."
}

$protocolProvenance = Get-Content -LiteralPath `
    (Join-Path $RepositoryRoot "eng\p10i-package-provenance.json") `
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
        throw "The P10I package provenance is missing $id."
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
$carrierProvenance = Get-Content -LiteralPath $ProvenancePath -Raw |
    ConvertFrom-Json
Assert-CarrierProvenanceStatic $carrierProvenance
if ($PolicySelfTest) {
    Invoke-PolicySelfTest $carrierProvenance
    exit 0
}

New-Item -ItemType Directory -Path `
    $WorkRootA, $WorkRootB -Force | Out-Null
$invocationId = [Guid]::NewGuid().ToString("N")
$a = Invoke-CarrierBuild $WorkRootA "a" $invocationId
$b = Invoke-CarrierBuild $WorkRootB "b" $invocationId
Assert-Equal ([string]$a.Bytes) ([string]$b.Bytes) `
    "External build A/B byte length"
Assert-Equal $a.Sha256 $b.Sha256 "External build A/B SHA-256"
Assert-Equal $a.Sha512 $b.Sha512 "External build A/B SHA-512"
Assert-CarrierProvenancePackage $carrierProvenance $a.Package

$smokeRoot = Join-Path $a.Root "locked-install-smoke"
$smokeFeed = Join-Path $smokeRoot "feed"
New-Item -ItemType Directory -Path $smokeRoot, $smokeFeed -Force |
    Out-Null
Copy-PackageSet `
    (Join-Path $a.Source "vendor\p14-profile-carrier\packages") `
    $smokeFeed
Copy-PackageSet $ProtocolPackageRoot $smokeFeed
Copy-Item -LiteralPath $a.Package `
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
Assert-CarrierProvenanceLock $carrierProvenance $smokeLock

$identityProject = Join-Path $RepositoryRoot `
    "eng\P10B3ProfileCarrier.Identity\P10B3ProfileCarrier.Identity.csproj"
Set-IsolatedEnvironment (Join-Path $a.Root "identity")
Invoke-Checked "dotnet" @(
    "restore", $identityProject,
    "--configfile", $a.Config,
    "--packages", $env:NUGET_PACKAGES
) $RepositoryRoot
Invoke-Checked "dotnet" @(
    "build", $identityProject,
    "--no-restore",
    "--configuration", "Release"
) $RepositoryRoot
$identityDll = Join-Path $RepositoryRoot `
    "eng\P10B3ProfileCarrier.Identity\bin\Release\net10.0\P10B3ProfileCarrier.Identity.dll"
$identityArguments = @(
    "--package", $a.Package,
    "--lock", $smokeLock,
    "--carrier-source", $carrierSourceCommit,
    "--protocol-source", $protocolSourceCommit,
    "--carrier-version", $carrierVersion,
    "--protocol-version", $protocolVersion,
    "--package-sha256", $a.Sha256,
    "--package-sha512", $a.Sha512,
    "--lock-sha256", (Get-Hash $smokeLock "SHA256"),
    "--lock-sha512", (Get-Hash $smokeLock "SHA512"),
    "--self-test",
    "--provenance", $ProvenancePath
)
Invoke-Checked "dotnet" (@($identityDll) + $identityArguments) $a.Source

New-Item -ItemType Directory -Path $PublishedRoot -Force | Out-Null
$publishedPackage = Join-Path $PublishedRoot `
    "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
$publishedLock = Join-Path $PublishedRoot `
    "install-smoke.packages.lock.json"
Copy-Item -LiteralPath $a.Package -Destination $publishedPackage -Force
Copy-Item -LiteralPath $smokeLock -Destination $publishedLock -Force
Assert-CarrierProvenancePackage $carrierProvenance $publishedPackage
Assert-CarrierProvenanceLock $carrierProvenance $publishedLock

Write-Output "PASS carrier-source-commit=$carrierSourceCommit protocol-source-commit=$protocolSourceCommit"
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
