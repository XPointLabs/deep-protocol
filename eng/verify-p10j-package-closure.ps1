[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$WorkRootA = "",
    [string]$WorkRootB = "",
    [string]$PublishedRoot = "",
    [string]$PublishedLockPath = "",
    [string]$ProvenancePath = "",
    [switch]$PolicySelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceCommit = "2886880d4c2060cd819765c53c77a02e1c475ea8"
$protocolVersion = "0.3.0-p10j.2886880"
$carrierVersion = "0.2.0-p10j.2886880"
$normalizerSha256 = "18ad526c7676a7458c86c42ca4d85365694f7b627addad1ad09ae1d2c47c911d"
$normalizerSha512 = "33953c302cac1c3d9e8c09341231db414130de482e5160eece4dee89a75a2e9f6e1c992e35f1353b19891244d9cca70e0c2e80328c7ead67989cda53d22058d9"
$packageSpecs = @(
    [PSCustomObject]@{ Id = "Deep.Protocol"; Version = $protocolVersion },
    [PSCustomObject]@{ Id = "Deep.Protocol.Abstractions"; Version = $protocolVersion },
    [PSCustomObject]@{ Id = "Deep.Protocol.MembershipRoutes"; Version = $protocolVersion },
    [PSCustomObject]@{ Id = "Deep.Protocol.ProfileCarrier"; Version = $carrierVersion },
    [PSCustomObject]@{ Id = "Deep.Protocol.Protobuf"; Version = $protocolVersion }
)
$buildSpecs = @(
    $packageSpecs | Where-Object { $_.Id -eq "Deep.Protocol.Abstractions" }
    $packageSpecs | Where-Object { $_.Id -eq "Deep.Protocol.Protobuf" }
    $packageSpecs | Where-Object { $_.Id -eq "Deep.Protocol" }
    $packageSpecs | Where-Object { $_.Id -eq "Deep.Protocol.MembershipRoutes" }
    $packageSpecs | Where-Object { $_.Id -eq "Deep.Protocol.ProfileCarrier" }
)

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$workspaceRoot = Split-Path -Parent (Split-Path -Parent $RepositoryRoot)
if ([string]::IsNullOrWhiteSpace($WorkRootA)) {
    $WorkRootA = Join-Path $workspaceRoot "artifacts\deep-protocol-p10j\external-a"
}
if ([string]::IsNullOrWhiteSpace($WorkRootB)) {
    $WorkRootB = Join-Path $workspaceRoot "artifacts\deep-protocol-p10j\external-b"
}
if ([string]::IsNullOrWhiteSpace($PublishedRoot)) {
    $PublishedRoot = Join-Path $RepositoryRoot "vendor\p10j-package-closure\packages"
}
if ([string]::IsNullOrWhiteSpace($PublishedLockPath)) {
    $PublishedLockPath = Join-Path $RepositoryRoot `
        "vendor\p10j-package-closure\install-smoke.packages.lock.json"
}
$WorkRootA = [IO.Path]::GetFullPath($WorkRootA)
$WorkRootB = [IO.Path]::GetFullPath($WorkRootB)
$PublishedRoot = [IO.Path]::GetFullPath($PublishedRoot)
$PublishedLockPath = [IO.Path]::GetFullPath($PublishedLockPath)
$acceptedProvenancePath = (Resolve-Path -LiteralPath (
    Join-Path $RepositoryRoot "eng\p10j-package-closure-provenance.json")).Path
if ([string]::IsNullOrWhiteSpace($ProvenancePath)) {
    $ProvenancePath = $acceptedProvenancePath
}
$ProvenancePath = (Resolve-Path -LiteralPath $ProvenancePath).Path
if (!$ProvenancePath.Equals(
        $acceptedProvenancePath,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Only the accepted P10J provenance is permitted."
}

function Invoke-Checked {
    param([string]$File, [string[]]$Arguments, [string]$WorkingDirectory)
    Push-Location $WorkingDirectory
    try {
        Write-Host "RUN $File $($Arguments -join ' ')"
        & $File @Arguments | Out-Host
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

function Assert-Equal {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "$Label differs: expected '$Expected', actual '$Actual'."
    }
}

function Assert-AcceptedSource {
    param([string]$Candidate)
    Assert-Equal $sourceCommit $Candidate "Fixed P10J source commit"
}

function Assert-ExternalRoots {
    $repositoryPrefix = $RepositoryRoot.TrimEnd("\") + "\"
    foreach ($root in @($WorkRootA, $WorkRootB)) {
        if ($root.Equals(
                $RepositoryRoot,
                [StringComparison]::OrdinalIgnoreCase) -or
            $root.StartsWith(
                $repositoryPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "P10J build roots must be external to the repository."
        }
    }
    if ($WorkRootA.Equals(
            $WorkRootB,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "P10J A/B build roots must be distinct."
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
    $env:AllowedOutputExtensionsInPackageBuildOutputFolder = ".dll;.pdb"
}

function New-LocalConfig {
    param([string]$Path, [string]$Feed)
    $feedUri = [Uri]::new($Feed).AbsoluteUri
    [IO.File]::WriteAllText(
        $Path,
        "<?xml version=`"1.0`" encoding=`"utf-8`"?><configuration><packageSources><clear /><add key=`"local`" value=`"$feedUri`" /></packageSources></configuration>",
        [Text.UTF8Encoding]::new($false))
}

function Get-PackagePath {
    param([string]$Root, [object]$Spec)
    return Join-Path $Root "$($Spec.Id).$($Spec.Version).nupkg"
}

function Assert-ProvenanceStatic {
    param([object]$Value)
    Assert-Equal "deep-protocol-p10j-package-closure.v1" `
        ([string]$Value.schema) "Provenance schema"
    Assert-Equal $sourceCommit ([string]$Value.sourceCommit) `
        "Provenance source commit"
    Assert-Equal $protocolVersion ([string]$Value.protocolVersion) `
        "Provenance protocol version"
    Assert-Equal $carrierVersion ([string]$Value.profileCarrierVersion) `
        "Provenance carrier version"
    Assert-Equal "git-archive-exact-commit" ([string]$Value.sourceAcquisition) `
        "Provenance source acquisition"
    if ($Value.networkSourcesAllowed -or
        !$Value.identity.portablePdbIncludedForEveryPackage -or
        !$Value.identity.peCodeViewMatchesPortablePdb -or
        !$Value.identity.pePdbSha256ChecksumPresent -or
        !$Value.reproducibility.distinctExternalWorkRoots -or
        !$Value.reproducibility.releaseBuildAByteIdentical -or
        !$Value.reproducibility.releaseBuildBByteIdentical -or
        !$Value.reproducibility.debugBuildVerified -or
        !$Value.reproducibility.publishedPackagesByteIdentical -or
        !$Value.reproducibility.sourceDriftRejected -or
        !$Value.reproducibility.packageByteDriftRejected -or
        !$Value.reproducibility.installLockDriftRejected) {
        throw "P10J provenance omits a required closure proof."
    }
    Assert-Equal $sourceCommit ([string]$Value.identity.nuspecRepositoryCommit) `
        "Nuspec identity commit"
    Assert-Equal $sourceCommit ([string]$Value.identity.pdbSourceLinkCommit) `
        "SourceLink identity commit"
    Assert-Equal $normalizerSha256 `
        ([string]$Value.normalization.acceptedSnapshotSha256) `
        "Normalizer SHA-256"
    Assert-Equal $normalizerSha512 `
        ([string]$Value.normalization.acceptedSnapshotSha512) `
        "Normalizer SHA-512"
    foreach ($spec in $packageSpecs) {
        $entry = @($Value.packages |
            Where-Object { $_.id -eq $spec.Id })
        if ($entry.Count -ne 1) {
            throw "Provenance must contain exactly one $($spec.Id) entry."
        }
        Assert-Equal $spec.Version ([string]$entry[0].version) `
            "$($spec.Id) provenance version"
        Assert-Equal `
            "vendor/p10j-package-closure/packages/$($spec.Id).$($spec.Version).nupkg" `
            ([string]$entry[0].file) `
            "$($spec.Id) provenance file"
    }
    Assert-Equal "vendor/p10j-package-closure/install-smoke.packages.lock.json" `
        ([string]$Value.lockedInstall.file) "Locked-install file"
}

function Assert-ProvenancePackage {
    param([object]$Entry, [string]$PackagePath, [string]$Label)
    Assert-Equal ([string]$Entry.bytes) `
        ([string](Get-Item -LiteralPath $PackagePath).Length) `
        "$Label byte length"
    Assert-Equal ([string]$Entry.sha256) `
        (Get-Hash $PackagePath "SHA256") "$Label SHA-256"
    Assert-Equal ([string]$Entry.sha512) `
        (Get-Hash $PackagePath "SHA512") "$Label SHA-512"
    Assert-Equal ([string]$Entry.contentHash) `
        (Get-ContentHash $PackagePath) "$Label content hash"
}

function Assert-ProvenancePackages {
    param([object]$Value, [string]$PackageRoot)
    foreach ($spec in $packageSpecs) {
        $entry = @($Value.packages |
            Where-Object { $_.id -eq $spec.Id })[0]
        Assert-ProvenancePackage $entry `
            (Get-PackagePath $PackageRoot $spec) $spec.Id
    }
}

function Assert-ProvenanceLock {
    param([object]$Value, [string]$LockPath)
    Assert-ProvenancePackage $Value.lockedInstall $LockPath "Install lock"
}

function Assert-VendorManifest {
    param([object]$Manifest, [object]$Provenance)
    Assert-Equal "deep-protocol-p10j-package-feed.v1" `
        ([string]$Manifest.schema) "Vendor manifest schema"
    Assert-Equal $sourceCommit ([string]$Manifest.sourceCommit) `
        "Vendor manifest source commit"
    Assert-Equal $protocolVersion ([string]$Manifest.protocolVersion) `
        "Vendor manifest protocol version"
    Assert-Equal $carrierVersion ([string]$Manifest.profileCarrierVersion) `
        "Vendor manifest carrier version"
    if ($Manifest.networkSourcesAllowed) {
        throw "The P10J vendor manifest must prohibit network sources."
    }
    foreach ($spec in $packageSpecs) {
        $manifestEntry = @($Manifest.packages |
            Where-Object {
                $_.file -eq "packages/$($spec.Id).$($spec.Version).nupkg"
            })
        $provenanceEntry = @($Provenance.packages |
            Where-Object { $_.id -eq $spec.Id })
        if ($manifestEntry.Count -ne 1 -or $provenanceEntry.Count -ne 1) {
            throw "The P10J manifest/provenance entry for $($spec.Id) is not unique."
        }
        foreach ($property in @(
            "bytes", "sha256", "sha512", "contentHash"
        )) {
            Assert-Equal ([string]$provenanceEntry[0].$property) `
                ([string]$manifestEntry[0].$property) `
                "$($spec.Id) manifest $property"
        }
    }
}

function Copy-JsonObject {
    param([object]$Value)
    return $Value | ConvertTo-Json -Depth 30 | ConvertFrom-Json
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
    param([object]$Accepted)
    $alternateAncestor = (& git -C $RepositoryRoot rev-parse `
        "$sourceCommit^").Trim()
    Expect-Rejected {
        Assert-AcceptedSource $alternateAncestor
    } "alternate-ancestor-source"
    $descendant = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($descendant -eq $sourceCommit) {
        throw "The P10J policy self-test requires a descendant HEAD."
    }
    Expect-Rejected {
        Assert-AcceptedSource $descendant
    } "alternate-descendant-source"
    $sourceMutation = Copy-JsonObject $Accepted
    $sourceMutation.sourceCommit = $alternateAncestor
    Expect-Rejected {
        Assert-ProvenanceStatic $sourceMutation
    } "provenance-source-drift"
    $versionMutation = Copy-JsonObject $Accepted
    $versionMutation.protocolVersion = "0.3.0-p10j.tampered"
    Expect-Rejected {
        Assert-ProvenanceStatic $versionMutation
    } "provenance-version-drift"
    $hashMutation = Copy-JsonObject $Accepted
    $hashMutation.packages[0].sha256 = ("0" * 64)
    Expect-Rejected {
        Assert-ProvenancePackage $hashMutation.packages[0] `
            (Get-PackagePath $PublishedRoot $packageSpecs[0]) `
            "Tampered package"
    } "provenance-package-hash-drift"
    Write-Output "P10J package closure policy self-test PASS"
}

function Invoke-ClosureBuild {
    param(
        [string]$ExternalRoot,
        [string]$Label,
        [string]$InvocationId
    )
    $root = Join-Path $ExternalRoot "$InvocationId-$Label"
    $source = Join-Path $root "source"
    $feed = Join-Path $root "feed"
    $output = Join-Path $root "output"
    New-Item -ItemType Directory -Path $source, $feed, $output -Force |
        Out-Null
    $archive = Join-Path $root "accepted-source.zip"
    Invoke-Checked git @(
        "-C", $RepositoryRoot,
        "archive", "--format=zip",
        "-o", $archive,
        $sourceCommit
    ) $RepositoryRoot
    Expand-Archive -LiteralPath $archive -DestinationPath $source
    $normalizer = Join-Path $source "eng\Normalize-NuGetPackage.ps1"
    Assert-Equal $normalizerSha256 (Get-Hash $normalizer "SHA256") `
        "$Label normalizer SHA-256"
    Assert-Equal $normalizerSha512 (Get-Hash $normalizer "SHA512") `
        "$Label normalizer SHA-512"
    Copy-PackageSet `
        (Join-Path $source "vendor\p14-profile-carrier\packages") $feed
    $config = Join-Path $root "NuGet.Config"
    New-LocalConfig $config $feed
    $sourceLink = Join-Path $root "p10j.sourcelink.json"
    [IO.File]::WriteAllText(
        $sourceLink,
        "{`"documents`":{`"/_/deep-protocol/*`":`"https://raw.githubusercontent.com/XPointLabs/deep-protocol/$sourceCommit/*`"}}",
        [Text.UTF8Encoding]::new($false))
    Set-IsolatedEnvironment $root

    foreach ($spec in $buildSpecs) {
        $project = Join-Path $source "src\$($spec.Id)\$($spec.Id).csproj"
        $properties = @(
            "-p:Version=$($spec.Version)",
            "-p:PackageVersion=$($spec.Version)",
            "-p:RepositoryCommit=$sourceCommit",
            "-p:SourceRevisionId=$sourceCommit",
            "-p:SourceLink=$sourceLink",
            "-p:PathMap=$source=/_/deep-protocol",
            "-p:DeepProtocolPackageVersion=[$protocolVersion]",
            "-p:Deterministic=true",
            "-p:ContinuousIntegrationBuild=true",
            "-p:DebugType=portable",
            "-p:RestoreLockedMode=false"
        )
        Invoke-Checked dotnet (@(
            "restore", $project,
            "--configfile", $config,
            "--packages", $env:NUGET_PACKAGES,
            "--force-evaluate"
        ) + $properties) $source
        Invoke-Checked dotnet (@(
            "pack", $project,
            "--no-restore",
            "--configuration", "Release",
            "--output", $output
        ) + $properties) $source
        $package = Get-PackagePath $output $spec
        Invoke-Checked powershell @(
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", $normalizer,
            "-Path", $package
        ) $source
        Copy-Item -LiteralPath $package -Destination $feed -Force
    }

    foreach ($spec in $packageSpecs) {
        $project = Join-Path $source "src\$($spec.Id)\$($spec.Id).csproj"
        $properties = @(
            "-p:Version=$($spec.Version)",
            "-p:PackageVersion=$($spec.Version)",
            "-p:RepositoryCommit=$sourceCommit",
            "-p:SourceRevisionId=$sourceCommit",
            "-p:SourceLink=$sourceLink",
            "-p:PathMap=$source=/_/deep-protocol",
            "-p:DeepProtocolPackageVersion=[$protocolVersion]",
            "-p:Deterministic=true",
            "-p:ContinuousIntegrationBuild=true",
            "-p:DebugType=portable",
            "-p:RestoreLockedMode=false"
        )
        Invoke-Checked dotnet (@(
            "build", $project,
            "--no-restore",
            "--configuration", "Debug"
        ) + $properties) $source
    }
    return [PSCustomObject]@{
        Root = $root
        Source = $source
        Feed = $feed
        Config = $config
        Output = $output
    }
}

function New-LockedInstallSmoke {
    param([object]$Build)
    $root = Join-Path $Build.Root "locked-install"
    $feed = Join-Path $root "feed"
    New-Item -ItemType Directory -Path $root, $feed -Force | Out-Null
    Copy-PackageSet `
        (Join-Path $Build.Source "vendor\p14-profile-carrier\packages") $feed
    Copy-PackageSet $Build.Output $feed
    $config = Join-Path $root "NuGet.Config"
    New-LocalConfig $config $feed
    $project = Join-Path $root "locked-install-smoke.csproj"
    [IO.File]::WriteAllText(
        $project,
        "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup><PackageReference Include=`"Deep.Protocol`" Version=`"[$protocolVersion]`" /><PackageReference Include=`"Deep.Protocol.MembershipRoutes`" Version=`"[$protocolVersion]`" /><PackageReference Include=`"Deep.Protocol.ProfileCarrier`" Version=`"[$carrierVersion]`" /></ItemGroup></Project>",
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $root "Program.cs"),
        "System.Console.WriteLine(typeof(Program).Assembly.GetName().Name);",
        [Text.UTF8Encoding]::new($false))
    Set-IsolatedEnvironment $root
    Invoke-Checked dotnet @(
        "restore", $project,
        "--configfile", $config,
        "--packages", $env:NUGET_PACKAGES,
        "--force-evaluate"
    ) $root
    Invoke-Checked dotnet @(
        "restore", $project,
        "--configfile", $config,
        "--packages", $env:NUGET_PACKAGES,
        "--locked-mode"
    ) $root
    foreach ($configuration in @("Debug", "Release")) {
        Invoke-Checked dotnet @(
            "build", $project,
            "--no-restore",
            "--configuration", $configuration
        ) $root
    }
    Invoke-Checked dotnet @(
        "run", "--project", $project,
        "--no-build", "--configuration", "Release"
    ) $root
    return Join-Path $root "packages.lock.json"
}

Assert-ExternalRoots
Assert-AcceptedSource $sourceCommit
$resolvedCommit = (& git -C $RepositoryRoot rev-parse `
    "$sourceCommit`^{commit}").Trim()
if ($LASTEXITCODE -ne 0 -or
    $resolvedCommit -ne $sourceCommit -or
    $sourceCommit -notmatch "^[0-9a-f]{40}$") {
    throw "The fixed P10J source must be an available exact full commit."
}
& git -C $RepositoryRoot merge-base --is-ancestor $sourceCommit HEAD
if ($LASTEXITCODE -ne 0) {
    throw "The fixed P10J source must be an ancestor of current HEAD."
}
$provenance = Get-Content -LiteralPath $ProvenancePath -Raw |
    ConvertFrom-Json
Assert-ProvenanceStatic $provenance
$manifest = Get-Content -LiteralPath (
    Join-Path $RepositoryRoot "vendor\p10j-package-closure\package-manifest.json"
) -Raw | ConvertFrom-Json
Assert-VendorManifest $manifest $provenance
Assert-ProvenancePackages $provenance $PublishedRoot
Assert-ProvenanceLock $provenance $PublishedLockPath

if ($PolicySelfTest) {
    Invoke-PolicySelfTest $provenance
    exit 0
}

New-Item -ItemType Directory -Path $WorkRootA, $WorkRootB -Force |
    Out-Null
$invocationId = [Guid]::NewGuid().ToString("N")
$a = Invoke-ClosureBuild $WorkRootA "a" $invocationId
$b = Invoke-ClosureBuild $WorkRootB "b" $invocationId
foreach ($spec in $packageSpecs) {
    $packageA = Get-PackagePath $a.Output $spec
    $packageB = Get-PackagePath $b.Output $spec
    Assert-Equal ([string](Get-Item $packageA).Length) `
        ([string](Get-Item $packageB).Length) `
        "$($spec.Id) A/B byte length"
    Assert-Equal (Get-Hash $packageA "SHA256") `
        (Get-Hash $packageB "SHA256") "$($spec.Id) A/B SHA-256"
    Assert-Equal (Get-Hash $packageA "SHA512") `
        (Get-Hash $packageB "SHA512") "$($spec.Id) A/B SHA-512"
}
Assert-ProvenancePackages $provenance $a.Output
$smokeLock = New-LockedInstallSmoke $a
Assert-ProvenanceLock $provenance $smokeLock

$identityProject = Join-Path $RepositoryRoot `
    "eng\P10JPackageClosure.Identity\P10JPackageClosure.Identity.csproj"
$identityRoot = Join-Path $a.Root "identity"
New-Item -ItemType Directory -Path $identityRoot -Force | Out-Null
Set-IsolatedEnvironment $identityRoot
Invoke-Checked dotnet @(
    "restore", $identityProject,
    "--configfile", $a.Config,
    "--packages", $env:NUGET_PACKAGES
) $RepositoryRoot
Invoke-Checked dotnet @(
    "build", $identityProject,
    "--no-restore",
    "--configuration", "Release"
) $RepositoryRoot
$identityDll = Join-Path $RepositoryRoot `
    "eng\P10JPackageClosure.Identity\bin\Release\net10.0\P10JPackageClosure.Identity.dll"
Invoke-Checked dotnet @(
    $identityDll,
    "--package-root", $a.Output,
    "--lock", $smokeLock,
    "--provenance", $ProvenancePath,
    "--source", $sourceCommit,
    "--protocol-version", $protocolVersion,
    "--carrier-version", $carrierVersion,
    "--self-test"
) $a.Source

# Publishing starts only after A/B, provenance, locked install, and identity pass.
New-Item -ItemType Directory -Path $PublishedRoot -Force | Out-Null
foreach ($spec in $packageSpecs) {
    Copy-Item -LiteralPath (Get-PackagePath $a.Output $spec) `
        -Destination (Get-PackagePath $PublishedRoot $spec) -Force
}
Copy-Item -LiteralPath $smokeLock -Destination $PublishedLockPath -Force
Assert-ProvenancePackages $provenance $PublishedRoot
Assert-ProvenanceLock $provenance $PublishedLockPath

Write-Output "PASS source-commit=$sourceCommit"
Write-Output "protocol-version=$protocolVersion carrier-version=$carrierVersion"
Write-Output "external-work-root-a=$($a.Root)"
Write-Output "external-work-root-b=$($b.Root)"
foreach ($spec in $packageSpecs) {
    $path = Get-PackagePath $PublishedRoot $spec
    Write-Output "$($spec.Id)-bytes=$((Get-Item $path).Length)"
    Write-Output "$($spec.Id)-sha256=$(Get-Hash $path 'SHA256')"
    Write-Output "$($spec.Id)-sha512=$(Get-Hash $path 'SHA512')"
    Write-Output "$($spec.Id)-contentHash=$(Get-ContentHash $path)"
}
Write-Output "locked-install=$PublishedLockPath"
Write-Output "lock-bytes=$((Get-Item $PublishedLockPath).Length)"
Write-Output "lock-sha256=$(Get-Hash $PublishedLockPath 'SHA256')"
Write-Output "lock-sha512=$(Get-Hash $PublishedLockPath 'SHA512')"
Write-Output "release-a-b-byte-identical=true debug-build-verified=true"
