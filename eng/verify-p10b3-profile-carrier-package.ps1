[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$ProtocolPackageRoot = "",
    [string]$WorkRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$contractCommit = "60ce2e3a5140f245d6bcfecf60fa456c26ffe730"
$protocolVersion = "0.3.0-p10b3.60ce2e3"
$carrierVersion = "0.2.0-p10b3.60ce2e3"
$normalizerSha256 = "237891f23c12f04bc799ab485ff4a297dca78af9bb0d0bb4002a8d507c1c0343"
$normalizerSha512 = "53b31b3f1e353a8b746a54750d1711f1ed328897eb186487a6e33a848380675bf07494c68b7f611eedaa25c077061ee1eb71fcac0fa49b2ba371ddb6b0deb044"
$protocolPackages = @(
    "Deep.Protocol.$protocolVersion.nupkg",
    "Deep.Protocol.Abstractions.$protocolVersion.nupkg",
    "Deep.Protocol.Protobuf.$protocolVersion.nupkg"
)

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if ([string]::IsNullOrWhiteSpace($ProtocolPackageRoot)) {
    $ProtocolPackageRoot = Join-Path $RepositoryRoot "artifacts\survival\P10B3\60ce2e3\packages"
}
$ProtocolPackageRoot = (Resolve-Path -LiteralPath $ProtocolPackageRoot).Path
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path $RepositoryRoot "artifacts\survival\P10B3\60ce2e3\profile-carrier"
}
$WorkRoot = [IO.Path]::GetFullPath($WorkRoot)

function Invoke-Checked {
    param([string]$File, [string[]]$Arguments, [string]$WorkingDirectory)
    Push-Location $WorkingDirectory
    try {
        & $File @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
    }
    finally { Pop-Location }
}

function Get-Hash {
    param([string]$Path, [string]$Algorithm)
    return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

function Assert-Equal {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Expected -ne $Actual) { throw "$Label differs; the two normalized packages are not byte-identical." }
}

function Copy-FileSet {
    param([string]$From, [string]$To)
    Get-ChildItem -LiteralPath $From -File -Filter "*.nupkg" | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $To $_.Name) -Force
    }
}

$normalizer = Join-Path $RepositoryRoot "eng\Normalize-NuGetPackage.ps1"
Assert-Equal $normalizerSha256 (Get-Hash $normalizer "SHA256") "Normalize-NuGetPackage.ps1 SHA-256"
Assert-Equal $normalizerSha512 (Get-Hash $normalizer "SHA512") "Normalize-NuGetPackage.ps1 SHA-512"
foreach ($package in $protocolPackages) {
    if (!(Test-Path -LiteralPath (Join-Path $ProtocolPackageRoot $package))) {
        throw "The accepted P10B3 protocol package is unavailable: $package"
    }
}

$dirty = & git -C $RepositoryRoot status --porcelain=v1
if ($LASTEXITCODE -ne 0 -or $null -ne $dirty) {
    throw "The P10B3 carrier package gate requires an exact clean committed HEAD."
}
$head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch "^[0-9a-f]{40}$") {
    throw "The current reviewed carrier source commit could not be resolved."
}

New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
$runRoot = Join-Path $WorkRoot "run-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $runRoot | Out-Null
$results = @()

foreach ($label in @("pack-a", "pack-b")) {
    $root = Join-Path $runRoot $label
    $archive = Join-Path $root "source.zip"
    $source = Join-Path $root "source"
    $feed = Join-Path $root "feed"
    $output = Join-Path $root "output"
    $cliHome = Join-Path $root "cli-home"
    $packagesHome = Join-Path $root "packages-home"
    New-Item -ItemType Directory -Path $source, $feed, $output, $cliHome, $packagesHome -Force | Out-Null
    Invoke-Checked "git" @("-C", $RepositoryRoot, "archive", "--format=zip", "-o", $archive, $head) $RepositoryRoot
    Expand-Archive -LiteralPath $archive -DestinationPath $source
    Copy-FileSet (Join-Path $source "vendor\p14-profile-carrier\packages") $feed
    Copy-FileSet $ProtocolPackageRoot $feed
    $config = Join-Path $root "NuGet.Config"
    $feedUri = [Uri]::new($feed).AbsoluteUri
    Set-Content -LiteralPath $config -NoNewline -Encoding utf8 @"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$feedUri" /></packageSources></configuration>
"@
    $env:DOTNET_CLI_HOME = $cliHome
    $env:APPDATA = (Join-Path $root "appdata")
    $env:NUGET_PACKAGES = $packagesHome
    $env:NUGET_HTTP_CACHE_PATH = (Join-Path $root "http-cache")
    $env:HTTP_PROXY = "http://127.0.0.1:9"
    $env:HTTPS_PROXY = "http://127.0.0.1:9"
    $env:ALL_PROXY = "http://127.0.0.1:9"
    $env:NO_PROXY = ""
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:DOTNET_NOLOGO = "1"
    $project = Join-Path $source "src\Deep.Protocol.ProfileCarrier\Deep.Protocol.ProfileCarrier.csproj"
    $properties = @(
        "-p:Version=$carrierVersion",
        "-p:PackageVersion=$carrierVersion",
        "-p:RepositoryCommit=$contractCommit",
        "-p:DeepProtocolPackageVersion=[$protocolVersion]",
        "-p:Deterministic=true",
        "-p:ContinuousIntegrationBuild=true",
        "-p:RestoreLockedMode=false"
    )
    Invoke-Checked "dotnet" (@("restore", $project, "--configfile", $config, "--packages", $packagesHome, "--force-evaluate") + $properties) $source
    Invoke-Checked "dotnet" (@("build", $project, "--no-restore", "--configuration", "Release") + $properties) $source
    Invoke-Checked "dotnet" (@("pack", $project, "--no-restore", "--no-build", "--configuration", "Release", "--output", $output) + $properties) $source
    $package = Join-Path $output "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
    Invoke-Checked "powershell" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $normalizer, "-Path", $package) $source
    $results += [PSCustomObject]@{
        Package = $package
        Sha256 = Get-Hash $package "SHA256"
        Sha512 = Get-Hash $package "SHA512"
        Bytes = (Get-Item -LiteralPath $package).Length
    }
}

Assert-Equal $results[0].Sha256 $results[1].Sha256 "normalized package SHA-256"
Assert-Equal $results[0].Sha512 $results[1].Sha512 "normalized package SHA-512"
Assert-Equal ([string]$results[0].Bytes) ([string]$results[1].Bytes) "normalized package byte length"

$smokeRoot = Join-Path $runRoot "locked-install-smoke"
$smokeFeed = Join-Path $smokeRoot "feed"
$smokePackages = Join-Path $smokeRoot "packages-home"
New-Item -ItemType Directory -Path $smokeRoot, $smokeFeed, $smokePackages -Force | Out-Null
Copy-FileSet (Join-Path $RepositoryRoot "vendor\p14-profile-carrier\packages") $smokeFeed
Copy-FileSet $ProtocolPackageRoot $smokeFeed
Copy-Item -LiteralPath $results[0].Package -Destination (Join-Path $smokeFeed "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg") -Force
$smokeConfig = Join-Path $smokeRoot "NuGet.Config"
$smokeFeedUri = [Uri]::new($smokeFeed).AbsoluteUri
Set-Content -LiteralPath $smokeConfig -NoNewline -Encoding utf8 @"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$smokeFeedUri" /></packageSources></configuration>
"@
$smokeProject = Join-Path $smokeRoot "locked-install-smoke.csproj"
Set-Content -LiteralPath $smokeProject -NoNewline -Encoding utf8 @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup><PackageReference Include="Deep.Protocol.ProfileCarrier" Version="[$carrierVersion]" /><PackageReference Include="Deep.Protocol" Version="[$protocolVersion]" /></ItemGroup></Project>
"@
Set-Content -LiteralPath (Join-Path $smokeRoot "Program.cs") -NoNewline -Encoding utf8 "System.Console.WriteLine(typeof(Program).Assembly.GetName().Name);"
$env:DOTNET_CLI_HOME = Join-Path $smokeRoot "cli-home"
$env:APPDATA = Join-Path $smokeRoot "appdata"
$env:NUGET_PACKAGES = $smokePackages
$env:NUGET_HTTP_CACHE_PATH = Join-Path $smokeRoot "http-cache"
Invoke-Checked "dotnet" @("restore", $smokeProject, "--configfile", $smokeConfig, "--packages", $smokePackages, "--force-evaluate") $smokeRoot
Invoke-Checked "dotnet" @("restore", $smokeProject, "--configfile", $smokeConfig, "--packages", $smokePackages, "--locked-mode") $smokeRoot
Invoke-Checked "dotnet" @("build", $smokeProject, "--no-restore", "--configuration", "Release") $smokeRoot
Invoke-Checked "dotnet" @("run", "--project", $smokeProject, "--no-build", "--configuration", "Release") $smokeRoot
$lockPath = Join-Path $smokeRoot "packages.lock.json"
$lock = Get-Content -LiteralPath $lockPath -Raw
if ($lock -notmatch [regex]::Escape('"Deep.Protocol.ProfileCarrier": {') -or
    $lock -notmatch [regex]::Escape("$protocolVersion")) {
    throw "The locked install smoke did not resolve the exact P10B3 carrier and protocol graph."
}

$finalOutput = Join-Path $WorkRoot "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg"
Copy-Item -LiteralPath $results[0].Package -Destination $finalOutput -Force
$finalLock = Join-Path $WorkRoot "install-smoke.packages.lock.json"
Copy-Item -LiteralPath $lockPath -Destination $finalLock -Force
Write-Output "PASS carrier-source-commit=$head protocol-source-commit=$contractCommit"
Write-Output "package=$finalOutput"
Write-Output "bytes=$($results[0].Bytes)"
Write-Output "sha256=$($results[0].Sha256)"
Write-Output "sha512=$($results[0].Sha512)"
Write-Output "independent-rebuild-byte-identical=true"
Write-Output "locked-install-smoke-lock=$finalLock"
