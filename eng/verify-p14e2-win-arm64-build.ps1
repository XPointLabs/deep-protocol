[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$WorkRoot = (Join-Path `
        ([System.IO.Path]::GetTempPath()) "deep-p14e2-win-arm64")
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

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch "^[0-9a-f]{40}$") {
    throw "A committed source revision is required."
}

$runRoot = Join-Path ([System.IO.Path]::GetFullPath($WorkRoot)) `
    "run-$([Guid]::NewGuid().ToString('N'))"
$sourceRoot = Join-Path $runRoot "source"
$archive = Join-Path $runRoot "source.zip"
$packages = Join-Path $runRoot "packages"
$cliHome = Join-Path $runRoot "cli-home"
New-Item -ItemType Directory -Path $sourceRoot, $packages, $cliHome -Force |
    Out-Null
Invoke-Checked "git" @(
    "-C", $RepositoryRoot,
    "archive", "--format=zip", "-o", $archive, $head
) $RepositoryRoot
Expand-Archive -LiteralPath $archive -DestinationPath $sourceRoot

$env:DOTNET_CLI_HOME = $cliHome
$env:NUGET_PACKAGES = $packages
$env:NUGET_HTTP_CACHE_PATH = Join-Path $runRoot "http-cache"
$env:HTTP_PROXY = "http://127.0.0.1:9"
$env:HTTPS_PROXY = "http://127.0.0.1:9"
$env:ALL_PROXY = "http://127.0.0.1:9"
$env:NO_PROXY = ""
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

$project = Join-Path $sourceRoot `
    "src\Deep.Protocol.ProfileCarrier\Deep.Protocol.ProfileCarrier.csproj"
$config = Join-Path $sourceRoot "eng\p14-profile-carrier.NuGet.Config"
$disabledLock = Join-Path $runRoot "rid-probe-no-lock.json"
$properties = @(
    "-p:RestorePackagesWithLockFile=false",
    "-p:NuGetLockFilePath=$disabledLock",
    "-p:EnableRuntimePackDownload=false",
    "-p:DisableTransitiveFrameworkReferenceDownloads=true",
    "-p:SelfContained=false",
    "-p:UseAppHost=false"
)

Invoke-Checked "dotnet" (@(
    "restore", $project,
    "--runtime", "win-arm64",
    "--configfile", $config,
    "--packages", $packages,
    "-p:RestoreNoCache=true",
    "-p:NuGetAudit=false"
) + $properties) $sourceRoot
Invoke-Checked "dotnet" (@(
    "build", $project,
    "--configuration", "Release",
    "--runtime", "win-arm64",
    "--no-restore"
) + $properties) $sourceRoot

$assetsPath = Join-Path $sourceRoot `
    "src\Deep.Protocol.ProfileCarrier\obj\project.assets.json"
$assetsText = Get-Content -LiteralPath $assetsPath -Raw
$selectedPath = "runtimes/win-arm64/native/libsodium.dll"
if (-not $assetsText.Contains($selectedPath, [StringComparison]::Ordinal)) {
    throw "The win-arm64 restore did not select the exact libsodium asset."
}
$assembly = Get-Item -LiteralPath (Join-Path $sourceRoot `
    "src\Deep.Protocol.ProfileCarrier\bin\Release\net10.0\win-arm64\" +
    "Deep.Protocol.ProfileCarrier.dll")
$assemblyHash = (Get-FileHash -LiteralPath $assembly.FullName -Algorithm SHA256).
    Hash.ToLowerInvariant()

Write-Output "win-arm64-build=PASS repository-commit=$head"
Write-Output "win-arm64-assembly-sha256=$assemblyHash"
Write-Output "win-arm64-selected-native-asset=$selectedPath"
