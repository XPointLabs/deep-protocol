[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$XNodeRoot,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "deep-p14-carrier-provenance")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Git {
    param([string[]]$Arguments)
    $result = & git -C $XNodeRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git provenance command failed: $($Arguments -join ' ')"
    }
    return ($result | Out-String).Trim()
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$XNodeRoot = (Resolve-Path -LiteralPath $XNodeRoot).Path
$manifestPath = Join-Path $RepositoryRoot `
    "tests\Deep.Protocol.ProfileCarrier.Tests\Vectors\xnode-eff4523.provenance.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne "deep-p14-profile-carrier-provenance-v1") {
    throw "The provenance manifest schema is invalid."
}

$commit = $manifest.sourceCommit
if ((Invoke-Git @("rev-parse", "$commit^{commit}")) -ne $commit) {
    throw "The accepted XNode commit is unavailable."
}
if ((Invoke-Git @("rev-parse", "$commit^{tree}")) -ne $manifest.sourceTree) {
    throw "The accepted XNode tree identity differs."
}
foreach ($file in $manifest.files) {
    $acceptedBlob = Invoke-Git @("rev-parse", "$commit`:$($file.path)")
    if ($acceptedBlob -ne $file.gitBlob) {
        throw "Accepted XNode blob identity differs: $($file.path)."
    }
    $workingPath = Join-Path $XNodeRoot ($file.path.Replace("/", "\"))
    $workingBlob = Invoke-Git @("hash-object", $workingPath)
    if ($workingBlob -ne $file.gitBlob) {
        throw "The differential source drifted from the accepted blob: $($file.path)."
    }
}

$workBase = [System.IO.Path]::GetFullPath($WorkRoot)
New-Item -ItemType Directory -Path $workBase -Force | Out-Null
$resolvedWorkRoot = Join-Path $workBase "run-$([Guid]::NewGuid().ToString('N'))"
$cliHome = Join-Path $resolvedWorkRoot "empty-cli-home"
$packagesHome = Join-Path $resolvedWorkRoot "empty-packages"
New-Item -ItemType Directory -Path $cliHome, $packagesHome | Out-Null
$env:DOTNET_CLI_HOME = $cliHome
$env:NUGET_PACKAGES = $packagesHome
$env:NUGET_HTTP_CACHE_PATH = (Join-Path $resolvedWorkRoot "empty-http-cache")
$env:HTTP_PROXY = "http://127.0.0.1:9"
$env:HTTPS_PROXY = "http://127.0.0.1:9"
$env:ALL_PROXY = "http://127.0.0.1:9"
$env:NO_PROXY = ""
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

$project = Join-Path $RepositoryRoot `
    "eng\P14ProfileCarrier.Differential\P14ProfileCarrier.Differential.csproj"
$config = Join-Path $RepositoryRoot "eng\p14-profile-carrier.NuGet.Config"
& dotnet restore $project `
    --configfile $config `
    --locked-mode `
    --packages $packagesHome `
    -p:XNodeRoot=$XNodeRoot `
    -p:RestoreNoCache=true
if ($LASTEXITCODE -ne 0) {
    throw "The locked differential restore failed."
}
$output = & dotnet run `
    --project $project `
    --no-restore `
    --configuration Release `
    -p:XNodeRoot=$XNodeRoot
if ($LASTEXITCODE -ne 0) {
    throw "The XNode differential gate failed."
}
$expected = "PASS $($manifest.goldenSha256)"
if (($output | Select-Object -Last 1) -ne $expected) {
    throw "The differential gate output differs from the accepted golden hash."
}
Write-Output $expected
