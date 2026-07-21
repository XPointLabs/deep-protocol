[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$XNodeRoot,
    [string]$RepositoryRoot = "",
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "deep-p14-carrier-provenance")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function Invoke-Git {
    param([string[]]$Arguments)
    $result = & git -C $XNodeRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git provenance command failed: $($Arguments -join ' ')"
    }
    return @($result)
}

function Invoke-GitArchive {
    param([string[]]$Arguments, [string]$WorkingDirectory)
    Push-Location $WorkingDirectory
    try {
        & git -C $XNodeRoot @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "The exact accepted XNode archive could not be materialized."
        }
    }
    finally {
        Pop-Location
    }
}

function Get-GitBlobHash {
    param([string]$Path)
    $result = & git -C $XNodeRoot hash-object $Path
    if ($LASTEXITCODE -ne 0) {
        throw "A materialized XNode input could not be hashed."
    }
    return ($result | Out-String).Trim()
}

function Assert-MaterializedFile {
    param(
        [string]$MaterializedRoot,
        [string]$RelativePath,
        [string]$ExpectedBlob
    )
    $path = Join-Path $MaterializedRoot ($RelativePath.Replace("/", "\"))
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The exact XNode archive is missing: $RelativePath."
    }
    if ((Get-GitBlobHash $path) -ne $ExpectedBlob) {
        throw "The materialized XNode source drifted: $RelativePath."
    }
}

function Assert-MaterializedTree {
    param(
        [string]$MaterializedRoot,
        [System.Collections.IDictionary]$ExpectedFiles
    )
    $prefix = $MaterializedRoot.TrimEnd("\") + "\"
    $actualFiles = @(
        Get-ChildItem -LiteralPath $MaterializedRoot -Recurse -File |
            ForEach-Object {
                $_.FullName.Substring($prefix.Length).Replace("\", "/")
            } |
            Sort-Object
    )
    $expectedPaths = @($ExpectedFiles.Keys | Sort-Object)
    $difference = Compare-Object $expectedPaths $actualFiles
    if ($null -ne $difference) {
        throw "The materialized XNode archive file set differs from the accepted tree."
    }
    foreach ($path in $expectedPaths) {
        Assert-MaterializedFile $MaterializedRoot $path $ExpectedFiles[$path]
    }
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$XNodeRoot = (Resolve-Path -LiteralPath $XNodeRoot).Path
$manifestPath = Join-Path $RepositoryRoot `
    "tests\Deep.Protocol.ProfileCarrier.Tests\Vectors\xnode-eff4523.provenance.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne "deep-p14-profile-carrier-provenance-v1") {
    throw "The provenance manifest schema is invalid."
}

$commit = [string]$manifest.sourceCommit
$resolvedCommit = (Invoke-Git @("rev-parse", "$commit^{commit}") |
    Out-String).Trim()
if ($resolvedCommit -ne $commit) {
    throw "The accepted XNode commit is unavailable."
}
$resolvedTree = (Invoke-Git @("rev-parse", "$commit^{tree}") |
    Out-String).Trim()
if ($resolvedTree -ne $manifest.sourceTree) {
    throw "The accepted XNode tree identity differs."
}
foreach ($file in $manifest.files) {
    $acceptedBlob = (Invoke-Git @(
        "rev-parse",
        "$commit`:$($file.path)"
    ) | Out-String).Trim()
    if ($acceptedBlob -ne $file.gitBlob) {
        throw "Accepted XNode blob identity differs: $($file.path)."
    }
}

$treeFiles = [ordered]@{}
foreach ($line in Invoke-Git @("ls-tree", "-r", $commit)) {
    if ($line -notmatch "^[0-9]{6} blob ([0-9a-f]{40})`t(.+)$") {
        throw "The accepted XNode tree contains an unsupported non-blob entry."
    }
    $treeFiles[$Matches[2]] = $Matches[1]
}
if ($treeFiles.Count -eq 0) {
    throw "The accepted XNode tree is empty."
}

$workBase = [System.IO.Path]::GetFullPath($WorkRoot)
New-Item -ItemType Directory -Path $workBase -Force | Out-Null
$resolvedWorkRoot = Join-Path $workBase "run-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $resolvedWorkRoot | Out-Null
$archive = Join-Path $resolvedWorkRoot "xnode-eff4523.zip"
$materializedRoot = Join-Path $resolvedWorkRoot "xnode-eff4523"
Invoke-GitArchive @(
    "archive", "--format=zip",
    "-o", $archive,
    $commit
) $resolvedWorkRoot
Expand-Archive -LiteralPath $archive -DestinationPath $materializedRoot
Assert-MaterializedTree $materializedRoot $treeFiles

$driftPath = "src/XNode.ProfileGenerator/DormantProfileComposer.cs"
$driftFile = Join-Path $materializedRoot ($driftPath.Replace("/", "\"))
$exactBytes = [System.IO.File]::ReadAllBytes($driftFile)
try {
    [System.IO.File]::WriteAllBytes($driftFile, [byte[]](@($exactBytes) + 0))
    $driftWasRejected = $false
    try {
        Assert-MaterializedFile $materializedRoot $driftPath $treeFiles[$driftPath]
    }
    catch {
        $driftWasRejected = $true
    }
    if (!$driftWasRejected) {
        throw "The provenance validator accepted a deliberate source drift."
    }
}
finally {
    [System.IO.File]::WriteAllBytes($driftFile, $exactBytes)
}
Assert-MaterializedTree $materializedRoot $treeFiles
Write-Output "source-drift-rejection=PASS"

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
$env:DOTNET_NOLOGO = "1"

$project = Join-Path $RepositoryRoot `
    "eng\P14ProfileCarrier.Differential\P14ProfileCarrier.Differential.csproj"
$config = Join-Path $RepositoryRoot "eng\p14-profile-carrier.NuGet.Config"
& dotnet restore $project `
    --configfile $config `
    --locked-mode `
    --packages $packagesHome `
    -p:XNodeRoot=$materializedRoot `
    -p:RestoreNoCache=true
if ($LASTEXITCODE -ne 0) {
    throw "The locked differential restore failed."
}
$output = & dotnet run `
    --project $project `
    --no-restore `
    --configuration Release `
    -p:XNodeRoot=$materializedRoot
if ($LASTEXITCODE -ne 0) {
    throw "The exact accepted XNode differential gate failed."
}
$expected = "PASS $($manifest.goldenSha256)"
if (($output | Select-Object -Last 1) -ne $expected) {
    throw "The differential gate output differs from the accepted golden hash."
}
Write-Output "materialized-commit=$commit tree=$($manifest.sourceTree) files=$($treeFiles.Count)"
Write-Output $expected
