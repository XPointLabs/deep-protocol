[CmdletBinding()]
param(
    [string]$NdkRoot = (Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk\28.2.13676358')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$gate = Join-Path $PSScriptRoot 'Test-DeepMlKemBraidEvidence.ps1'
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$requiredFiles = @(
    'native/Deep.MlKemBraid/.gitattributes',
    'native/Deep.MlKemBraid/Cargo.lock',
    'native/Deep.MlKemBraid/Cargo.toml',
    'native/Deep.MlKemBraid/rust-toolchain.toml',
    'native/Deep.MlKemBraid/src/lib.rs',
    'native/Deep.MlKemBraid/include/deep_mlkem_braid_v1.h',
    'native/Deep.MlKemBraid/third-party/libcrux/provenance.json',
    'native/Deep.MlKemBraid/third-party/libcrux/LICENSE-APACHE',
    'native/Deep.MlKemBraid/third-party/libcrux/LICENSE-MIT',
    'native/Deep.MlKemBraid/evidence/candidate-manifest.v1.json',
    'native/Deep.MlKemBraid/evidence/candidate-windows-x64-sbom.cdx.json',
    'native/Deep.MlKemBraid/evidence/candidate-android-arm64-sbom.cdx.json',
    'native/Deep.MlKemBraid/target/x86_64-pc-windows-msvc/release/deep_mlkem_braid.dll',
    'native/Deep.MlKemBraid/target/aarch64-linux-android/release/libdeep_mlkem_braid.so',
    'eng/.gitattributes',
    'eng/Build-DeepMlKemBraid.ps1',
    'eng/Deep.MlKemBraid.NativeProbe/deep_mlkem_braid_probe.c',
    'eng/Deep.MlKemBraid.AndroidProbe/deep_mlkem_braid_android_probe.c'
)

function New-EvidenceFixture {
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ("deep-mlkem-braid-evidence-$([Guid]::NewGuid().ToString('N'))")
    New-Item -ItemType Directory -Path $fixture | Out-Null
    foreach ($relativePath in $requiredFiles) {
        $source = Join-Path $repositoryRoot ($relativePath.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required fixture source is absent: $relativePath"
        }
        $destination = Join-Path $fixture ($relativePath.Replace('/', '\'))
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    return (Resolve-Path -LiteralPath $fixture).Path
}

function Remove-EvidenceFixture([string]$Fixture) {
    $resolved = (Resolve-Path -LiteralPath $Fixture).Path
    if (-not $resolved.StartsWith($temporaryParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notmatch '^deep-mlkem-braid-evidence-[0-9a-f]{32}$') {
        throw "Refusing to remove an unexpected fixture path: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Invoke-ExpectedRejection([string]$Name, [scriptblock]$Mutate, [string]$ExpectedMessage) {
    $fixture = New-EvidenceFixture
    try {
        & $Mutate $fixture
        try {
            $output = @(& $gate -RepositoryRoot $fixture -NdkRoot $NdkRoot 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
            $accepted = $true
        } catch {
            $accepted = $false
            $output = $_ | Out-String
        }
        if ($accepted) {
            throw "$Name drift was unexpectedly accepted."
        }
        if ($output -notmatch [regex]::Escape($ExpectedMessage)) {
            throw "$Name rejected for an unexpected reason: $output"
        }
        Write-Output "PASS reject-$Name"
    } finally {
        if (Test-Path -LiteralPath $fixture -PathType Container) {
            Remove-EvidenceFixture $fixture
        }
    }
}

$baseline = & $gate -RepositoryRoot $repositoryRoot -NdkRoot $NdkRoot
if ($LASTEXITCODE -ne 0 -or ($baseline | Out-String) -notmatch '"status":"pass"') {
    throw 'The unmodified evidence baseline did not pass.'
}
Write-Output 'PASS accept-exact-baseline'

Invoke-ExpectedRejection 'cargo-lock-drift' {
    param($fixture)
    Add-Content -LiteralPath (Join-Path $fixture 'native\Deep.MlKemBraid\Cargo.lock') -Value '# drift'
} 'File length drift for native/Deep.MlKemBraid/Cargo.lock.'

Invoke-ExpectedRejection 'libcrux-provenance-drift' {
    param($fixture)
    Add-Content -LiteralPath (Join-Path $fixture 'native\Deep.MlKemBraid\third-party\libcrux\provenance.json') -Value ' '
} 'File length drift for native/Deep.MlKemBraid/third-party/libcrux/provenance.json.'

Invoke-ExpectedRejection 'windows-artifact-drift' {
    param($fixture)
    $path = Join-Path $fixture 'native\Deep.MlKemBraid\target\x86_64-pc-windows-msvc\release\deep_mlkem_braid.dll'
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $original = $stream.ReadByte()
        $stream.Position = 0
        $stream.WriteByte(($original -bxor 1))
    } finally {
        $stream.Dispose()
    }
} 'SHA-256 drift for native/Deep.MlKemBraid/target/x86_64-pc-windows-msvc/release/deep_mlkem_braid.dll.'

Invoke-ExpectedRejection 'android-sbom-drift' {
    param($fixture)
    Add-Content -LiteralPath (Join-Path $fixture 'native\Deep.MlKemBraid\evidence\candidate-android-arm64-sbom.cdx.json') -Value ' '
} 'Android SBOM file hash differs.'

Invoke-ExpectedRejection 'windows-arm64-status-drift' {
    param($fixture)
    $path = Join-Path $fixture 'native\Deep.MlKemBraid\evidence\candidate-manifest.v1.json'
    $text = Get-Content -LiteralPath $path -Raw
    $changed = $text.Replace('"status": "pending"', '"status": "evidenced-candidate"')
    if ($changed -ceq $text) {
        throw 'Unable to create the Windows arm64 status fixture.'
    }
    [IO.File]::WriteAllText($path, $changed, [Text.UTF8Encoding]::new($false))
} "Windows arm64 status differs. Expected 'pending'; actual 'evidenced-candidate'."

Invoke-ExpectedRejection 'unknown-manifest-field' {
    param($fixture)
    $path = Join-Path $fixture 'native\Deep.MlKemBraid\evidence\candidate-manifest.v1.json'
    $text = Get-Content -LiteralPath $path -Raw
    $changed = $text.Replace('"releaseDisposition": "candidate-evidence-only",', '"releaseDisposition": "candidate-evidence-only",' + "`n  " + '"unreviewed": true,')
    if ($changed -ceq $text) {
        throw 'Unable to create the unknown manifest-field fixture.'
    }
    [IO.File]::WriteAllText($path, $changed, [Text.UTF8Encoding]::new($false))
} 'manifest properties count differs.'

[ordered]@{
    schema = 'deep-mlkem-braid-evidence-drift-test-result.v1'
    status = 'pass'
    acceptedBaselines = 1
    rejectedDriftCases = 6
} | ConvertTo-Json -Compress
