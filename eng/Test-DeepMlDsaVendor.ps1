$ErrorActionPreference = 'Stop'

$nativeRoot = Join-Path $PSScriptRoot '..\native\Deep.MlDsa'
$vendorRoot = (Resolve-Path -LiteralPath (Join-Path $nativeRoot 'vendor\mldsa-native')).Path
$manifestPath = Join-Path $nativeRoot 'vendor\mldsa-native.provenance.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

if ($manifest.schemaVersion -ne 1 -or
    $manifest.upstreamCommit -ne '834a90d5e846ffa1e1611bd24e160bb2e9b86d35' -or
    $manifest.upstreamMlDsaTreeGitSha1 -ne '8a16ff246ec175f23827313ae8b4cde2cb801a8b') {
    throw 'ML-DSA vendor provenance pin is invalid.'
}

$files = @(Get-ChildItem -LiteralPath $vendorRoot -File -Recurse | ForEach-Object {
    $_.FullName.Substring($vendorRoot.Length + 1).Replace('\', '/')
})
[Array]::Sort($files, [StringComparer]::Ordinal)
if ($files.Count -ne $manifest.fileCount) {
    throw "ML-DSA vendor file count changed: $($files.Count)."
}

$builder = [System.Text.StringBuilder]::new()
foreach ($relative in $files) {
    $path = Join-Path $vendorRoot $relative.Replace('/', '\')
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [void]$builder.Append($relative).Append(' ').Append($hash).Append("`n")
}
$actual = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($builder.ToString()))).ToLowerInvariant()
if ($actual -ne $manifest.sourceSnapshotSha256) {
    throw "ML-DSA vendor snapshot digest changed: $actual."
}

Write-Output "ML-DSA vendor source verified: $($files.Count) files, SHA-256 $actual."
