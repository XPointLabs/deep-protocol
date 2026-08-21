[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$corpus = Join-Path $root 'reference/session-compatibility-v0'
$manifestPath = Join-Path $corpus 'MANIFEST.json'
$sumsPath = Join-Path $corpus 'SHA256SUMS'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema -cne 'deep-offline-reference-corpus.v1' -or
    $manifest.sourceCommit -cne '586054ae9787a0df620c1da30b588edb89e7f7da' -or
    $manifest.mode -cne 'immutable-offline-reference-only' -or
    $manifest.canonicalization -cne 'utf8-preserve-bom-lf') {
    throw 'Reference corpus manifest identity differs.'
}
$entries = @($manifest.entries)
$paths = @($entries | ForEach-Object { [string]$_.path })
if (($paths -join "`n") -cne (@($paths | Sort-Object -CaseSensitive) -join "`n") -or
    @($paths | Select-Object -Unique).Count -ne $paths.Count) {
    throw 'Reference corpus manifest paths are not canonical sorted unique paths.'
}
$sumLines = [Collections.Generic.List[string]]::new()
foreach ($entry in $entries) {
    $relative = [string]$entry.path
    if ($relative.StartsWith('/') -or $relative.Contains('\') -or $relative.Contains('..')) {
        throw "Unsafe corpus path: $relative"
    }
    $path = Join-Path $corpus ($relative.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Corpus file missing: $relative" }
    $raw = [IO.File]::ReadAllBytes($path)
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($raw)
    $canonical = [Text.UTF8Encoding]::new($false).GetBytes(
        $text.Replace("`r`n", "`n").Replace("`r", "`n"))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($algorithm.ComputeHash($canonical))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
    if ($hash -cne [string]$entry.sha256) { throw "Corpus hash differs: $relative" }
    if ([long]$entry.bytes -ne $canonical.Length) { throw "Corpus canonical byte length differs: $relative" }
    $sumLines.Add("$hash  $relative")
}
$actualFiles = @(Get-ChildItem -LiteralPath $corpus -Recurse -File | ForEach-Object {
    $_.FullName.Substring($corpus.Length + 1).Replace('\', '/')
} | Where-Object { $_ -notin @('MANIFEST.json', 'SHA256SUMS', 'README.md') } | Sort-Object -CaseSensitive)
if (($actualFiles -join "`n") -cne ($paths -join "`n")) { throw 'Corpus contains unmanifested or missing evidence files.' }
$expectedSums = ($sumLines -join "`n") + "`n"
$actualSums = [IO.File]::ReadAllText($sumsPath, [Text.UTF8Encoding]::new($false))
if ($actualSums -cne $expectedSums) { throw 'SHA256SUMS is not canonical LF sorted content.' }
Write-Output "PASS immutable offline reference corpus ($($entries.Count) files)"
