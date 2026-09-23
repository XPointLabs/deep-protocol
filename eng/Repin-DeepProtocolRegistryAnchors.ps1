[CmdletBinding()]
param([switch] $Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$workspaceRoot = Split-Path $repoRoot -Parent
$registryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.json'
$raw = [IO.File]::ReadAllText($registryPath)
$registry = $raw | ConvertFrom-Json
$sources = @{}
foreach ($source in $registry.sources) { $sources[[string]$source.id] = $source }
$anchorMatches = [regex]::Matches($raw, '(?s)"sourceAnchor"\s*:\s*\{.*?\n[ \t]*\}')
$output = [Text.StringBuilder]::new()
$cursor = 0
$updates = 0
$failures = [Collections.Generic.List[string]]::new()

foreach ($match in $anchorMatches) {
    [void]$output.Append($raw.Substring($cursor, $match.Index - $cursor))
    $anchor = ("{$($match.Value)}" | ConvertFrom-Json).sourceAnchor
    $source = $sources[[string]$anchor.anchorSourceId]
    if ($null -eq $source -or $source.kind -eq 'production-source-scan') {
        $failures.Add("$($anchor.scope)/$($anchor.id): unknown normative source")
        [void]$output.Append($match.Value)
        $cursor = $match.Index + $match.Length
        continue
    }
    $path = Join-Path $workspaceRoot $source.path
    $lines = [IO.File]::ReadAllText($path).Replace("`r`n", "`n").Split("`n")
    $headings = [string[]]::new($lines.Length)
    $heading = ''
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '^#{1,6} ') { $heading = $lines[$i] }
        $headings[$i] = $heading
    }
    $width = [int]$anchor.endLine - [int]$anchor.startLine + 1
    $candidates = [Collections.Generic.List[object]]::new()
    for ($i = 0; $i + $width -le $lines.Length; $i++) {
        if ($headings[$i] -cne [string]$anchor.section) { continue }
        if ($width -eq 1 -and $anchor.anchorSourceId -eq 'protocol-registry-v1' -and
            -not ([string]$anchor.scope).StartsWith('alias:', [StringComparison]::Ordinal)) {
            $cells = $lines[$i].Split('|')
            if ($cells.Length -lt 3) { continue }
            $first = $cells[1].Trim()
            $second = $cells[2].Trim()
            $bound = switch -Wildcard ([string]$anchor.scope) {
                'magic' { $first.Contains("``$($anchor.id)``", [StringComparison]::Ordinal) }
                'suite:*' { $first -ceq "``$(([string]$anchor.id).Split(':')[-1])``" }
                'carrier' { $first -ceq "``$($anchor.id)``" }
                'deployment-profile' { $first -ceq "``$($anchor.id)``" }
                'call:*' {
                    $first -ceq ([string]$anchor.scope).Substring(5).Replace('-', ' ') -and
                    $second -ceq "``$($anchor.name)``"
                }
                'interface' { $first -ceq "``$($anchor.name)``" }
                default { $false }
            }
            if (-not $bound) { continue }
        }
        $range = ($lines[$i..($i + $width - 1)] -join "`n") + "`n"
        $allEvidence = $true
        foreach ($token in $anchor.evidenceTokens) {
            if (-not $range.Contains([string]$token, [StringComparison]::Ordinal)) {
                $allEvidence = $false
                break
            }
        }
        if ($allEvidence) {
            $candidates.Add([pscustomobject]@{
                Start = $i + 1
                Range = $range
                Distance = [Math]::Abs(($i + 1) - [int]$anchor.startLine)
            })
        }
    }
    if ($candidates.Count -eq 0) {
        $failures.Add("$($anchor.scope)/$($anchor.id): evidence missing in $($anchor.section)")
        [void]$output.Append($match.Value)
        $cursor = $match.Index + $match.Length
        continue
    }
    $selected = @($candidates | Sort-Object Distance, Start)[0]
    $start = [int]$selected.Start
    $end = $start + $width - 1
    $hash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes([string]$selected.Range))).ToLowerInvariant()
    $replacement = [regex]::Replace($match.Value, '("startLine"\s*:\s*)\d+', "`${1}$start")
    $replacement = [regex]::Replace($replacement, '("endLine"\s*:\s*)\d+', "`${1}$end")
    $replacement = [regex]::Replace(
        $replacement, '("normalizedSha256"\s*:\s*")[0-9a-f]{64}(" )?',
        { param($found) $found.Groups[1].Value + $hash + $found.Value.Substring($found.Groups[1].Length + 64) })
    [void]$output.Append($replacement)
    if ($replacement -cne $match.Value) { $updates++ }
    $cursor = $match.Index + $match.Length
}
[void]$output.Append($raw.Substring($cursor))

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Error $failure }
    throw "Registry repin halted with $($failures.Count) unresolved normative anchors."
}
Write-Output "Validated $($anchorMatches.Count) normative anchors; $updates need mechanical repin."
if ($Apply) {
    [IO.File]::WriteAllText($registryPath, $output.ToString(), [Text.UTF8Encoding]::new($false))
    Write-Output 'Applied line/hash updates; review the diff and run the strict generator.'
}
