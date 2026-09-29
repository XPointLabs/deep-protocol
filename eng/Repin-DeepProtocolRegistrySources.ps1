[CmdletBinding()]
param([switch]$Apply)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$workspaceRoot = Split-Path $repoRoot -Parent
$registryPath = Join-Path $repoRoot 'registry/deep-protocol-v1.registry.json'
$raw = [IO.File]::ReadAllText($registryPath)
$registry = $raw | ConvertFrom-Json
# Reuse the strict generator's inventory implementation, never a second scan grammar.
$generator = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Generate-DeepProtocolRegistry.ps1'))
$ast = [Management.Automation.Language.Parser]::ParseInput($generator, [ref]$null, [ref]$null)
foreach ($name in @('Get-Sha256Hex', 'Get-NormalizedTextSha256', 'Get-ProductionWireInventory')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
    if ($null -eq $function) { throw "Strict generator function is absent: $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
$inventory = Get-ProductionWireInventory $repoRoot $registry.productionInventory
$changes = 0
foreach ($source in $registry.sources) {
    # Approved frozen Git blobs cannot be repinned through this tool.
    if ($source.kind -eq 'approved-git-blob') { continue }
    $hash = if ($source.kind -eq 'production-source-scan') { $inventory.Sha256 }
        else { Get-NormalizedTextSha256 (Join-Path $workspaceRoot $source.path) }
    if ($source.normalizedSha256 -ceq $hash) { continue }
    $pattern = '(?s)("id"\s*:\s*"' + [regex]::Escape($source.id) + '"\s*,\s*"kind".*?"normalizedSha256"\s*:\s*")[0-9a-f]{64}'
    $matches = [regex]::Matches($raw, $pattern)
    if ($matches.Count -ne 1) { throw "Source repin is ambiguous: $($source.id)" }
    $raw = [regex]::Replace($raw, $pattern, { param($m) $m.Groups[1].Value + $hash })
    Write-Output "Mechanical source repin: $($source.id)"
    $changes++
}
if ($Apply) { [IO.File]::WriteAllText($registryPath, $raw, [Text.UTF8Encoding]::new($false)) }
Write-Output "$changes source hashes changed; review normative/code diffs and run strict generator."
