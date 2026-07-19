param(
    [Parameter(Mandatory = $true)][string] $InputPath,
    [Parameter(Mandatory = $true)][string] $OutputPath,
    [Parameter(Mandatory = $true)][string] $Command,
    [Parameter(Mandatory = $true)][string] $SourceCommit
)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $InputPath).Path
[xml] $document = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
$ns = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
$ns.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
$counters = $document.SelectSingleNode('//t:ResultSummary/t:Counters', $ns)
if ($null -eq $counters) { throw 'TRX counters are missing.' }
$sorted = @(
    $document.SelectNodes('//t:UnitTestResult', $ns) |
        ForEach-Object {
            [ordered]@{ testName = [string] $_.testName; outcome = [string] $_.outcome }
        } |
        Sort-Object -Property @{ Expression = { $_.testName } }, @{ Expression = { $_.outcome } }
)
$seen = @{}
$tests = @(
    foreach ($test in $sorted) {
        $key = $test.testName + [char] 0x1f + $test.outcome
        $previous = if ($seen.ContainsKey($key)) { [int] $seen[$key] } else { 0 }
        $occurrence = 1 + $previous
        $seen[$key] = $occurrence
        [ordered]@{
            testName = $test.testName
            outcome = $test.outcome
            occurrence = $occurrence
        }
    }
)
$evidence = [ordered]@{
    schema = 'deep.sanitized-test-evidence.v1'
    sourceCommit = $SourceCommit
    command = $Command
    originalLocalTrxSha256 =
        (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    privacy = [ordered]@{ userHostPathsTimesAndExecutionIdsRemoved = $true }
    counters = [ordered]@{
        total = [int] $counters.total
        passed = [int] $counters.passed
        failed = [int] $counters.failed
        skipped = [int] $counters.notExecuted
    }
    tests = $tests
}
[System.IO.File]::WriteAllText(
    $OutputPath,
    (($evidence | ConvertTo-Json -Depth 8) + "`n"),
    [System.Text.UTF8Encoding]::new($false))
