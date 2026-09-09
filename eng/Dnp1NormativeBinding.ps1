Set-StrictMode -Version Latest

$script:Dnp1ApprovedNormativeCommit = '2651599913bf92c021d36b6a53395499b6a091fb'
$script:Dnp1NormativeRelativeRoot = 'docs/survival-program/releases/v3.0.0/specs'

function Get-Dnp1ApprovedNormativeBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $NormativeRoot,
        [string] $ExpectedNormativeCommit = $script:Dnp1ApprovedNormativeCommit,
        [Parameter(Mandatory)] [string[]] $Names
    )

    if ($ExpectedNormativeCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'Approved normative commit is invalid.'
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $NormativeRoot).Path
    $gitRoot = (& git -C $resolvedRoot rev-parse --show-toplevel 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitRoot)) {
        throw 'Cannot resolve the normative repository root.'
    }
    & git -C $gitRoot cat-file -e "$ExpectedNormativeCommit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'Approved normative commit is unavailable in the normative repository.'
    }

    $expectedRoot = [IO.Path]::GetFullPath((Join-Path $gitRoot $script:Dnp1NormativeRelativeRoot))
    if ([IO.Path]::GetFullPath($resolvedRoot) -cne $expectedRoot) {
        throw 'Normative root is not the exact approved specs path.'
    }
    if ($Names.Count -eq 0 -or ($Names | Sort-Object -Unique).Count -ne $Names.Count) {
        throw 'Normative binding names are empty or duplicated.'
    }

    $bindings = foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name) -or [IO.Path]::IsPathRooted($name) -or
            $name.Contains('/') -or $name.Contains('\') -or $name.Contains('..')) {
            throw "Unsafe normative binding name: $name"
        }
        $path = Join-Path $resolvedRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Normative file missing: $name"
        }
        $relative = "$($script:Dnp1NormativeRelativeRoot)/$name"
        $approvedBlob = (& git -C $gitRoot rev-parse "$ExpectedNormativeCommit`:$relative" 2>$null |
            Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $approvedBlob -notmatch '^[0-9a-f]{40,64}$') {
            throw "Normative path is absent from the approved commit: $relative"
        }
        $checkedOutBlob = (& git -C $gitRoot hash-object "--path=$relative" -- $path 2>$null |
            Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $checkedOutBlob -cne $approvedBlob) {
            throw "Normative file differs from the approved commit: $relative"
        }
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = 'git'
        $start.WorkingDirectory = $gitRoot
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.CreateNoWindow = $true
        $start.Arguments = "cat-file blob $approvedBlob"
        $process = [Diagnostics.Process]::Start($start)
        if ($null -eq $process) { throw 'Cannot read approved normative blob.' }
        $bytes = [IO.MemoryStream]::new()
        try {
            $process.StandardOutput.BaseStream.CopyTo($bytes)
            $stderr = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            if ($process.ExitCode -ne 0) {
                throw "Cannot read approved normative blob: $stderr"
            }
            $algorithm = [Security.Cryptography.SHA256]::Create()
            try {
                $sha256 = ([BitConverter]::ToString(
                    $algorithm.ComputeHash($bytes.ToArray()))).Replace('-', '')
            }
            finally { $algorithm.Dispose() }
        }
        finally {
            $bytes.Dispose()
            $process.Dispose()
        }
        [ordered]@{
            path = $name
            sha256 = $sha256
        }
    }

    return [pscustomobject]@{
        Commit = $ExpectedNormativeCommit
        GitRoot = $gitRoot
        Root = $resolvedRoot
        Files = @($bindings)
    }
}
