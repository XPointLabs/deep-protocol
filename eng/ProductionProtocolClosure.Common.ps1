Set-StrictMode -Version Latest

$script:ClosurePolicyFileName = 'production-protocol-closure.policy.json'
$script:ClosurePolicySchemaFileName = 'production-protocol-closure.policy.schema.json'
$script:ClosureManifestFileName = 'deep-production-protocol-closure.manifest.v2.json'
$script:IsWindowsPlatform = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [Runtime.InteropServices.OSPlatform]::Windows)
$script:ClosurePathComparer = if ($script:IsWindowsPlatform) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
$script:ClosurePathComparison = if ($script:IsWindowsPlatform) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }

function Throw-ClosureError([string] $Message) {
    throw "ProductionProtocolClosure: $Message"
}

function Get-CanonicalFullPath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Throw-ClosureError 'A path may not be empty.' }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-ExactKeys {
    param(
        [Parameter(Mandatory = $true)] [Collections.IDictionary] $Value,
        [Parameter(Mandatory = $true)] [string[]] $Expected,
        [Parameter(Mandatory = $true)] [string] $Label)
    $actual = @($Value.Keys | ForEach-Object { [string] $_ } | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        Throw-ClosureError "$Label fields differ from the strict schema (actual: $($actual -join ', '))."
    }
}

function Assert-CanonicalRelativePath([string] $Path, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 512 -or
        $Path.Contains('\') -or $Path.StartsWith('/') -or $Path.Contains(':') -or
        $Path -match '(^|/)\.\.(/|$)' -or $Path -match '(^|/)\.(/|$)') {
        Throw-ClosureError "$Label is not a canonical repository-relative path: $Path"
    }
}

function ConvertTo-CanonicalHttpsRepositoryUrl([string] $Url, [string] $Label) {
    $uri = $null
    if ([string]::IsNullOrWhiteSpace($Url) -or
        -not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $uri) -or
        $uri.Scheme -cne 'https' -or -not $uri.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        [string]::IsNullOrWhiteSpace($uri.Host) -or $uri.AbsolutePath -eq '/' -or
        $uri.AbsolutePath.EndsWith('/') -or $uri.AbsolutePath -cnotmatch '\.git$') {
        Throw-ClosureError "$Label must be an exact canonical HTTPS .git repository URL."
    }
    $canonical = "https://$($uri.IdnHost.ToLowerInvariant())$($uri.AbsolutePath)"
    if ($Url -cne $canonical) {
        Throw-ClosureError "$Label is not canonical; expected '$canonical'."
    }
    return $canonical
}

function Get-FileDigest([string] $Path, [string] $Algorithm = 'SHA256') {
    return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

function Assert-StrictJsonNoDuplicateProperties([string] $Text, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Text)) { Throw-ClosureError "$Label is empty." }
    try {
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 64
        $document = [System.Text.Json.JsonDocument]::Parse($Text, $options)
    }
    catch { Throw-ClosureError "$Label is invalid strict JSON: $($_.Exception.Message)" }
    try {
        function Assert-Element($Element, [string] $Path) {
            if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($property in $Element.EnumerateObject()) {
                    if (-not $names.Add($property.Name)) {
                        Throw-ClosureError "$Label contains a duplicate JSON property at $Path.$($property.Name)."
                    }
                    Assert-Element $property.Value "$Path.$($property.Name)"
                }
            }
            elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                $index = 0
                foreach ($item in $Element.EnumerateArray()) {
                    Assert-Element $item "$Path[$index]"
                    $index++
                }
            }
        }
        Assert-Element $document.RootElement '$'
    }
    finally { $document.Dispose() }
}

function Read-StrictJsonHashtable([string] $Path, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw-ClosureError "$Label is missing: $Path" }
    $text = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
    Assert-StrictJsonNoDuplicateProperties $text $Label
    try { return $text | ConvertFrom-Json -AsHashtable -Depth 64 }
    catch { Throw-ClosureError "$Label cannot be converted from strict JSON: $($_.Exception.Message)" }
}

function Get-GitBlobHash([string] $Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if (-not (Test-Path -LiteralPath $file.FullName -PathType Leaf)) { Throw-ClosureError "Git blob input is not a regular file: $Path" }
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($file.Length)$([char]0)")
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA1)
    try {
        $hash.AppendData($header)
        $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $buffer = [byte[]]::new(128KB)
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $hash.AppendData($buffer, 0, $read) }
        }
        finally { $stream.Dispose() }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Test-CanonicalContentHash([string] $Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { return $false }
    return $bytes.Length -eq 64 -and [Convert]::ToBase64String($bytes) -ceq $Value
}

# This is intentionally a fail-closed subset of NuGet's non-floating VersionRange
# grammar.  It is kept here rather than loading a version of NuGet.Versioning from
# the host SDK: Windows PowerShell cannot reliably load the SDK's current-target
# assembly, and accepting a range we cannot evaluate would make the lock proof
# weaker.  Floating ranges, unbounded ranges, revision versions and malformed
# prerelease labels are therefore not production-closure inputs.
function ConvertTo-ClosureNuGetVersion([string] $Value, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 256 -or
        $Value -notmatch '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-(?<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$') {
        Throw-ClosureError "$Label is not a supported canonical NuGet version."
    }
    $majorText = [string] $Matches.major; $minorText = [string] $Matches.minor; $patchText = [string] $Matches.patch
    $pre = if ($Matches.ContainsKey('pre')) { [string] $Matches.pre } else { '' }
    if ($pre.Length -gt 128 -or $pre -match '(^|\.)[0-9]{2,}(?=\.|$)') {
        Throw-ClosureError "$Label has a non-canonical prerelease label."
    }
    try {
        return [PSCustomObject]@{
            original = $Value
            major = [UInt32] $majorText
            minor = [UInt32] $minorText
            patch = [UInt32] $patchText
            prerelease = $pre
        }
    }
    catch { Throw-ClosureError "$Label has a numeric component outside the supported range." }
}

function Compare-ClosureNuGetVersion($Left, $Right) {
    foreach ($part in @('major', 'minor', 'patch')) {
        if ($Left.$part -lt $Right.$part) { return -1 }
        if ($Left.$part -gt $Right.$part) { return 1 }
    }
    if ([string]::IsNullOrEmpty($Left.prerelease) -and [string]::IsNullOrEmpty($Right.prerelease)) { return 0 }
    if ([string]::IsNullOrEmpty($Left.prerelease)) { return 1 }
    if ([string]::IsNullOrEmpty($Right.prerelease)) { return -1 }
    $leftParts = @($Left.prerelease -split '\.')
    $rightParts = @($Right.prerelease -split '\.')
    $count = [Math]::Min($leftParts.Count, $rightParts.Count)
    for ($index = 0; $index -lt $count; $index++) {
        $left = $leftParts[$index]; $right = $rightParts[$index]
        $leftNumeric = $left -match '^[0-9]+$'; $rightNumeric = $right -match '^[0-9]+$'
        if ($leftNumeric -and $rightNumeric) {
            $cmp = [StringComparer]::Ordinal.Compare($left.PadLeft(32, '0'), $right.PadLeft(32, '0'))
        }
        elseif ($leftNumeric) { $cmp = -1 }
        elseif ($rightNumeric) { $cmp = 1 }
        else { $cmp = [StringComparer]::Ordinal.Compare($left, $right) }
        if ($cmp -lt 0) { return -1 }
        if ($cmp -gt 0) { return 1 }
    }
    return [Math]::Sign($leftParts.Count - $rightParts.Count)
}

function Assert-ClosureNuGetRangeSatisfies([string] $Range, [string] $Resolved, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Range) -or $Range.Length -gt 512 -or $Range -match '\s{2,}') {
        Throw-ClosureError "$Label is not a supported canonical NuGet range."
    }
    $resolvedVersion = ConvertTo-ClosureNuGetVersion $Resolved "$Label resolved version"
    if ($Range -match '^\[(?<exact>[^,\[\]\(\)\s]+)\]$') {
        $exactText = [string] $Matches.exact
        $exact = ConvertTo-ClosureNuGetVersion $exactText "$Label exact range"
        if ((Compare-ClosureNuGetVersion $resolvedVersion $exact) -ne 0) { Throw-ClosureError "$Label resolved version is outside its exact NuGet range." }
        return
    }
    if ($Range -notmatch '^(?<lowerDelimiter>[\[\(])(?<lower>[^,\[\]\(\)\s]*), (?<upper>[^,\[\]\(\)\s]*)(?<upperDelimiter>[\]\)])$') {
        Throw-ClosureError "$Label is not a supported canonical NuGet range."
    }
    $lowerDelimiter = [string] $Matches.lowerDelimiter; $lowerText = [string] $Matches.lower; $upperText = [string] $Matches.upper; $upperDelimiter = [string] $Matches.upperDelimiter
    if ([string]::IsNullOrEmpty($lowerText) -and [string]::IsNullOrEmpty($upperText)) {
        Throw-ClosureError "$Label may not be an unbounded NuGet range."
    }
    if ([string]::IsNullOrEmpty($lowerText) -and $lowerDelimiter -ne '(') {
        Throw-ClosureError "$Label has an invalid empty lower NuGet bound."
    }
    if ([string]::IsNullOrEmpty($upperText) -and $upperDelimiter -ne ')') {
        Throw-ClosureError "$Label has an invalid empty upper NuGet bound."
    }
    if (-not [string]::IsNullOrEmpty($lowerText)) {
        $lower = ConvertTo-ClosureNuGetVersion $lowerText "$Label lower bound"
        $comparison = Compare-ClosureNuGetVersion $resolvedVersion $lower
        if ($comparison -lt 0 -or ($comparison -eq 0 -and $lowerDelimiter -eq '(')) {
            Throw-ClosureError "$Label resolved version is below its NuGet range."
        }
    }
    if (-not [string]::IsNullOrEmpty($upperText)) {
        $upper = ConvertTo-ClosureNuGetVersion $upperText "$Label upper bound"
        $comparison = Compare-ClosureNuGetVersion $resolvedVersion $upper
        if ($comparison -gt 0 -or ($comparison -eq 0 -and $upperDelimiter -eq ')')) {
            Throw-ClosureError "$Label resolved version is above its NuGet range."
        }
    }
    if (-not [string]::IsNullOrEmpty($lowerText) -and -not [string]::IsNullOrEmpty($upperText) -and
        (Compare-ClosureNuGetVersion $lower $upper) -gt 0) {
        Throw-ClosureError "$Label lower NuGet bound exceeds its upper bound."
    }
}

function Read-ClosurePolicy {
    param(
        [Parameter(Mandatory = $true)] [string] $PolicyPath,
        [Parameter(Mandatory = $true)] [string] $SchemaPath)
    foreach ($path in @($PolicyPath, $SchemaPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Throw-ClosureError "Required tracked policy file is missing: $path"
        }
    }
    $policy = Read-StrictJsonHashtable $PolicyPath 'Policy'
    $schema = Read-StrictJsonHashtable $SchemaPath 'Policy schema'
    try {
        $policyText = [IO.File]::ReadAllText($PolicyPath, [Text.UTF8Encoding]::new($false, $true))
        if (-not (Test-Json -Json $policyText -SchemaFile $SchemaPath -ErrorAction Stop)) {
            Throw-ClosureError 'Policy does not satisfy the complete tracked JSON schema.'
        }
    }
    catch { Throw-ClosureError "Policy does not satisfy the complete tracked JSON schema: $($_.Exception.Message)" }
    if ($policy -isnot [Collections.IDictionary] -or $schema -isnot [Collections.IDictionary]) {
        Throw-ClosureError 'Policy and schema roots must be JSON objects.'
    }
    Assert-ExactKeys $policy @('$schema', 'schema', 'repositoryUrl', 'repositoryType', 'packages') 'Policy'
    if ($policy['$schema'] -cne "./$script:ClosurePolicySchemaFileName" -or
        $policy.schema -cne 'deep-production-protocol-closure-policy/v1') {
        Throw-ClosureError 'Policy schema identity is not exact.'
    }
    Assert-ExactKeys $schema @('$schema', '$id', 'title', 'type', 'additionalProperties', 'required', 'properties', '$defs') 'Policy schema'
    $requiredPolicyFields = @('$schema', 'schema', 'repositoryUrl', 'repositoryType', 'packages')
    if ((@($schema.required | ForEach-Object { [string] $_ } | Sort-Object) -join "`n") -cne (@($requiredPolicyFields | Sort-Object) -join "`n")) {
        Throw-ClosureError 'Policy schema required fields differ from the strict repository identity contract.'
    }
    Assert-ExactKeys $schema.properties @('$schema', 'schema', 'repositoryUrl', 'repositoryType', 'packages') 'Policy schema properties'
    if ($schema['$schema'] -cne 'https://json-schema.org/draft/2020-12/schema' -or
        $schema.type -cne 'object' -or $schema.additionalProperties -ne $false -or
        $schema.properties.packages.minItems -ne 3 -or
        $schema.properties.packages.maxItems -ne 3 -or
        $schema.properties.repositoryType.const -cne 'git' -or
        $schema['$defs'].package.additionalProperties -ne $false) {
        Throw-ClosureError 'Policy schema lost its strict exact-three/additionalProperties contract.'
    }
    $policy.repositoryUrl = ConvertTo-CanonicalHttpsRepositoryUrl $policy.repositoryUrl 'Policy repositoryUrl'
    if ($policy.repositoryType -cne 'git') { Throw-ClosureError 'Policy repositoryType must be the exact value git.' }
    if ($policy.packages -isnot [Collections.IList] -or $policy.packages.Count -ne 3) {
        Throw-ClosureError 'Policy must contain exactly three packages.'
    }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $projects = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($package in $policy.packages) {
        if ($package -isnot [Collections.IDictionary]) { Throw-ClosureError 'Each policy package must be an object.' }
        Assert-ExactKeys $package @('id', 'project', 'lockFile', 'targetFramework', 'packageReferences', 'projectReferences', 'packInputs', 'packTargets') "Policy package '$($package.id)'"
        if ([string]::IsNullOrWhiteSpace($package.id) -or $package.id -cnotmatch '^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*$' -or
            -not $ids.Add([string] $package.id)) {
            Throw-ClosureError "Policy package ID is malformed or duplicated: $($package.id)"
        }
        Assert-CanonicalRelativePath $package.project "Policy project for $($package.id)"
        Assert-CanonicalRelativePath $package.lockFile "Policy lock file for $($package.id)"
        if (-not $projects.Add([string] $package.project) -or $package.targetFramework -cne 'net10.0') {
            Throw-ClosureError "Policy project or target framework is malformed for $($package.id)."
        }
        foreach ($field in @('packageReferences', 'projectReferences', 'packInputs', 'packTargets')) {
            if ($package[$field] -isnot [Collections.IList]) { Throw-ClosureError "Policy $field must be an array for $($package.id)." }
        }
        $directIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in $package.packageReferences) {
            if ($reference -isnot [Collections.IDictionary]) { Throw-ClosureError "Policy packageReferences must contain objects for $($package.id)." }
            Assert-ExactKeys $reference @('id', 'version') "Policy direct PackageReference for $($package.id)"
            if ([string]::IsNullOrWhiteSpace([string] $reference.id) -or
                [string] $reference.id -cnotmatch '^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*$' -or
                [string] $reference.version -cnotmatch '^\[[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\]$' -or
                -not $directIds.Add([string] $reference.id)) {
                Throw-ClosureError "Policy direct PackageReference is malformed, non-exact, or duplicated for $($package.id)."
            }
        }
        foreach ($field in @('projectReferences', 'packInputs', 'packTargets')) {
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($value in $package[$field]) {
                if ([string]::IsNullOrWhiteSpace([string] $value) -or -not $seen.Add([string] $value)) {
                    Throw-ClosureError "Policy $field contains an empty or duplicate value for $($package.id)."
                }
            }
        }
        if ($package.packInputs.Count -ne $package.packTargets.Count -or $package.packInputs.Count -eq 0) {
            Throw-ClosureError "Policy pack input/target mapping is not one-to-one for $($package.id)."
        }
        foreach ($input in $package.packInputs) {
            if (([string] $input).StartsWith('build:', [StringComparison]::Ordinal)) {
                if ([string] $input -cnotmatch '^build:[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*$') {
                    Throw-ClosureError "Policy build pack input is malformed for $($package.id): $input"
                }
            }
            else {
                Assert-CanonicalRelativePath $input "Policy pack input for $($package.id)"
            }
        }
        foreach ($target in $package.packTargets) { Assert-CanonicalRelativePath $target "Policy pack target for $($package.id)" }
    }
    foreach ($package in $policy.packages) {
        foreach ($id in $package.projectReferences) {
            if (-not $ids.Contains([string] $id) -or [string] $id -ceq [string] $package.id) {
                Throw-ClosureError "Policy project reference is missing or self-referential: $($package.id) -> $id"
            }
        }
    }
    $policy['policySha256'] = Get-FileDigest $PolicyPath
    $policy['schemaSha256'] = Get-FileDigest $SchemaPath
    return $policy
}

function Get-PolicyPackage([Collections.IDictionary] $Policy, [string] $Id) {
    $matches = @($Policy.packages | Where-Object { $_.id -ceq $Id })
    if ($matches.Count -ne 1) { Throw-ClosureError "Policy has no unique canonical package '$Id'." }
    return $matches[0]
}

function Read-ExactSnapshotPolicy([string] $SourceRoot, [object[]] $TrackedEntries) {
    # Trust comes from the verified Git tree, not the checkout (which may have
    # legitimate smudge/EOL transformations even when git status is clean).
    foreach ($name in @($script:ClosurePolicyFileName, $script:ClosurePolicySchemaFileName)) {
        $relative = "eng/$name"
        $entry = @($TrackedEntries | Where-Object path -ceq $relative)
        $path = Join-Path $SourceRoot $relative
        if ($entry.Count -ne 1 -or $entry[0].mode -cnotin @('100644', '100755')) {
            Throw-ClosureError "Exact HEAD lacks a regular policy input: $relative"
        }
        Assert-NoReparseAncestors $path 'Exact snapshot policy'
        if ((Get-GitBlobHash $path) -cne $entry[0].hash) { Throw-ClosureError "Policy bytes differ from exact Git blob: $relative" }
    }
    return Read-ClosurePolicy (Join-Path $SourceRoot "eng/$script:ClosurePolicyFileName") (Join-Path $SourceRoot "eng/$script:ClosurePolicySchemaFileName")
}

function Get-PolicyDirectPackageIds([Collections.IDictionary] $Package) {
    return @($Package.packageReferences | ForEach-Object { [string] $_.id } | Sort-Object)
}

function Get-PolicyDirectPackageVersion([Collections.IDictionary] $Package, [string] $Id) {
    $matches = @($Package.packageReferences | Where-Object { $_.id -ceq $Id })
    if ($matches.Count -ne 1) { Throw-ClosureError "Policy has no unique direct PackageReference '$Id' for $($Package.id)." }
    return [string] $matches[0].version
}

function Invoke-Checked {
    param([string] $FileName, [string[]] $Arguments, [string] $Label)
    if ($FileName -ieq 'dotnet') {
        $text = Invoke-PinnedDotNetText $Arguments $Label
        if (-not [string]::IsNullOrEmpty($text)) { Write-Output $text }
        return
    }
    & $FileName @Arguments
    if ($LASTEXITCODE -ne 0) { Throw-ClosureError "$Label failed with exit code $LASTEXITCODE." }
}

function Invoke-PinnedDotNetText {
    param([string[]] $Arguments, [string] $Label)
    $sdk = Get-SelectedDotNetSdkContract
    $pins = @($Arguments | Where-Object { $_.StartsWith('-p:MSBuildSDKsPath=', [StringComparison]::OrdinalIgnoreCase) })
    if ($pins.Count -ne 1 -or (Get-CanonicalFullPath $pins[0].Substring($pins[0].IndexOf('=') + 1)) -cne $sdk.SdksPath) {
        Throw-ClosureError "$Label lacks the exact selected MSBuildSDKsPath global property."
    }
    foreach ($pin in @(Get-CompilerGlobalPins $sdk)) {
        $prefix = $pin.Substring(0, $pin.IndexOf('=') + 1)
        $matches = @($Arguments | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
        if ($matches.Count -ne 1 -or $matches[0] -cne $pin) { Throw-ClosureError "$Label lacks an exact compiler global pin: $prefix" }
    }
    $process = New-RedirectedProcess 'dotnet' $Arguments @{
        MSBuildSDKsPath = $sdk.SdksPath
        DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR = $null
        DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER = $null
        DOTNET_HOST_PATH = (Get-Command dotnet).Source
        DOTNET_STARTUP_HOOKS = $null
        DOTNET_ADDITIONAL_DEPS = $null
        DOTNET_SHARED_STORE = $null
    }
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $parts = @($stdout.GetAwaiter().GetResult(), $stderr.GetAwaiter().GetResult()) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $text = ($parts -join [Environment]::NewLine).Trim()
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0) { Throw-ClosureError "$Label failed with exit code ${exitCode}: $text" }
    return $text
}

function Get-CheckedGitText([string] $Repository, [string[]] $Arguments, [string] $Label) {
    # Successful Git diagnostics (e.g. autocrlf warnings) are not porcelain
    # status entries or object IDs. Keep stdout and stderr separate.
    $process = New-RedirectedProcess git (@('-C', $Repository) + $Arguments) $null
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $result = $stdout.GetAwaiter().GetResult()
        $diagnostic = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { Throw-ClosureError "$Label failed: $diagnostic" }
        return $result.Trim()
    }
    finally { $process.Dispose() }
}

function Test-IsReparsePoint([string] $Path) {
    return (((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-NoReparseAncestors([string] $ExistingPath, [string] $Label) {
    $full = Get-CanonicalFullPath $ExistingPath
    if (-not (Test-Path -LiteralPath $full)) { Throw-ClosureError "$Label path does not exist: $full" }
    $current = Get-Item -LiteralPath $full -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-ClosureError "$Label contains a reparse point: $($current.FullName)"
        }
        $current = if ($current -is [IO.DirectoryInfo]) { $current.Parent } else { $current.Directory }
    }
}

function Assert-NoReparseDescendants([string] $Directory, [string] $Label) {
    Assert-NoReparseAncestors $Directory $Label
    foreach ($item in Get-ChildItem -LiteralPath $Directory -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-ClosureError "$Label contains a reparse point: $($item.FullName)"
        }
    }
}

function Get-GitTreeEntries([string] $Repository, [string] $Commit) {
    $lines = @((Get-CheckedGitText $Repository @('ls-tree', '-r', '--full-tree', $Commit) 'tracked tree enumeration') -split "`r?`n")
    $entries = @()
    foreach ($line in $lines) {
        if ($line -notmatch '^(?<mode>[0-9]{6}) blob (?<hash>[0-9a-f]{40})\t(?<path>.+)$') {
            Throw-ClosureError "HEAD contains a non-blob or non-canonical tracked entry: $line"
        }
        if ($Matches.mode -notin @('100644', '100755')) {
            Throw-ClosureError "HEAD contains an unsupported non-regular Git mode $($Matches.mode): $($Matches.path)"
        }
        $path = $Matches.path
        Assert-CanonicalRelativePath $path 'Tracked path'
        $entries += [PSCustomObject]@{ mode = $Matches.mode; hash = $Matches.hash; path = $path }
    }
    if ($entries.Count -eq 0) { Throw-ClosureError 'HEAD tracked tree is empty.' }
    return $entries
}

function New-RedirectedProcess {
    param([string] $FileName, [string[]] $Arguments, [Collections.IDictionary] $EnvironmentOverrides)
    $command = (Get-Command $FileName -ErrorAction Stop).Source
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $command
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void] $start.ArgumentList.Add($argument) }
    if ($null -ne $EnvironmentOverrides) {
        foreach ($name in $EnvironmentOverrides.Keys) {
            if ($null -eq $EnvironmentOverrides[$name]) {
                [void] $start.Environment.Remove([string] $name)
            }
            else {
                $start.Environment[[string] $name] = [string] $EnvironmentOverrides[$name]
            }
        }
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { Throw-ClosureError "Cannot start process: $FileName" }
    return $process
}

function Read-AsciiProtocolLine([IO.Stream] $Stream, [string] $Label) {
    $bytes = [Collections.Generic.List[byte]]::new()
    while ($true) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) { Throw-ClosureError "$Label ended before a complete protocol line." }
        if ($value -eq 10) { break }
        if ($value -ne 13) { $bytes.Add([byte] $value) }
        if ($bytes.Count -gt 4096) { Throw-ClosureError "$Label protocol line is oversized." }
    }
    return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
}

function Invoke-ProcessCaptureBytes {
    param([string] $FileName, [string[]] $Arguments, [string] $Label)
    $process = New-RedirectedProcess $FileName $Arguments
    try {
        $process.StandardInput.Close()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $memory = [IO.MemoryStream]::new()
        try {
            $process.StandardOutput.BaseStream.CopyTo($memory)
            $process.WaitForExit()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($process.ExitCode -ne 0) { Throw-ClosureError "$Label failed with exit code $($process.ExitCode): $stderr" }
            return $memory.ToArray()
        }
        finally { $memory.Dispose() }
    }
    finally { $process.Dispose() }
}

function New-ExactGitSnapshot {
    param([string] $Repository, [string] $Commit, [string] $Destination, [object[]] $TrackedEntries)
    New-PrivateDirectoryAtomic $Destination
    $process = New-RedirectedProcess git @('-C', $Repository, 'cat-file', '--batch')
    try {
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $stdout = $process.StandardOutput.BaseStream
        $stdin = $process.StandardInput
        foreach ($entry in @($TrackedEntries | Sort-Object path)) {
            if ($entry.mode -notin @('100644', '100755')) {
                Throw-ClosureError "Exact snapshot contains unsupported Git mode $($entry.mode): $($entry.path)"
            }
            $target = Join-Path $Destination $entry.path
            $parent = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
            $stdin.WriteLine([string] $entry.hash)
            $stdin.Flush()
            $header = Read-AsciiProtocolLine $stdout 'git cat-file --batch'
            if ($header -notmatch '^(?<hash>[0-9a-f]{40}) blob (?<length>[0-9]+)$' -or $Matches.hash -cne [string] $entry.hash) {
                Throw-ClosureError "git cat-file returned an unexpected object for $($entry.path): $header"
            }
            try { $remaining = [Int64] $Matches.length }
            catch { Throw-ClosureError "git cat-file returned an invalid blob length for $($entry.path)." }
            $stream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = [byte[]]::new(128KB)
                while ($remaining -gt 0) {
                    $wanted = [int] [Math]::Min([Int64] $buffer.Length, $remaining)
                    $read = $stdout.Read($buffer, 0, $wanted)
                    if ($read -le 0) { Throw-ClosureError "git cat-file truncated blob bytes for $($entry.path)." }
                    $stream.Write($buffer, 0, $read)
                    $remaining -= $read
                }
                $stream.Flush($true)
            }
            finally { $stream.Dispose() }
            if ($stdout.ReadByte() -ne 10) { Throw-ClosureError "git cat-file blob terminator is invalid for $($entry.path)." }
            if (-not $script:IsWindowsPlatform) {
                $mode = if ($entry.mode -ceq '100755') {
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute -bor
                    [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::GroupExecute -bor
                    [IO.UnixFileMode]::OtherRead -bor [IO.UnixFileMode]::OtherExecute
                }
                else {
                    [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor
                    [IO.UnixFileMode]::GroupRead -bor [IO.UnixFileMode]::OtherRead
                }
                [IO.File]::SetUnixFileMode($target, $mode)
            }
        }
        $stdin.Close()
        $process.WaitForExit()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { Throw-ClosureError "git cat-file --batch failed with exit code $($process.ExitCode): $stderr" }
    }
    finally { $process.Dispose() }
    $manifest = Get-ExactGitSnapshotManifest $Destination $TrackedEntries
    $manifest['transport'] = 'git-cat-file-batch'
    return $manifest
}

function Get-CanonicalWorkspaceEntries([string] $Repository) {
    Assert-NoReparseAncestors $Repository 'Reproducibility workspace'
    $trackedBytes = Invoke-ProcessCaptureBytes git @('-C', $Repository, 'ls-files', '--stage', '-z') 'tracked workspace enumeration'
    $trackedText = [Text.UTF8Encoding]::new($false, $true).GetString($trackedBytes)
    $trackedModes = [Collections.Generic.Dictionary[string, string]]::new($script:ClosurePathComparer)
    foreach ($record in @($trackedText.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries))) {
        $separator = $record.IndexOf("`t", [StringComparison]::Ordinal)
        if ($separator -le 0) { Throw-ClosureError 'Tracked workspace index record is malformed.' }
        $metadata = $record.Substring(0, $separator).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        $path = $record.Substring($separator + 1)
        Assert-CanonicalRelativePath $path 'Tracked workspace path'
        if ($metadata.Count -ne 3 -or $metadata[2] -cne '0' -or $metadata[0] -notin @('100644', '100755')) {
            Throw-ClosureError "Tracked workspace contains a non-regular or unmerged entry: $path"
        }
        if ($trackedModes.ContainsKey($path)) { Throw-ClosureError "Tracked workspace path is duplicated: $path" }
        $trackedModes.Add($path, $metadata[0])
    }
    $allBytes = Invoke-ProcessCaptureBytes git @('-C', $Repository, 'ls-files', '--cached', '--others', '--exclude-standard', '-z') 'canonical workspace enumeration'
    $allText = [Text.UTF8Encoding]::new($false, $true).GetString($allBytes)
    $entries = @()
    $seen = [Collections.Generic.HashSet[string]]::new($script:ClosurePathComparer)
    foreach ($path in @($allText.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries))) {
        Assert-CanonicalRelativePath $path 'Canonical workspace path'
        if (-not $seen.Add($path)) { Throw-ClosureError "Canonical workspace path is duplicated: $path" }
        $source = Join-Path $Repository $path
        if (-not (Test-Path -LiteralPath $source)) { continue }
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { Throw-ClosureError "Canonical workspace entry is not a regular file: $path" }
        Assert-NoReparseAncestors $source "Canonical workspace input $path"
        $entries += [PSCustomObject]@{ path = $path; mode = if ($trackedModes.ContainsKey($path)) { $trackedModes[$path] } else { 'untracked-regular' } }
    }
    if ($entries.Count -eq 0) { Throw-ClosureError 'Canonical workspace inventory is empty.' }
    return @($entries | Sort-Object path)
}

function Copy-CanonicalWorkspaceSnapshot {
    param([string] $Repository, [string] $Destination, [object[]] $Entries)
    New-PrivateDirectoryAtomic $Destination
    $records = [Text.StringBuilder]::new()
    foreach ($entry in $Entries) {
        $source = Join-Path $Repository $entry.path
        $target = Join-Path $Destination $entry.path
        $parent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
        [IO.File]::Copy($source, $target, $false)
        $file = Get-Item -LiteralPath $target -Force
        [void] $records.Append($entry.path).Append([char]0).Append($file.Length).Append([char]0).
            Append((Get-FileDigest $target)).Append([char]0).Append($entry.mode).Append("`n")
    }
    Assert-NoReparseDescendants $Destination 'Canonical reproducibility snapshot'
    $bytes = [Text.Encoding]::UTF8.GetBytes($records.ToString())
    return [ordered]@{
        fileCount = $Entries.Count
        inventorySha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        inventorySha512 = [Convert]::ToHexString([Security.Cryptography.SHA512]::HashData($bytes)).ToLowerInvariant()
    }
}

function Get-ExactGitSnapshotManifest([string] $SourceRoot, [object[]] $TrackedEntries) {
    Assert-NoReparseDescendants $SourceRoot 'Extracted exact-HEAD snapshot'
    $trackedPaths = @($TrackedEntries | ForEach-Object path | Sort-Object -CaseSensitive)
    $files = @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Force | ForEach-Object {
        $_.FullName.Substring($SourceRoot.TrimEnd('\', '/').Length + 1).Replace('\', '/')
    } | Sort-Object -CaseSensitive)
    if (($files -join "`n") -cne ($trackedPaths -join "`n")) {
        Throw-ClosureError 'Extracted snapshot file set differs from the exact HEAD tree.'
    }
    $byPath = [Collections.Generic.Dictionary[string, object]]::new($script:ClosurePathComparer)
    foreach ($entry in $TrackedEntries) {
        if ($byPath.ContainsKey([string] $entry.path)) { Throw-ClosureError "Tracked tree path is duplicated: $($entry.path)" }
        $byPath[[string] $entry.path] = $entry
    }
    $records = [Text.StringBuilder]::new()
    foreach ($relative in $files) {
        $file = Get-Item -LiteralPath (Join-Path $SourceRoot $relative) -Force
        $blob = Get-GitBlobHash $file.FullName
        if ($blob -cne [string] $byPath[$relative].hash) {
            Throw-ClosureError "Extracted snapshot bytes differ from the exact Git blob (archive export transformation is forbidden): $relative"
        }
        [void] $records.Append($relative).Append([char]0).Append($file.Length).Append([char]0).
            Append((Get-FileDigest $file.FullName)).Append([char]0).Append($blob).Append("`n")
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($records.ToString())
    return [ordered]@{
        fileCount = $files.Count
        inventorySha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        inventorySha512 = [Convert]::ToHexString([Security.Cryptography.SHA512]::HashData($bytes)).ToLowerInvariant()
    }
}

function Assert-TrackedTreeNoReparse([string] $Repository, [string] $Commit) {
    Assert-NoReparseAncestors $Repository 'RepositoryRoot'
    $entries = @(Get-GitTreeEntries $Repository $Commit)
    foreach ($entry in $entries) {
        $current = $Repository
        $parts = @($entry.path -split '/')
        for ($index = 0; $index -lt $parts.Count; $index++) {
            $current = Join-Path $current $parts[$index]
            if (-not (Test-Path -LiteralPath $current)) { Throw-ClosureError "Tracked worktree path is missing: $($entry.path)" }
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-ClosureError "Tracked file or ancestor is a reparse point: $($entry.path)"
            }
            if ($index -lt $parts.Count - 1 -and -not $item.PSIsContainer) {
                Throw-ClosureError "Tracked path ancestor is not a directory: $($entry.path)"
            }
        }
        if (-not (Test-Path -LiteralPath $current -PathType Leaf)) { Throw-ClosureError "Tracked path is not a regular file: $($entry.path)" }
    }
    return $entries
}

if (-not ('DeepProtocolClosure.NativeDirectoryIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DeepProtocolClosure {
    public static class NativeDirectoryIdentity {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES securityAttributes);

        public static void CreatePrivate(string path, byte[] securityDescriptor) {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
                throw new ArgumentException("A non-empty security descriptor is required.", "securityDescriptor");
            GCHandle pinned = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
            try {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES {
                    nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                    lpSecurityDescriptor = pinned.AddrOfPinnedObject(),
                    bInheritHandle = false
                };
                if (!CreateDirectoryW(path, ref attributes))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { pinned.Free(); }
        }

        public static string Get(string path) {
            using (SafeFileHandle handle = CreateFileW(path, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return info.VolumeSerialNumber.ToString("x8") + ":" +
                    info.FileIndexHigh.ToString("x8") + info.FileIndexLow.ToString("x8");
            }
        }
    }
}
'@
}

function Get-UnixIdentity([string] $Path) {
    $currentUid = (& id -u 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentUid -notmatch '^[0-9]+$') { Throw-ClosureError 'Cannot determine the current Unix UID.' }
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::OSX)) {
        $identity = (& stat -f '%d:%i:%u' -- $Path 2>&1 | Out-String).Trim()
    }
    else {
        $identity = (& stat --format='%d:%i:%u' -- $Path 2>&1 | Out-String).Trim()
    }
    if ($LASTEXITCODE -ne 0 -or $identity -notmatch '^(?<device>[0-9]+):(?<inode>[0-9]+):(?<uid>[0-9]+)$') {
        Throw-ClosureError "Cannot stat Unix directory identity: $Path"
    }
    if ($Matches.uid -cne $currentUid) { Throw-ClosureError "Unix directory is not owned by current UID ${currentUid}: $Path" }
    return $identity
}

function Get-DirectoryIdentity([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container) -or (Test-IsReparsePoint $Path)) {
        Throw-ClosureError "Directory identity target is missing or reparse: $Path"
    }
    if ($script:IsWindowsPlatform) { return [DeepProtocolClosure.NativeDirectoryIdentity]::Get((Resolve-Path -LiteralPath $Path).Path) }
    return Get-UnixIdentity (Resolve-Path -LiteralPath $Path).Path
}

function ConvertTo-SidValue($Identity) {
    if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    if ($Identity -is [Security.Principal.IdentityReference]) { return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value }
    return ([Security.Principal.NTAccount]::new([string] $Identity)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function New-WindowsPrivateAcl {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($user, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void] $acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-WindowsPrivateAcl($Acl, [string] $Label) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $Acl.AreAccessRulesProtected -or (ConvertTo-SidValue $owner) -ne $user.Value) {
        Throw-ClosureError "$Label must be current-principal owned with protected ACL inheritance."
    }
    $currentPrincipalAllows = @($Acl.Access | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        -not $_.IsInherited -and
        (($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) -and
        (ConvertTo-SidValue $_.IdentityReference) -ceq $user.Value -and
        (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)
    })
    if ($currentPrincipalAllows.Count -ne 1) {
        Throw-ClosureError "$Label must grant one explicit effective FullControl allow rule to the current SID."
    }
    foreach ($rule in @($Acl.Access)) {
        $sid = ConvertTo-SidValue $rule.IdentityReference
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) -or
            $sid -notin @($user.Value, $system.Value) -or
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl)) {
            Throw-ClosureError "$Label ACL is not an explicit private current-SID/SYSTEM FullControl allow list."
        }
    }
}

function Assert-PrivateExclusiveDirectory([string] $Path, [string] $Label) {
    Assert-NoReparseAncestors $Path $Label
    if ($script:IsWindowsPlatform) {
        Assert-WindowsPrivateAcl (Get-Acl -LiteralPath $Path) $Label
    }
    else {
        $privateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
        if ([IO.File]::GetUnixFileMode($Path) -ne $privateMode) { Throw-ClosureError "$Label must have Unix mode 0700." }
        [void] (Get-UnixIdentity $Path)
    }
}

function New-PrivateDirectoryAtomic([string] $Path) {
    if (Test-Path -LiteralPath $Path) { Throw-ClosureError "Private directory already exists: $Path" }
    if ($script:IsWindowsPlatform) {
        $privateAcl = New-WindowsPrivateAcl
        [DeepProtocolClosure.NativeDirectoryIdentity]::CreatePrivate($Path, $privateAcl.GetSecurityDescriptorBinaryForm())
    }
    else {
        $mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute
        [IO.Directory]::CreateDirectory($Path, $mode) | Out-Null
    }
    Assert-PrivateExclusiveDirectory $Path 'Fresh private directory'
}

function New-PrivateClosureStage([string] $Parent = '') {
    if ([string]::IsNullOrWhiteSpace($Parent)) {
        $localRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localRoot) -or -not (Test-Path -LiteralPath $localRoot -PathType Container)) {
            Throw-ClosureError 'A per-user LocalApplicationData directory is unavailable.'
        }
        Assert-NoReparseAncestors $localRoot 'LocalApplicationData'
        $parent = Join-Path $localRoot 'DeepProtocolProductionClosure'
        if (-not (Test-Path -LiteralPath $parent)) { New-PrivateDirectoryAtomic $parent }
    }
    else {
        Assert-NoReparseAncestors $Parent 'Private staging parent'
        $parent = Get-CanonicalFullPath $Parent
    }
    Assert-PrivateExclusiveDirectory $parent 'Private staging parent'
    $stage = Join-Path $parent ".deep-protocol-closure-stage-$([Guid]::NewGuid().ToString('N'))"
    New-PrivateDirectoryAtomic $stage
    return [PSCustomObject]@{
        Path = $stage
        Identity = Get-DirectoryIdentity $stage
        Parent = $parent
        ParentIdentity = Get-DirectoryIdentity $parent
    }
}

function Assert-StableDirectory([string] $Path, [string] $Identity, [string] $Label) {
    if ((Get-DirectoryIdentity $Path) -cne $Identity) { Throw-ClosureError "$Label identity changed." }
}

function Move-StageToQuarantine($Stage) {
    try {
        Assert-StableDirectory $Stage.Parent $Stage.ParentIdentity 'Private staging parent'
        Assert-StableDirectory $Stage.Path $Stage.Identity 'Private stage'
        Assert-NoReparseDescendants $Stage.Path 'Private stage before quarantine'
        $quarantine = Join-Path $Stage.Parent ".deep-protocol-closure-quarantine-$([Guid]::NewGuid().ToString('N'))"
        [IO.Directory]::Move($Stage.Path, $quarantine)
        return $quarantine
    }
    catch { return "$($Stage.Path) (identity could not be proven; path was not followed, moved, or deleted)" }
}

function Remove-VerifiedStage($Stage) {
    Remove-VerifiedPrivateDirectory $Stage.Path $Stage.Identity $Stage.Parent $Stage.ParentIdentity 'Private stage before cleanup'
}

function Remove-VerifiedPrivateDirectory([string] $Path, [string] $Identity, [string] $Parent, [string] $ParentIdentity, [string] $Label) {
    Assert-StableDirectory $Parent $ParentIdentity "$Label parent"
    Assert-PrivateExclusiveDirectory $Parent "$Label parent"
    Assert-StableDirectory $Path $Identity $Label
    Assert-PrivateExclusiveDirectory $Path $Label
    Assert-NoReparseDescendants $Path $Label
    [IO.Directory]::Delete($Path, $true)
}

function Assert-SafeNewOutput([string] $OutputDirectory, [string] $Repository) {
    $output = Get-CanonicalFullPath $OutputDirectory
    if (Test-Path -LiteralPath $output) { Throw-ClosureError 'OutputDirectory must be new and non-existing.' }
    $parent = Split-Path -Parent $output
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
        Throw-ClosureError 'OutputDirectory parent must already exist.'
    }
    Assert-PrivateExclusiveDirectory $parent 'OutputDirectory parent'
    $repo = (Resolve-Path -LiteralPath $Repository).Path.TrimEnd('\', '/')
    if (Test-PathWithin $output $repo) {
        Throw-ClosureError 'OutputDirectory may not be the repository or a worktree descendant.'
    }
    return [PSCustomObject]@{ Path = $output; Parent = $parent; ParentIdentity = Get-DirectoryIdentity $parent }
}

function Get-DirectoryFileManifest([string] $Directory) {
    Assert-NoReparseDescendants $Directory 'Manifest directory'
    return @(Get-ChildItem -LiteralPath $Directory -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = Get-FileDigest $_.FullName 'SHA256'; sha512 = Get-FileDigest $_.FullName 'SHA512' }
    })
}

function Move-PublishedStage([string] $Published, $Output, [Collections.IList] $ExpectedFiles) {
    $publishedIdentity = Get-DirectoryIdentity $Published
    Assert-PrivateExclusiveDirectory $Published 'Candidate publication'
    Assert-StableDirectory $Output.Parent $Output.ParentIdentity 'OutputDirectory parent before publication'
    Assert-PrivateExclusiveDirectory $Output.Parent 'OutputDirectory parent before publication'
    if (Test-Path -LiteralPath $Output.Path) { Throw-ClosureError 'OutputDirectory appeared before publication.' }
    [IO.Directory]::Move($Published, $Output.Path)
    Assert-StableDirectory $Output.Parent $Output.ParentIdentity 'OutputDirectory parent after publication'
    if ((Get-DirectoryIdentity $Output.Path) -cne $publishedIdentity) {
        Throw-ClosureError 'Published output identity changed; redirected output was not followed or deleted.'
    }
    Assert-PrivateExclusiveDirectory $Output.Path 'Published output'
    Assert-NoReparseDescendants $Output.Path 'Published output'
    $actual = @(Get-DirectoryFileManifest $Output.Path)
    if (($actual | ConvertTo-Json -Depth 4 -Compress) -cne ($ExpectedFiles | ConvertTo-Json -Depth 4 -Compress)) {
        Throw-ClosureError 'Published output hashes or file identity changed; output was not followed or deleted.'
    }
}

function Test-PathWithin([string] $Path, [string] $Root) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $boundary = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    return $script:ClosurePathComparer.Equals($candidate, $boundary) -or
        $candidate.StartsWith($boundary + [IO.Path]::DirectorySeparatorChar, $script:ClosurePathComparison)
}

function Get-SelectedDotNetSdkContract {
    $version = (& dotnet --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cnotmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$') {
        Throw-ClosureError "Cannot determine a canonical selected .NET SDK version: $version"
    }
    $dotnetRoot = Split-Path -Parent ((Get-Command dotnet -ErrorAction Stop).Source)
    $sdkRoot = Join-Path $dotnetRoot "sdk/$version"
    $sdksPath = Join-Path $sdkRoot 'Sdks'
    foreach ($path in @($sdkRoot, $sdksPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container) -or (Test-IsReparsePoint $path)) {
            Throw-ClosureError "Selected .NET SDK path is missing or reparse: $path"
        }
    }
    return [PSCustomObject]@{
        Version = $version
        DotNetRoot = Get-CanonicalFullPath $dotnetRoot
        SdkRoot = Get-CanonicalFullPath $sdkRoot
        SdksPath = Get-CanonicalFullPath $sdksPath
    }
}

function New-MsBuildAuditLogPath([string] $SourceRoot) {
    $root = Join-Path (Get-CanonicalFullPath $SourceRoot) '.closure-audit'
    if (-not (Test-Path -LiteralPath $root)) { New-PrivateDirectoryAtomic $root }
    else { Assert-PrivateExclusiveDirectory $root 'MSBuild audit log root' }
    return Join-Path $root "$([Guid]::NewGuid().ToString('N')).binlog"
}

function Get-MsBuildBinlogInputPaths([string] $BinlogPath) {
    if (-not (Test-Path -LiteralPath $BinlogPath -PathType Leaf)) { Throw-ClosureError "MSBuild binary log is missing: $BinlogPath" }
    $sdk = Get-SelectedDotNetSdkContract
    foreach ($assembly in @('Microsoft.Build.Framework.dll', 'Microsoft.Build.Utilities.Core.dll', 'Microsoft.Build.dll')) {
        [void] [Reflection.Assembly]::LoadFrom((Join-Path $sdk.SdkRoot $assembly))
    }
    $paths = [Collections.Generic.HashSet[string]]::new($script:ClosurePathComparer)
    $replay = [Microsoft.Build.Logging.BinaryLogReplayEventSource]::new()
    $handler = [Microsoft.Build.Framework.AnyEventHandler] {
        param($sender, $eventArgs)
        if ($eventArgs -is [Microsoft.Build.Framework.ProjectImportedEventArgs]) {
            if (-not $eventArgs.ImportIgnored -and -not [string]::IsNullOrWhiteSpace($eventArgs.ImportedProjectFile)) {
                [void] $paths.Add([string] $eventArgs.ImportedProjectFile)
            }
        }
        elseif ($eventArgs -is [Microsoft.Build.Framework.ProjectStartedEventArgs] -and
            -not [string]::IsNullOrWhiteSpace($eventArgs.ProjectFile)) {
            [void] $paths.Add([string] $eventArgs.ProjectFile)
        }
    }
    $replay.add_AnyEventRaised($handler)
    try { $replay.Replay($BinlogPath) }
    finally {
        $replay.remove_AnyEventRaised($handler)
    }
    if ($paths.Count -eq 0) { Throw-ClosureError 'MSBuild binary log contained no project/import inputs.' }
    return @($paths | Sort-Object)
}

function Assert-HermeticMsBuildBinlogInputs {
    param([string] $SourceRoot, [Collections.IDictionary] $Package, [string] $BinlogPath, [string] $Label)
    $sdk = Get-SelectedDotNetSdkContract
    $source = Get-CanonicalFullPath $SourceRoot
    $nugetRoot = Join-Path $source '.closure-packages'
    $allowedRoots = @($source, $sdk.SdkRoot, $nugetRoot)
    $paths = @(Get-MsBuildBinlogInputPaths $BinlogPath)
    foreach ($path in $paths) {
        $full = Get-CanonicalFullPath $path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Throw-ClosureError "$Label imported input is missing: $full" }
        Assert-NoReparseAncestors $full "$Label imported input"
        if (-not @($allowedRoots | Where-Object { Test-PathWithin $full $_ }).Count) {
            Throw-ClosureError "$Label imported input escaped exact snapshot/SDK/private locked NuGet roots: $full"
        }
    }
    foreach ($required in @(
        (Join-Path $SourceRoot $Package.project),
        (Join-Path $sdk.SdksPath 'Microsoft.NET.Sdk/Sdk/Sdk.props'),
        (Join-Path $sdk.SdksPath 'Microsoft.NET.Sdk/Sdk/Sdk.targets'),
        (Join-Path $SourceRoot 'eng/ProductionProtocolClosure.InputAudit.targets'))) {
        $expected = Get-CanonicalFullPath $required
        if (@($paths | Where-Object { (Get-CanonicalFullPath $_) -ceq $expected }).Count -ne 1) {
            Throw-ClosureError "$Label binary log lacks exact required project/import input: $expected"
        }
    }
}

function Get-CompilerGlobalPins($Sdk) {
    return @(
        '-p:CompilerResponseFile=', '-p:CscToolPath=', '-p:CscToolExe=',
        '-p:CscEnvironment=', '-p:AdditionalCompilerArguments=',
        '-p:Features=', '-p:InterceptorsNamespaces=', '-p:InterceptorsPreviewNamespaces=',
        '-p:UseSharedCompilation=false', '-p:UseHostCompilerIfAvailable=false',
        '-p:SkipCompilerExecution=false', '-p:NoConfig=true', '-p:NoStandardLib=true',
        "-p:RoslynTargetsPath=$(Join-Path $Sdk.SdkRoot 'Roslyn')",
        "-p:DotNetHostPath=$((Get-Command dotnet).Source)")
}

function Get-MsBuildCompilerInvocations([string] $BinlogPath) {
    # Task events are emitted by the actual Csc invocation. Do not trust mutable
    # post-target @(Compile) / @(CscCommandLineArgs) as proof of executed inputs.
    $sdk = Get-SelectedDotNetSdkContract
    foreach ($assembly in @('Microsoft.Build.Framework.dll', 'Microsoft.Build.Utilities.Core.dll', 'Microsoft.Build.dll')) {
        [void] [Reflection.Assembly]::LoadFrom((Join-Path $sdk.SdkRoot $assembly))
    }
    $tasks = @{}
    $replay = [Microsoft.Build.Logging.BinaryLogReplayEventSource]::new()
    $handler = [Microsoft.Build.Framework.AnyEventHandler] {
        param($sender, $eventArgs)
        $context = $eventArgs.BuildEventContext
        if ($null -eq $context) { return }
        $key = "$($context.NodeId):$($context.ProjectContextId):$($context.TaskId)"
        if ($eventArgs -is [Microsoft.Build.Framework.TaskStartedEventArgs] -and $eventArgs.TaskName -ceq 'Csc') {
            if ($tasks.ContainsKey($key)) { Throw-ClosureError 'Duplicate Csc task context in binary log.' }
            $tasks[$key] = [ordered]@{
                Project = $eventArgs.ProjectFile; Assembly = $eventArgs.TaskAssemblyLocation
                Commands = [Collections.Generic.List[string]]::new(); ResponseFiles = $false; Success = $false
            }
        }
        elseif ($tasks.ContainsKey($key)) {
            if ($eventArgs -is [Microsoft.Build.Framework.TaskCommandLineEventArgs]) {
                if ($eventArgs.TaskName -cne 'Csc') { Throw-ClosureError 'Unexpected compiler task command event.' }
                $tasks[$key].Commands.Add($eventArgs.CommandLine)
            }
            elseif ($eventArgs -is [Microsoft.Build.Framework.TaskParameterEventArgs] -and
                ($eventArgs.ParameterName -ceq 'ResponseFiles' -or $eventArgs.ItemType -ceq 'ResponseFiles') -and $eventArgs.Items.Count -gt 0) {
                $tasks[$key].ResponseFiles = $true
            }
            elseif ($eventArgs -is [Microsoft.Build.Framework.TaskFinishedEventArgs]) { $tasks[$key].Success = $eventArgs.Succeeded }
        }
    }
    $replay.add_AnyEventRaised($handler)
    try { $replay.Replay($BinlogPath) } finally { $replay.remove_AnyEventRaised($handler) }
    return @($tasks.Values)
}

function Assert-CompilerCommand {
    param([string] $Command, [string] $Project, [string] $SourceRoot)
    $sdk = Get-SelectedDotNetSdkContract
    # Only use the shell's bundled Roslyn lexical splitter, not its option
    # parser/compiler (which may be a different version than the pinned SDK).
    [void] [Reflection.Assembly]::Load('Microsoft.CodeAnalysis')
    $csc = Join-Path $sdk.SdkRoot 'Roslyn/bincore/csc.dll'
    $hostPath = (Get-Command dotnet).Source
    $appHostName = if ($script:IsWindowsPlatform) { 'Roslyn/bincore/csc.exe' } else { 'Roslyn/bincore/csc' }
    $appHost = Join-Path $sdk.SdkRoot $appHostName
    $tokens = @(); $matched = $false
    # MSBuild's ToolCommandLine event logs its executable without quotes even
    # when its path contains spaces. Match the exact pinned prefix before
    # splitting arguments; never resolve a bare executable through PATH.
    foreach ($prefix in @("$hostPath exec ", "`"$hostPath`" exec ")) {
        if ($Command.StartsWith($prefix, $script:ClosurePathComparison)) {
            $rest = @([Microsoft.CodeAnalysis.CommandLineParser]::SplitCommandLineIntoArguments($Command.Substring($prefix.Length), $false))
            if ($rest.Count -lt 2 -or -not $script:ClosurePathComparer.Equals((Get-CanonicalFullPath $rest[0]), $csc)) { Throw-ClosureError 'Actual Csc command selected a different compiler DLL.' }
            $tokens = @($rest | Select-Object -Skip 1); $matched = $true; break
        }
    }
    if (-not $matched -and (Test-Path -LiteralPath $appHost -PathType Leaf)) {
        foreach ($prefix in @("$appHost ", "`"$appHost`" ")) {
            if ($Command.StartsWith($prefix, $script:ClosurePathComparison)) {
                Assert-NoReparseAncestors $appHost 'Actual compiler apphost'
                $tokens = @([Microsoft.CodeAnalysis.CommandLineParser]::SplitCommandLineIntoArguments($Command.Substring($prefix.Length), $false))
                $matched = $true; break
            }
        }
    }
    if (-not $matched -or $tokens.Count -lt 3) { Throw-ClosureError 'Actual Csc command did not use the exact selected SDK compiler/apphost.' }
    Assert-NoReparseAncestors $csc 'Actual compiler'
    $base = Split-Path -Parent $Project
    $allowed = @($SourceRoot, $sdk.SdkRoot, (Join-Path $sdk.DotNetRoot 'packs'))
    function Assert-CompilerPath([string] $Value, [bool] $Output = $false) {
        if ($Value.StartsWith('"') -and $Value.EndsWith('"')) { $Value = $Value.Substring(1, $Value.Length - 2) }
        if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOfAny([char[]]@('"', "`r", "`n")) -ge 0 -or $Value.StartsWith('@')) {
            Throw-ClosureError 'Non-canonical actual compiler path/response file.'
        }
        $full = [IO.Path]::GetFullPath($Value, $base)
        $roots = if ($Output) { @($SourceRoot) } else { $allowed }
        if (-not @($roots | Where-Object { Test-PathWithin $full $_ }).Count) { Throw-ClosureError 'Actual input escaped the audited roots (compiler input or output).' }
        if (-not $Output -and -not (Test-Path -LiteralPath $full -PathType Leaf)) { Throw-ClosureError 'Actual compiler input is missing.' }
        $existing = $full
        while (-not (Test-Path -LiteralPath $existing)) { $existing = Split-Path -Parent $existing }
        Assert-NoReparseAncestors $existing 'Actual compiler path'
    }
    $noConfig = $false; $noStdLib = $false; $sourceCount = 0
    foreach ($token in $tokens) {
        if ($token.StartsWith('@')) { Throw-ClosureError 'Actual compiler response files (including nested response files) are forbidden.' }
        if ($token -ceq '/noconfig') { $noConfig = $true; continue }
        if ($token -ceq '/nostdlib+') { $noStdLib = $true; continue }
        if (-not $token.StartsWith('/') -and -not $token.StartsWith('-') -or
            (-not $script:IsWindowsPlatform -and [IO.Path]::IsPathRooted($token) -and (Test-Path -LiteralPath $token -PathType Leaf))) {
            Assert-CompilerPath $token; $sourceCount++; continue
        }
        if ($token -cnotmatch '^/(?<name>[a-z][a-z0-9]*)(?<toggle>[+-]?)(?::(?<value>.*))?$') { Throw-ClosureError "Unknown actual Csc argument grammar: $token" }
        $name = $Matches.name; $value = if ($Matches.ContainsKey('value')) { $Matches.value } else { '' }; $toggle = $Matches.toggle
        if ($name -cin @('reference', 'analyzer', 'additionalfile', 'analyzerconfig', 'embed', 'sourcelink', 'win32res', 'win32icon', 'win32manifest', 'keyfile', 'appconfig', 'ruleset', 'addmodule')) {
            if ($toggle.Length -ne 0) { Throw-ClosureError 'Unexpected compiler input toggle.' }
            # Multi-input/alias/reference search syntax is deliberately not in
            # this exact-three closure. Each canonical argument is one file.
            Assert-CompilerPath $value
        }
        elseif ($name -cin @('resource', 'linkresource')) {
            if ($value -cnotmatch '^(?<path>"[^"]+"|[^",]+)(?:,[^",]+){0,2}$') { Throw-ClosureError 'Non-canonical actual compiler resource.' }
            Assert-CompilerPath $Matches.path
        }
        elseif ($name -cin @('out', 'refout', 'pdb', 'doc', 'generatedfilesout', 'errorlog', 'touchedfiles')) { Assert-CompilerPath $value $true }
        elseif ($name -cin @('unsafe', 'checked', 'nowarn', 'fullpaths', 'errorreport', 'warn', 'define', 'highentropyva', 'nullable', 'debug', 'filealign', 'optimize', 'target', 'warnaserror', 'utf8output', 'deterministic', 'langversion', 'checksumalgorithm', 'pathmap', 'platform', 'nologo', 'reportanalyzer', 'skipanalyzers', 'refonly', 'publicsign', 'delaysign', 'subsystemversion', 'baseaddress', 'codepage', 'preferreduilang', 'instrument', 'reportivts', 'modulename', 'moduleassemblyname', 'runtimeversion')) {
            # These compiler switches do not introduce file inputs. Unknown
            # switches (notably /lib, /recurse, /features, /keycontainer) reject.
            continue
        }
        else { Throw-ClosureError "Unreviewed actual Csc option: /$name" }
    }
    if (-not $noConfig -or -not $noStdLib -or $sourceCount -eq 0) { Throw-ClosureError 'Actual Csc command lacks noconfig/nostdlib/source closure.' }
}

function Assert-HermeticCompilerInvocations([string] $SourceRoot, $Package, [string] $BinlogPath) {
    $sdk = Get-SelectedDotNetSdkContract
    $expectedAssembly = Join-Path $sdk.SdkRoot 'Roslyn/Microsoft.Build.Tasks.CodeAnalysis.dll'
    $rootProject = Get-CanonicalFullPath (Join-Path $SourceRoot $Package.project)
    $rootCount = 0
    foreach ($task in @(Get-MsBuildCompilerInvocations $BinlogPath)) {
        if (-not $task.Success -or $task.ResponseFiles -or $task.Commands.Count -ne 1 -or
            -not $script:ClosurePathComparer.Equals($task.Assembly, $expectedAssembly)) {
            Throw-ClosureError 'Actual Csc invocation lacks successful exact-tool/no-response-file evidence.'
        }
        if (-not (Test-PathWithin $task.Project $SourceRoot)) { Throw-ClosureError 'Actual compiler project escaped snapshot.' }
        if ($script:ClosurePathComparer.Equals($task.Project, $rootProject)) { $rootCount++ }
        Assert-CompilerCommand $task.Commands[0] $task.Project $SourceRoot
    }
    if ($rootCount -ne 1) { Throw-ClosureError 'Audited root project must execute exactly one Csc task.' }
}

function Get-HermeticMsBuildProperties {
    param(
        [string] $SourceRoot,
        [Collections.IDictionary] $Package,
        [string] $Version,
        [Collections.IDictionary] $Policy = $null,
        [string] $Commit = '')
    $source = Get-CanonicalFullPath $SourceRoot
    $sdk = Get-SelectedDotNetSdkContract
    $auditTargets = Join-Path $source 'eng/ProductionProtocolClosure.InputAudit.targets'
    $auditProject = Get-CanonicalFullPath (Join-Path $source $Package.project)
    if (-not (Test-Path -LiteralPath $auditTargets -PathType Leaf)) {
        Throw-ClosureError "Tracked MSBuild input-audit targets are missing: $auditTargets"
    }
    $properties = @(
        "-p:Version=$Version", "-p:PackageVersion=$Version", "-p:DeepProtocolPackageVersion=[$Version]",
        '-p:UsePackagedDeepProtocol=false', '-p:ImportDirectoryBuildProps=false',
        '-p:ImportDirectoryBuildTargets=false', '-p:ImportDirectoryPackagesProps=false',
        '-p:ManagePackageVersionsCentrally=false', '-p:RestoreLockedMode=true',
        '-p:RestorePackagesWithLockFile=true', '-p:RestoreNoCache=true', '-p:NuGetAudit=false',
        "-p:RestorePackagesPath=$(Join-Path $source '.closure-packages')",
        "-p:MSBuildUserExtensionsPath=$(Join-Path $source '.closure-user-extensions')",
        "-p:MSBuildSDKsPath=$($sdk.SdksPath)",
        '-p:MSBuildEnableWorkloadResolver=false',
        '-p:RestoreAdditionalProjectSources=', '-p:CustomBeforeMicrosoftCommonProps=',
        '-p:CustomAfterMicrosoftCommonProps=', '-p:CustomBeforeMicrosoftCommonTargets=',
        "-p:CustomAfterMicrosoftCommonTargets=$auditTargets", '-p:ProvideCommandLineArgs=true',
        "-p:ProductionProtocolClosureAuditProject=$auditProject",
        '-p:ContinuousIntegrationBuild=true', '-p:Deterministic=true')
    if ($null -ne $Policy) {
        $properties += "-p:RepositoryUrl=$($Policy.repositoryUrl)"
        if (-not [string]::IsNullOrWhiteSpace($Commit)) { $properties += "-p:RepositoryCommit=$Commit" }
        $properties += '-p:PublishRepositoryUrl=true'
    }
    return $properties + @(Get-CompilerGlobalPins $sdk)
}

function Assert-HermeticEvaluatedInputClosure {
    param([string] $SourceRoot, [Collections.IDictionary] $Policy, [Collections.IDictionary] $Package, [string] $Version, [string] $Commit = '')
    $projectPath = Join-Path $SourceRoot $Package.project
    $properties = @(Get-HermeticMsBuildProperties $SourceRoot $Package $Version $Policy $Commit)
    $propertyNames = 'TargetFramework,RepositoryType,MSBuildAllProjects,MSBuildSDKsPath,MSBuildToolsPath,MSBuildBinPath,NETCoreSdkVersion,MSBuildEnableWorkloadResolver,NuGetPackageRoot,BaseIntermediateOutputPath,BaseOutputPath,MSBuildProjectExtensionsPath,ImportDirectoryBuildProps,ImportDirectoryBuildTargets,ImportDirectoryPackagesProps,CustomAfterMicrosoftCommonTargets,ProductionProtocolClosureAuditProject'
    $compilerPins = @(Get-CompilerGlobalPins (Get-SelectedDotNetSdkContract))
    $propertyNames += ',' + (($compilerPins | ForEach-Object { $_.Substring(3, $_.IndexOf('=') - 3) }) -join ',')
    $itemNames = 'Compile,Analyzer,Reference,EmbeddedResource,AdditionalFiles,NativeCompile,ClCompile,Content,None'
    $binlog = New-MsBuildAuditLogPath $SourceRoot
    $arguments = @('msbuild', $projectPath, '-nologo', '-verbosity:quiet', '-target:_ProductionProtocolEvaluateAudit', "-binaryLogger:$binlog;ProjectImports=None", "-getProperty:$propertyNames", "-getItem:$itemNames") + $properties
    $text = Invoke-PinnedDotNetText $arguments "MSBuild input-closure evaluation for $($Package.project)"
    Assert-HermeticMsBuildBinlogInputs $SourceRoot $Package $binlog "MSBuild evaluation for $($Package.id)"
    $start = $text.IndexOf('{')
    if ($start -lt 0) { Throw-ClosureError "MSBuild input-closure evaluation returned no JSON for $($Package.project)." }
    try { $value = $text.Substring($start) | ConvertFrom-Json -AsHashtable -Depth 64 }
    catch { Throw-ClosureError "MSBuild input-closure JSON is invalid for $($Package.project)." }
    foreach ($pin in $compilerPins) {
        $equals = $pin.IndexOf('=')
        $name = $pin.Substring(3, $equals - 3)
        if (-not $value.Properties.Contains($name) -or [string] $value.Properties[$name] -cne $pin.Substring($equals + 1)) {
            Throw-ClosureError "Evaluated compiler override differs from exact global pin: $name"
        }
    }
    $sdk = Get-SelectedDotNetSdkContract
    $auditTargets = Get-CanonicalFullPath (Join-Path $SourceRoot 'eng/ProductionProtocolClosure.InputAudit.targets')
    if ([string] $value.Properties.TargetFramework -cne [string] $Package.targetFramework -or
        [string] $value.Properties.RepositoryType -cne [string] $Policy.repositoryType -or
        (Get-CanonicalFullPath ([string] $value.Properties.MSBuildSDKsPath)) -cne $sdk.SdksPath -or
        (Get-CanonicalFullPath ([string] $value.Properties.MSBuildToolsPath)) -cne $sdk.SdkRoot -or
        (Get-CanonicalFullPath ([string] $value.Properties.MSBuildBinPath)) -cne $sdk.SdkRoot -or
        [string] $value.Properties.NETCoreSdkVersion -cne $sdk.Version -or
        [string] $value.Properties.MSBuildEnableWorkloadResolver -cne 'false' -or
        (Get-CanonicalFullPath ([string] $value.Properties.CustomAfterMicrosoftCommonTargets)) -cne $auditTargets -or
        (Get-CanonicalFullPath ([string] $value.Properties.ProductionProtocolClosureAuditProject)) -cne (Get-CanonicalFullPath $projectPath) -or
        [string] $value.Properties.ImportDirectoryBuildProps -cne 'false' -or
        [string] $value.Properties.ImportDirectoryBuildTargets -cne 'false' -or
        [string] $value.Properties.ImportDirectoryPackagesProps -cne 'false') {
        Throw-ClosureError "Hermetic MSBuild import/repository/TFM controls were not effective for $($Package.id)."
    }
    $source = Get-CanonicalFullPath $SourceRoot
    $dotnetRoot = $sdk.DotNetRoot
    $nugetRoot = Get-CanonicalFullPath ([string] $value.Properties.NuGetPackageRoot)
    if (-not (Test-PathWithin $nugetRoot $source)) { Throw-ClosureError "NuGetPackageRoot escaped the private snapshot for $($Package.id)." }
    $allowedRoots = @($source, $sdk.SdkRoot, (Join-Path $dotnetRoot 'packs'), $nugetRoot)
    function Assert-AllowedInput([string] $InputPath, [string] $Label) {
        if ([string]::IsNullOrWhiteSpace($InputPath)) { Throw-ClosureError "$Label has no evaluated FullPath." }
        $full = Get-CanonicalFullPath $InputPath
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Throw-ClosureError "$Label is missing: $full" }
        if (-not @($allowedRoots | Where-Object { Test-PathWithin $full $_ }).Count) {
            Throw-ClosureError "$Label escaped exact snapshot/SDK/private locked NuGet roots: $full"
        }
    }
    $allProjects = @(([string] $value.Properties.MSBuildAllProjects).Split(';', [StringSplitOptions]::RemoveEmptyEntries))
    if ($allProjects.Count -eq 0) { Throw-ClosureError "MSBuildAllProjects is empty for $($Package.id)." }
    foreach ($input in $allProjects) { Assert-AllowedInput $input "MSBuildAllProjects input for $($Package.id)" }
    foreach ($itemName in $itemNames.Split(',')) {
        if (-not $value.Items.Contains($itemName)) { continue }
        foreach ($item in @($value.Items[$itemName])) {
            $fullPath = if ($item.Contains('FullPath')) { [string] $item.FullPath } else { [string] $item.Identity }
            Assert-AllowedInput $fullPath "$itemName input for $($Package.id)"
        }
    }
}

function ConvertFrom-MsBuildJsonOutput([string] $Text, [string] $Label) {
    $start = $Text.IndexOf('{')
    if ($start -lt 0) { Throw-ClosureError "$Label returned no JSON." }
    try { return $Text.Substring($start) | ConvertFrom-Json -AsHashtable -Depth 64 }
    catch { Throw-ClosureError "$Label returned invalid JSON: $($_.Exception.Message)" }
}

function Assert-HermeticPostTargetInputs {
    param([string] $SourceRoot, [Collections.IDictionary] $Package, [Collections.IDictionary] $Value, [string] $ItemName, [string] $Label)
    $sdk = Get-SelectedDotNetSdkContract
    if (-not $Value.Items.Contains($ItemName)) { Throw-ClosureError "$Label did not return $ItemName." }
    $inputs = @($Value.Items[$ItemName])
    if ($inputs.Count -eq 0) { Throw-ClosureError "$Label returned an empty actual input set for $($Package.id)." }
    $source = Get-CanonicalFullPath $SourceRoot
    $nugetRoot = Join-Path $source '.closure-packages'
    $allowedRoots = @($source, $sdk.SdkRoot, (Join-Path $sdk.DotNetRoot 'packs'), $nugetRoot)
    foreach ($item in $inputs) {
        $path = if ($item.Contains('FullPath')) { [string] $item.FullPath } else { [string] $item.Identity }
        if ([string]::IsNullOrWhiteSpace($path)) { Throw-ClosureError "$Label returned an actual input without a path." }
        $full = Get-CanonicalFullPath $path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Throw-ClosureError "$Label actual input is missing: $full" }
        Assert-NoReparseAncestors $full "$Label actual input"
        if (-not @($allowedRoots | Where-Object { Test-PathWithin $full $_ }).Count) {
            Throw-ClosureError "$Label actual input escaped exact snapshot/SDK/private locked NuGet roots: $full"
        }
    }
}

function Invoke-HermeticAuditedTarget {
    param(
        [string] $SourceRoot,
        [Collections.IDictionary] $Policy,
        [Collections.IDictionary] $Package,
        [string] $Version,
        [string] $Commit,
        [ValidateSet('Build', 'Pack')] [string] $Target,
        [string] $PackageOutputPath = '')
    $project = Join-Path $SourceRoot $Package.project
    $properties = @(Get-HermeticMsBuildProperties $SourceRoot $Package $Version $Policy $Commit)
    $properties += @('-p:Configuration=Release', "-p:ProductionProtocolClosureAuditKind=$Target")
    $itemName = if ($Target -ceq 'Build') { '_ProductionProtocolActualCompilerInput' } else { '_ProductionProtocolActualPackInput' }
    if ($Target -ceq 'Pack') {
        if ([string]::IsNullOrWhiteSpace($PackageOutputPath)) { Throw-ClosureError 'Audited Pack requires PackageOutputPath.' }
        $properties += @('-p:NoBuild=true', '-p:NoRestore=true', "-p:PackageOutputPath=$(Get-CanonicalFullPath $PackageOutputPath)")
    }
    $binlog = New-MsBuildAuditLogPath $SourceRoot
    $arguments = @('msbuild', $project, '-nologo', '-verbosity:quiet', "-target:$Target", "-binaryLogger:$binlog;ProjectImports=None", "-getItem:$itemName") + $properties
    $text = Invoke-PinnedDotNetText $arguments "Audited $Target for $($Package.project)"
    Assert-HermeticMsBuildBinlogInputs $SourceRoot $Package $binlog "Audited $Target for $($Package.id)"
    $value = ConvertFrom-MsBuildJsonOutput $text "Audited $Target for $($Package.id)"
    Assert-HermeticPostTargetInputs $SourceRoot $Package $value $itemName "Audited $Target for $($Package.id)"
    if ($Target -ceq 'Build') {
        Assert-HermeticCompilerInvocations $SourceRoot $Package $binlog
        $outputs = @($Package.packInputs | Where-Object { $_.StartsWith('build:', [StringComparison]::Ordinal) } | ForEach-Object {
            $path = Get-BuildPackInputPath $SourceRoot $Package $_
            Assert-NoReparseAncestors $path 'Audited build output'
            [ordered]@{ input = [string] $_; sha256 = Get-FileDigest $path }
        })
        $manifestPath = Join-Path $SourceRoot ".closure-audit/$($Package.id).build.json"
        [IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $outputs -Compress), [Text.UTF8Encoding]::new($false))
    }
}

function Get-EvaluatedProjectContract {
    param([string] $SourceRoot, [Collections.IDictionary] $Policy, [Collections.IDictionary] $Package, [string] $Version)
    $projectPath = Join-Path $SourceRoot $Package.project
    $arguments = @('msbuild', $projectPath, '-nologo', '-verbosity:quiet',
        '-getProperty:TargetFramework,RepositoryType', '-getItem:PackageReference,ProjectReference')
    $arguments += @(Get-HermeticMsBuildProperties $SourceRoot $Package $Version $Policy)
    $text = Invoke-PinnedDotNetText $arguments "MSBuild policy evaluation for $($Package.project)"
    $start = $text.IndexOf('{')
    if ($start -lt 0) { Throw-ClosureError "MSBuild policy evaluation returned no JSON for $($Package.project)." }
    try { $value = $text.Substring($start) | ConvertFrom-Json -AsHashtable }
    catch { Throw-ClosureError "MSBuild policy evaluation JSON is invalid for $($Package.project)." }
    if ([string] $value.Properties.TargetFramework -cne [string] $Package.targetFramework) {
        Throw-ClosureError "Evaluated TargetFramework differs from policy for $($Package.id)."
    }
    if ([string] $value.Properties.RepositoryType -cne [string] $Policy.repositoryType) {
        Throw-ClosureError "Evaluated RepositoryType differs from policy for $($Package.id)."
    }
    $packageItems = if ($value.Items.Contains('PackageReference')) { @($value.Items.PackageReference) } else { @() }
    $packagePairs = @($packageItems | ForEach-Object { "{0}={1}" -f [string] $_.Identity, [string] $_.Version } | Sort-Object)
    $expectedPackagePairs = @($Package.packageReferences | ForEach-Object { "{0}={1}" -f [string] $_.id, [string] $_.version } | Sort-Object)
    if (($packagePairs -join "`n") -cne ($expectedPackagePairs -join "`n")) {
        Throw-ClosureError "Evaluated direct PackageReference IDs or exact constraints differ from policy for $($Package.id)."
    }
    $projectIds = @()
    $projectItems = if ($value.Items.Contains('ProjectReference')) { @($value.Items.ProjectReference) } else { @() }
    foreach ($reference in $projectItems) {
        $fullPath = [IO.Path]::GetFullPath([string] $reference.FullPath)
        $matches = @($Policy.packages | Where-Object { [IO.Path]::GetFullPath((Join-Path $SourceRoot $_.project)) -ieq $fullPath })
        if ($matches.Count -ne 1) { Throw-ClosureError "Evaluated ProjectReference is outside policy for $($Package.id): $fullPath" }
        $projectIds += [string] $matches[0].id
    }
    if ((@($projectIds | Sort-Object) -join "`n") -cne (@($Package.projectReferences | Sort-Object) -join "`n")) {
        Throw-ClosureError "Evaluated ProjectReference IDs differ from policy for $($Package.id)."
    }
    return [ordered]@{ packageReferences = $packagePairs; projectReferences = @($projectIds | Sort-Object) }
}

function Get-LockedGraph {
    param([string] $SourceRoot, [Collections.IDictionary] $Package)
    $lockPath = Join-Path $SourceRoot $Package.lockFile
    $lock = Read-StrictJsonHashtable $lockPath "Archived lock for $($Package.id)"
    Assert-ExactKeys $lock @('version', 'dependencies') "Archived lock root for $($Package.id)"
    if ($lock.version -ne 1 -or $lock.dependencies -isnot [Collections.IDictionary] -or
        $lock.dependencies.Count -ne 1 -or @($lock.dependencies.Keys | Where-Object { [string] $_ -ceq [string] $Package.targetFramework }).Count -ne 1) {
        Throw-ClosureError "Archived lock has an unsupported shape for $($Package.id)."
    }
    $result = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $framework = $lock.dependencies[[string] $Package.targetFramework]
    if ($framework -isnot [Collections.IDictionary]) { Throw-ClosureError "Archived lock framework is malformed for $($Package.id)." }
    foreach ($entry in $framework.GetEnumerator()) {
            $record = $entry.Value
            if ($record -isnot [Collections.IDictionary]) { Throw-ClosureError "Archived lock entry is not an object: $($entry.Key)." }
            if (-not $record.Contains('type')) { Throw-ClosureError "Archived lock entry has no type: $($entry.Key)." }
            $type = [string] $record.type
            if ($type -notin @('Direct', 'Transitive', 'Project')) { Throw-ClosureError "Archived lock type is unsupported: $($entry.Key)." }
            $expectedRecordKeys = switch ($type) {
                'Direct' { @('type', 'requested', 'resolved', 'contentHash', 'dependencies') }
                'Transitive' { @('type', 'resolved', 'contentHash', 'dependencies') }
                'Project' { @('type', 'dependencies') }
            }
            $actualRecordKeys = @($record.Keys | ForEach-Object { [string] $_ })
            $allowedRecordKeys = @($expectedRecordKeys | Where-Object { $_ -cne 'dependencies' })
            if ($record.Contains('dependencies')) { $allowedRecordKeys += 'dependencies' }
            if ((@($actualRecordKeys | Sort-Object) -join "`n") -cne (@($allowedRecordKeys | Sort-Object) -join "`n")) {
                Throw-ClosureError "Archived lock entry fields are not exact for $($entry.Key)."
            }
            $dependencies = if ($record.Contains('dependencies') -and $null -ne $record.dependencies) { $record.dependencies } else { @{} }
            if ($dependencies -isnot [Collections.IDictionary]) { Throw-ClosureError "Archived lock dependencies are malformed: $($entry.Key)." }
            foreach ($dependency in $dependencies.GetEnumerator()) {
                if ([string]::IsNullOrWhiteSpace([string] $dependency.Key) -or $dependency.Value -isnot [string]) {
                    Throw-ClosureError "Archived lock dependency key/range is malformed: $($entry.Key)."
                }
            }
            if ($type -ne 'Project') {
                if ([string] $record.resolved -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$' -or
                    -not (Test-CanonicalContentHash ([string] $record.contentHash))) {
                    Throw-ClosureError "Archived lock entry needs an exact version and canonical base64 SHA-512 contentHash: $($entry.Key)."
                }
            }
            $candidate = [PSCustomObject]@{
                id = [string] $entry.Key; type = $type
                version = if ($type -eq 'Project') { '' } else { [string] $record.resolved }
                contentHash = if ($type -eq 'Project') { '' } else { [string] $record.contentHash }
                requested = if ($type -eq 'Direct') { [string] $record.requested } else { '' }
                dependencies = $dependencies
            }
        if ($result.ContainsKey($candidate.id)) { Throw-ClosureError "Archived lock contains a duplicate entry: $($candidate.id)." }
        $result.Add($candidate.id, $candidate)
    }
    $direct = @($result.Values | Where-Object type -ceq 'Direct' | ForEach-Object id | Sort-Object)
    if (($direct -join "`n") -cne ((Get-PolicyDirectPackageIds $Package) -join "`n")) {
        Throw-ClosureError "Archived lock Direct entries differ from policy PackageReference IDs for $($Package.id)."
    }
    foreach ($id in $direct) {
        $exactConstraint = Get-PolicyDirectPackageVersion $Package $id
        $exactVersion = $exactConstraint.Trim('[', ']')
        $record = $result[$id]
        $lockExactRange = "[$exactVersion, $exactVersion]"
        if ($record.version -cne $exactVersion -or [string] $record.requested -cne $lockExactRange) {
            Throw-ClosureError "Archived lock direct PackageReference resolved version differs from policy: $($Package.id) -> $id"
        }
        Assert-ClosureNuGetRangeSatisfies ([string] $record.requested) ([string] $record.version) "Archived lock direct range $($Package.id) -> $id"
    }
    $projectEntries = @($result.Values | Where-Object type -ceq 'Project')
    if ($projectEntries.Count -ne $Package.projectReferences.Count) {
        Throw-ClosureError "Archived lock Project entries differ from policy for $($Package.id)."
    }
    foreach ($projectId in $Package.projectReferences) {
        if (-not $result.ContainsKey($projectId) -or $result[$projectId].type -cne 'Project') {
            Throw-ClosureError "Archived lock lacks policy project reference $($Package.id) -> $projectId."
        }
    }
    foreach ($entry in $result.Values) {
        foreach ($dependencyId in $entry.dependencies.Keys) {
            if (-not $result.ContainsKey([string] $dependencyId)) {
                Throw-ClosureError "Archived lock graph has a missing target: $($entry.id) -> $dependencyId."
            }
            $target = $result[[string] $dependencyId]
            if ($target.type -eq 'Project') {
                Throw-ClosureError "Archived lock contains a NuGet range targeting a project entry: $($entry.id) -> $dependencyId."
            }
            Assert-ClosureNuGetRangeSatisfies ([string] $entry.dependencies[$dependencyId]) ([string] $target.version) "Archived lock dependency range $($entry.id) -> $dependencyId"
        }
    }
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [Collections.Generic.Queue[string]]::new()
    foreach ($root in @(Get-PolicyDirectPackageIds $Package) + @($Package.projectReferences)) { $queue.Enqueue([string] $root) }
    while ($queue.Count -gt 0) {
        $id = $queue.Dequeue()
        if (-not $visited.Add($id)) { continue }
        foreach ($dependencyId in $result[$id].dependencies.Keys) { $queue.Enqueue([string] $dependencyId) }
    }
    if ($visited.Count -ne $result.Count) { Throw-ClosureError "Archived lock contains an unreachable or unaccounted entry for $($Package.id)." }
    return $result
}

function Get-DependencyContract {
    param([Collections.IDictionary] $Package, $Locked, [string] $Version)
    $contract = [ordered]@{}
    foreach ($id in $Package.projectReferences) { $contract[[string] $id] = $Version }
    foreach ($id in (Get-PolicyDirectPackageIds $Package)) { $contract[[string] $id] = [string] $Locked[$id].version }
    return $contract
}

function ConvertTo-CanonicalNuGetFramework([string] $Value, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -cnotmatch '^net(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$') {
        Throw-ClosureError "$Label is not a supported canonical NuGet target framework."
    }
    return $Value
}

function Read-PackageMetadata([string] $Path, [string] $ExpectedTargetFramework) {
    $expectedFramework = ConvertTo-CanonicalNuGetFramework $ExpectedTargetFramework 'Expected package target framework'
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -le 0 -or $archive.Entries.Count -gt 4096) { Throw-ClosureError "Package entry count is invalid: $Path" }
        $names = @($archive.Entries | ForEach-Object FullName)
        if (@($names | Sort-Object -Unique).Count -ne $names.Count -or
            @($names | Where-Object { $_ -ceq '[Content_Types].xml' }).Count -ne 1 -or
            @($names | Where-Object { $_ -ceq '_rels/.rels' }).Count -ne 1 -or
            @($names | Where-Object { $_ -cmatch '^package/services/metadata/core-properties/[^/]+\.psmdcp$' }).Count -ne 1) {
            Throw-ClosureError "Package metadata entries are duplicated or not exact: $Path"
        }
        $nuspec = @($archive.Entries | Where-Object { $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) })
        if ($nuspec.Count -ne 1 -or $nuspec[0].Length -gt 1MB) { Throw-ClosureError "Package has no unique bounded nuspec: $Path" }
        $reader = [IO.StreamReader]::new($nuspec[0].Open(), [Text.UTF8Encoding]::new($false, $true))
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $settings = [Xml.XmlReaderSettings]::new(); $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
        $xmlReader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
        try { $document = [Xml.XmlDocument]::new(); $document.XmlResolver = $null; $document.Load($xmlReader) } finally { $xmlReader.Dispose() }
        $ns = [Xml.XmlNamespaceManager]::new($document.NameTable); $ns.AddNamespace('n', $document.DocumentElement.NamespaceURI)
        $id = @($document.SelectNodes('/n:package/n:metadata/n:id', $ns)); $version = @($document.SelectNodes('/n:package/n:metadata/n:version', $ns)); $repository = @($document.SelectNodes('/n:package/n:metadata/n:repository', $ns))
        if ($id.Count -ne 1 -or $version.Count -ne 1 -or $repository.Count -ne 1) {
            Throw-ClosureError "Package identity/repository metadata is not unique and exact: $Path"
        }
        $dependencyContainers = @($document.SelectNodes('/n:package/n:metadata/n:dependencies', $ns))
        $groups = @($document.SelectNodes('/n:package/n:metadata/n:dependencies/n:group', $ns))
        $ungrouped = @($document.SelectNodes('/n:package/n:metadata/n:dependencies/n:dependency', $ns))
        if ($dependencyContainers.Count -ne 1 -or $groups.Count -ne 1 -or $ungrouped.Count -ne 0 -or
            $groups[0].Attributes.Count -ne 1 -or $groups[0].GetAttribute('targetFramework') -cne $expectedFramework) {
            Throw-ClosureError "Package must contain exactly one dependency group for canonical $expectedFramework and no ungrouped/other groups: $Path"
        }
        $dependencies = @($groups[0].SelectNodes('n:dependency', $ns))
        if (@($groups[0].ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element -and $_.LocalName -cne 'dependency' }).Count -ne 0) {
            Throw-ClosureError "Package dependency group contains an unsupported element: $Path"
        }
        return [PSCustomObject]@{
            id = $id[0].InnerText; version = $version[0].InnerText
            commit = $repository[0].GetAttribute('commit'); repositoryUrl = $repository[0].GetAttribute('url'); repositoryType = $repository[0].GetAttribute('type')
            targetFramework = $expectedFramework
            dependencies = @($dependencies | ForEach-Object { [PSCustomObject]@{ id = $_.GetAttribute('id'); version = $_.GetAttribute('version') } })
            entries = $names
        }
    }
    finally { $archive.Dispose() }
}

function Get-BuildPackInputPath([string] $SourceRoot, $Package, [string] $InputName) {
    if ($InputName -cnotin @("build:$($Package.id).dll", "build:$($Package.id).pdb")) { Throw-ClosureError "Unsupported build pack mapping: $InputName" }
    $projectDirectory = Split-Path -Parent (Join-Path $SourceRoot $Package.project)
    return Join-Path $projectDirectory "bin/Release/$($Package.targetFramework)/$($InputName.Substring(6))"
}

function Assert-PackagePackTargets([string] $Path, [Collections.IDictionary] $Package, [string] $SourceRoot) {
    $metadata = Read-PackageMetadata $Path ([string] $Package.targetFramework)
    $payload = @($metadata.entries | Where-Object {
        $_ -cne '[Content_Types].xml' -and $_ -cne '_rels/.rels' -and
        $_ -cne "$($Package.id).nuspec" -and
        $_ -cnotmatch '^package/services/metadata/core-properties/[^/]+\.psmdcp$'
    } | Sort-Object)
    if (($payload -join "`n") -cne (@($Package.packTargets | Sort-Object) -join "`n")) {
        Throw-ClosureError "Package payload targets differ from policy for $($Package.id)."
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $buildInputs = @($Package.packInputs | Where-Object { $_.StartsWith('build:', [StringComparison]::Ordinal) })
        $buildManifest = @()
        if ($buildInputs.Count -gt 0) {
            $manifestPath = Join-Path $SourceRoot ".closure-audit/$($Package.id).build.json"
            Assert-NoReparseAncestors $manifestPath 'Audited build manifest'
            $buildManifest = @(Read-StrictJsonHashtable $manifestPath 'Audited build manifest')
            if ($buildManifest.Count -ne $buildInputs.Count) { Throw-ClosureError 'Audited build manifest has the wrong exact output set.' }
        }
        for ($index = 0; $index -lt $Package.packInputs.Count; $index++) {
            $input = [string] $Package.packInputs[$index]
            $entry = @($archive.Entries | Where-Object FullName -ceq ([string] $Package.packTargets[$index]))
            if ($entry.Count -ne 1) { Throw-ClosureError "Tracked pack target is missing: $($Package.packTargets[$index])" }
            $source = if ($input.StartsWith('build:', [StringComparison]::Ordinal)) { Get-BuildPackInputPath $SourceRoot $Package $input } else { Join-Path $SourceRoot $input }
            Assert-NoReparseAncestors $source 'Pack source input'
            $sourceHash = Get-FileDigest $source
            if ($input.StartsWith('build:', [StringComparison]::Ordinal)) {
                $record = @($buildManifest | Where-Object input -ceq $input)
                if ($record.Count -ne 1) { Throw-ClosureError 'Audited build manifest has missing/duplicate mappings.' }
                Assert-ExactKeys $record[0] @('input', 'sha256') 'Audited build output'
                if ($record[0].sha256 -cne $sourceHash) { Throw-ClosureError "Build output changed after compiler audit: $input" }
            }
            $stream = $entry[0].Open()
            try { $entryHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() } finally { $stream.Dispose() }
            if ($entryHash -cne $sourceHash) { Throw-ClosureError "Pack input bytes changed in package: $input" }
        }
    }
    finally { $archive.Dispose() }
}

function Set-ExactNuspecDependencies([string] $Path, [Collections.IDictionary] $Contract, [string] $ExpectedTargetFramework) {
    $expectedFramework = ConvertTo-CanonicalNuGetFramework $ExpectedTargetFramework 'Expected package target framework'
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Update, $true)
        try {
            $manifest = @($archive.Entries | Where-Object { $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) })
            if ($manifest.Count -ne 1) { Throw-ClosureError 'Package has no unique nuspec before dependency normalization.' }
            $reader = [IO.StreamReader]::new($manifest[0].Open(), [Text.UTF8Encoding]::new($false, $true)); try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
            $settings = [Xml.XmlReaderSettings]::new(); $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
            $xmlReader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
            try { $document = [Xml.XmlDocument]::new(); $document.PreserveWhitespace = $true; $document.XmlResolver = $null; $document.Load($xmlReader) } finally { $xmlReader.Dispose() }
            $ns = [Xml.XmlNamespaceManager]::new($document.NameTable); $ns.AddNamespace('n', $document.DocumentElement.NamespaceURI)
            $containers = @($document.SelectNodes('/n:package/n:metadata/n:dependencies', $ns))
            $groups = @($document.SelectNodes('/n:package/n:metadata/n:dependencies/n:group', $ns))
            $ungrouped = @($document.SelectNodes('/n:package/n:metadata/n:dependencies/n:dependency', $ns))
            if ($containers.Count -ne 1 -or $groups.Count -ne 1 -or $ungrouped.Count -ne 0 -or
                $groups[0].Attributes.Count -ne 1 -or $groups[0].GetAttribute('targetFramework') -cne $expectedFramework) {
                Throw-ClosureError "Nuspec must have exactly one canonical $expectedFramework dependency group before normalization."
            }
            $dependencies = @($groups[0].SelectNodes('n:dependency', $ns))
            if ($dependencies.Count -ne $Contract.Count) { Throw-ClosureError 'Nuspec direct dependency IDs differ from policy/project/lock Direct entries.' }
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($dependency in $dependencies) {
                $id = $dependency.GetAttribute('id')
                if (-not $seen.Add($id) -or -not $Contract.Contains($id) -or @($Contract.Keys | Where-Object { $_ -ceq $id }).Count -ne 1) {
                    Throw-ClosureError "Nuspec has a duplicate, injected, transitive, or non-canonical direct dependency: $id"
                }
                $dependency.SetAttribute('version', "[$($Contract[$id])]")
            }
            $name = $manifest[0].FullName; $manifest[0].Delete()
            $replacement = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
            $replacement.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $writer = [IO.StreamWriter]::new($replacement.Open(), [Text.UTF8Encoding]::new($false)); try { $writer.Write($document.OuterXml) } finally { $writer.Dispose() }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}
