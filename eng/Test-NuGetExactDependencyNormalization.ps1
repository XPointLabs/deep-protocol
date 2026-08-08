[CmdletBinding()]
param(
    [string] $RepositoryRoot = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$source = Join-Path $RepositoryRoot `
    'vendor\p10j-package-closure\packages\Deep.Protocol.0.3.0-p10j.2886880.nupkg'
$normalizer = Join-Path $RepositoryRoot 'eng\Normalize-NuGetPackage.ps1'
$closureNormalizer = Join-Path $RepositoryRoot `
    'eng\Normalize-ProductionProtocolClosure.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) `
    "deep-nupkg-exact-dependency-$([Guid]::NewGuid().ToString('N'))"
$version = '0.3.0-p10j.2886880'
$contract = @(
    "Deep.Protocol.Abstractions=$version",
    "Deep.Protocol.Protobuf=$version"
)

function Assert-Throws {
    param([scriptblock] $Action, [string] $Name)
    try {
        & $Action
    }
    catch {
        return
    }
    throw "Expected '$Name' to fail closed."
}

function Read-DependencyVersions {
    param([string] $Package)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Package)
    try {
        $manifest = @($archive.Entries | Where-Object {
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($manifest.Count -ne 1) { throw 'Synthetic package manifest is not unique.' }
        $reader = [IO.StreamReader]::new($manifest[0].Open())
        try { [xml] $xml = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $result = @{}
        foreach ($dependency in $xml.package.metadata.dependencies.group.dependency) {
            if ($result.ContainsKey([string] $dependency.id)) {
                throw "Dependency '$($dependency.id)' is duplicated."
            }
            $result[[string] $dependency.id] = [string] $dependency.version
        }
        return $result
    }
    finally {
        $archive.Dispose()
    }
}

function Add-DuplicateDependency {
    param([string] $Package)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open(
        $Package,
        [IO.Compression.ZipArchiveMode]::Update)
    try {
        $manifest = @($archive.Entries | Where-Object {
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($manifest.Count -ne 1) { throw 'Synthetic package manifest is not unique.' }
        $name = $manifest[0].FullName
        $reader = [IO.StreamReader]::new($manifest[0].Open())
        try { $text = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $needle = "        <dependency id=`"Deep.Protocol.Abstractions`" version=`"$version`" exclude=`"Build,Analyzers`" />"
        if ($text.IndexOf($needle, [StringComparison]::Ordinal) -lt 0) {
            throw 'Synthetic dependency line is missing.'
        }
        $text = $text.Replace($needle, "$needle`r`n$needle")
        $manifest[0].Delete()
        $entry = $archive.CreateEntry($name)
        $writer = [IO.StreamWriter]::new(
            $entry.Open(),
            [Text.UTF8Encoding]::new($false))
        try { $writer.Write($text) }
        finally { $writer.Dispose() }
    }
    finally {
        $archive.Dispose()
    }
}

function Set-RepositoryUrl {
    param([string] $Package, [string] $Url)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Package, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $manifest = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
        if ($manifest.Count -ne 1) { throw 'Synthetic package manifest is not unique.' }
        $name = $manifest[0].FullName
        $reader = [IO.StreamReader]::new($manifest[0].Open())
        try { [xml] $xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $xml.package.metadata.repository.SetAttribute('url', $Url)
        $manifest[0].Delete()
        $entry = $archive.CreateEntry($name)
        $writer = [IO.StreamWriter]::new($entry.Open(), [Text.UTF8Encoding]::new($false))
        try { $xml.Save($writer) } finally { $writer.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Mutate-NuspecText {
    param([string] $Package, [scriptblock] $Mutation)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Package, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $manifest = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
        if ($manifest.Count -ne 1) { throw 'Synthetic package manifest is not unique.' }
        $name = $manifest[0].FullName
        $reader = [IO.StreamReader]::new($manifest[0].Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $changed = & $Mutation $text
        if ($changed -ceq $text) { throw 'Synthetic nuspec mutation made no change.' }
        $manifest[0].Delete()
        $entry = $archive.CreateEntry($name)
        $writer = [IO.StreamWriter]::new($entry.Open(), [Text.UTF8Encoding]::new($false))
        try { $writer.Write($changed) } finally { $writer.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Add-ZipEntry {
    param([string] $Package, [string] $Name, [int] $Bytes = 1)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Package, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $archive.CreateEntry($Name)
        $stream = $entry.Open()
        try {
            $block = [byte[]]::new([Math]::Min(1MB, $Bytes))
            $remaining = $Bytes
            while ($remaining -gt 0) {
                $write = [Math]::Min($remaining, $block.Length)
                $stream.Write($block, 0, $write)
                $remaining -= $write
            }
        }
        finally { $stream.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Add-ZipEntries {
    param([string] $Package, [int] $Count)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Package, [IO.Compression.ZipArchiveMode]::Update)
    try {
        for ($index = 0; $index -lt $Count; $index++) {
            $stream = $archive.CreateEntry("count/$index.bin").Open()
            try { $stream.WriteByte(0) } finally { $stream.Dispose() }
        }
    }
    finally { $archive.Dispose() }
}

function Copy-ClosureCase {
    param([string] $SourceDirectory, [string] $Name)
    $destination = Join-Path $root $Name
    New-Item -ItemType Directory -Path $destination | Out-Null
    Get-ChildItem -LiteralPath $SourceDirectory -File | Copy-Item -Destination $destination
    return $destination
}

New-Item -ItemType Directory -Path $root | Out-Null
try {
    $valid = Join-Path $root 'valid.nupkg'
    Copy-Item -LiteralPath $source -Destination $valid
    & $normalizer -Path $valid -ExactDependency $contract `
        -ExactDependencyPrefix 'Deep.Protocol'
    $versions = Read-DependencyVersions $valid
    if ($versions['Deep.Protocol.Abstractions'] -cne "[$version]" -or
        $versions['Deep.Protocol.Protobuf'] -cne "[$version]") {
        throw 'Normalizer did not emit exact internal dependency ranges.'
    }

    $second = Join-Path $root 'second.nupkg'
    Copy-Item -LiteralPath $source -Destination $second
    & $normalizer -Path $second -ExactDependency $contract `
        -ExactDependencyPrefix 'Deep.Protocol'
    if ((Get-FileHash $valid -Algorithm SHA256).Hash -cne
        (Get-FileHash $second -Algorithm SHA256).Hash) {
        throw 'Exact dependency normalization is not deterministic.'
    }

    $missing = Join-Path $root 'missing.nupkg'
    Copy-Item -LiteralPath $source -Destination $missing
    Assert-Throws {
        & $normalizer -Path $missing `
            -ExactDependency @("Deep.Protocol.Abstractions=$version") `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'unexpected internal dependency'

    $absent = Join-Path $root 'absent.nupkg'
    Copy-Item -LiteralPath $source -Destination $absent
    Assert-Throws {
        & $normalizer -Path $absent -ExactDependency ($contract + @(
            "Deep.Protocol.MembershipRoutes=$version")) `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'missing expected dependency'

    $drift = Join-Path $root 'drift.nupkg'
    Copy-Item -LiteralPath $source -Destination $drift
    Assert-Throws {
        & $normalizer -Path $drift -ExactDependency @(
            'Deep.Protocol.Abstractions=9.9.9',
            "Deep.Protocol.Protobuf=$version") `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'dependency version drift'

    $duplicateContract = Join-Path $root 'duplicate-contract.nupkg'
    Copy-Item -LiteralPath $source -Destination $duplicateContract
    Assert-Throws {
        & $normalizer -Path $duplicateContract -ExactDependency @(
            "Deep.Protocol.Abstractions=$version",
            "Deep.Protocol.Abstractions=$version") `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'duplicate contract entry'

    $duplicateNuspec = Join-Path $root 'duplicate-nuspec.nupkg'
    Copy-Item -LiteralPath $source -Destination $duplicateNuspec
    Add-DuplicateDependency $duplicateNuspec
    Assert-Throws {
        & $normalizer -Path $duplicateNuspec -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'duplicate nuspec dependency'

    $caseVariant = Join-Path $root 'case-variant.nupkg'
    Copy-Item -LiteralPath $source -Destination $caseVariant
    Mutate-NuspecText $caseVariant { param($text) $text.Replace(
        'Deep.Protocol.Abstractions', 'deep.protocol.abstractions') }
    Assert-Throws {
        & $normalizer -Path $caseVariant -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'case-variant dependency identity'

    $duplicateGroup = Join-Path $root 'duplicate-group.nupkg'
    Copy-Item -LiteralPath $source -Destination $duplicateGroup
    Mutate-NuspecText $duplicateGroup { param($text) $text.Replace(
        '</dependencies>', '<group targetFramework="net10.0" /></dependencies>') }
    Assert-Throws {
        & $normalizer -Path $duplicateGroup -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'duplicate target-framework group'

    $duplicateContainer = Join-Path $root 'duplicate-container.nupkg'
    Copy-Item -LiteralPath $source -Destination $duplicateContainer
    Mutate-NuspecText $duplicateContainer { param($text) $text.Replace(
        '</metadata>', '<dependencies><group targetFramework="net9.0" /></dependencies></metadata>') }
    Assert-Throws {
        & $normalizer -Path $duplicateContainer -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'duplicate dependencies container'

    $caseCollision = Join-Path $root 'case-collision.nupkg'
    Copy-Item -LiteralPath $source -Destination $caseCollision
    Add-ZipEntry $caseCollision 'LIB/net10.0/Deep.Protocol.dll'
    Assert-Throws {
        & $normalizer -Path $caseCollision -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'case-colliding ZIP part'

    $xmlUnsafe = Join-Path $root 'xml-unsafe.nupkg'
    Copy-Item -LiteralPath $source -Destination $xmlUnsafe
    Add-ZipEntry $xmlUnsafe 'bad&relationship.bin'
    Assert-Throws {
        & $normalizer -Path $xmlUnsafe -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'XML-unsafe ZIP part'

    $oversized = Join-Path $root 'oversized.nupkg'
    Copy-Item -LiteralPath $source -Destination $oversized
    Add-ZipEntry $oversized 'bomb.bin' (33MB)
    Assert-Throws {
        & $normalizer -Path $oversized -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'oversized ZIP part'

    $tooMany = Join-Path $root 'too-many.nupkg'
    Copy-Item -LiteralPath $source -Destination $tooMany
    Add-ZipEntries $tooMany 4091
    Assert-Throws {
        & $normalizer -Path $tooMany -ExactDependency $contract `
            -ExactDependencyPrefix 'Deep.Protocol'
    } 'excessive ZIP entry count'

    $cultureA = Join-Path $root 'culture-a.nupkg'
    $cultureB = Join-Path $root 'culture-b.nupkg'
    Copy-Item -LiteralPath $source -Destination $cultureA
    Copy-Item -LiteralPath $source -Destination $cultureB
    $oldCulture = [Globalization.CultureInfo]::CurrentCulture
    try {
        [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
        & $normalizer -Path $cultureA -ExactDependency $contract -ExactDependencyPrefix 'Deep.Protocol'
        [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
        & $normalizer -Path $cultureB -ExactDependency $contract -ExactDependencyPrefix 'Deep.Protocol'
    }
    finally { [Globalization.CultureInfo]::CurrentCulture = $oldCulture }
    if ((Get-FileHash $cultureA -Algorithm SHA256).Hash -cne
        (Get-FileHash $cultureB -Algorithm SHA256).Hash) {
        throw 'Normalization changed across process cultures.'
    }

    $closure = Join-Path $root 'closure'
    New-Item -ItemType Directory -Path $closure | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot `
        'vendor\p10j-package-closure\packages') -File `
        -Filter 'Deep.Protocol*.nupkg' |
        Copy-Item -Destination $closure
    $repositoryUrl = 'https://github.com/XPointLabs/deep-protocol.git'
    Get-ChildItem -LiteralPath $closure -File -Filter '*.nupkg' |
        ForEach-Object { Set-RepositoryUrl $_.FullName $repositoryUrl }
    $closureOutput = Join-Path $root 'closure-output'
    & $closureNormalizer -InputDirectory $closure -OutputDirectory $closureOutput `
        -ProductionVersion $version `
        -ProfileCarrierVersion '0.2.0-p10j.2886880' `
        -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' `
        -RepositoryUrl $repositoryUrl
    $protocolDependencies = Read-DependencyVersions (Join-Path $closureOutput `
        "Deep.Protocol.$version.nupkg")
    $routesDependencies = Read-DependencyVersions (Join-Path $closureOutput `
        "Deep.Protocol.MembershipRoutes.$version.nupkg")
    $carrierDependencies = Read-DependencyVersions (Join-Path $closureOutput `
        'Deep.Protocol.ProfileCarrier.0.2.0-p10j.2886880.nupkg')
    if ($protocolDependencies['Deep.Protocol.Abstractions'] -cne "[$version]" -or
        $protocolDependencies['Deep.Protocol.Protobuf'] -cne "[$version]" -or
        $routesDependencies['Deep.Protocol'] -cne "[$version]" -or
        $carrierDependencies['Deep.Protocol'] -cne "[$version]") {
        throw 'Five-package closure did not exact-pin every internal dependency.'
    }
    Assert-Throws {
        & $closureNormalizer -InputDirectory $closure `
            -OutputDirectory (Join-Path $root 'traversal-output') `
            -ProductionVersion '..\escape' -ProfileCarrierVersion '0.2.0-p10j.2886880' `
            -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
    } 'path-traversal package version'
    foreach ($invalidVersion in @(
        '01.0.0',
        '1.0.0-01',
        '1.0.0+metadata',
        ("1.0.0-" + ('a' * 129)))) {
        Assert-Throws {
            & $closureNormalizer -InputDirectory $closure `
                -OutputDirectory (Join-Path $root 'invalid-version-output') `
                -ProductionVersion $invalidVersion -ProfileCarrierVersion '0.2.0-p10j.2886880' `
                -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
        } "non-canonical version $invalidVersion"
    }

    foreach ($mutation in @('version', 'commit', 'url', 'id')) {
        $case = Copy-ClosureCase $closure "closure-$mutation"
        $package = Get-ChildItem -LiteralPath $case -Filter 'Deep.Protocol.Abstractions*.nupkg'
        switch ($mutation) {
            'version' { Mutate-NuspecText $package.FullName { param($text) $text.Replace($version, '9.9.9') } }
            'commit' { Mutate-NuspecText $package.FullName { param($text) $text.Replace('2886880d4c2060cd819765c53c77a02e1c475ea8', ('1' * 40)) } }
            'url' { Mutate-NuspecText $package.FullName { param($text) $text.Replace($repositoryUrl, 'https://invalid.example/deep-protocol.git') } }
            'id' { Mutate-NuspecText $package.FullName { param($text) $text.Replace('<id>Deep.Protocol.Abstractions</id>', '<id>deep.protocol.abstractions</id>') } }
        }
        Assert-Throws {
            & $closureNormalizer -InputDirectory $case `
                -OutputDirectory (Join-Path $root "output-$mutation") `
                -ProductionVersion $version -ProfileCarrierVersion '0.2.0-p10j.2886880' `
                -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
        } "closure $mutation drift"
    }

    $nestedCase = Copy-ClosureCase $closure 'closure-nested'
    $nestedDirectory = Join-Path $nestedCase 'nested'
    New-Item -ItemType Directory -Path $nestedDirectory | Out-Null
    Copy-Item -LiteralPath $source -Destination (Join-Path $nestedDirectory 'Other.nupkg')
    Assert-Throws {
        & $closureNormalizer -InputDirectory $nestedCase -OutputDirectory (Join-Path $root 'nested-output') `
            -ProductionVersion $version -ProfileCarrierVersion '0.2.0-p10j.2886880' `
            -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
    } 'nested extra package'

    $lateCase = Copy-ClosureCase $closure 'closure-late-failure'
    $latePackage = Get-ChildItem -LiteralPath $lateCase -Filter 'Deep.Protocol.Protobuf*.nupkg'
    Add-ZipEntry $latePackage.FullName 'LIB/net10.0/Deep.Protocol.Protobuf.dll'
    $before = @(Get-ChildItem -LiteralPath $lateCase -File | Sort-Object Name |
        ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }) -join '|'
    $lateOutput = Join-Path $root 'late-output'
    Assert-Throws {
        & $closureNormalizer -InputDirectory $lateCase -OutputDirectory $lateOutput `
            -ProductionVersion $version -ProfileCarrierVersion '0.2.0-p10j.2886880' `
            -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
    } 'late package normalization failure'
    $after = @(Get-ChildItem -LiteralPath $lateCase -File | Sort-Object Name |
        ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }) -join '|'
    if ($before -cne $after -or (Test-Path -LiteralPath $lateOutput) -or
        @(Get-ChildItem -LiteralPath $root -Directory -Filter '.deep-protocol-closure-*').Count -ne 0) {
        throw 'Transactional closure failure mutated input, published output, or leaked temp state.'
    }

    if ($env:OS -eq 'Windows_NT') {
        $writerCase = Copy-ClosureCase $closure 'closure-open-writer'
        $writerPackage = Get-ChildItem -LiteralPath $writerCase -Filter 'Deep.Protocol.Abstractions*.nupkg'
        $writer = [IO.File]::Open(
            $writerPackage.FullName, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::ReadWrite)
        try {
            Assert-Throws {
                & $closureNormalizer -InputDirectory $writerCase `
                    -OutputDirectory (Join-Path $root 'writer-output') `
                    -ProductionVersion $version -ProfileCarrierVersion '0.2.0-p10j.2886880' `
                    -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
            } 'concurrent source writer'
        }
        finally { $writer.Dispose() }
    }

    $oversizeCase = Copy-ClosureCase $closure 'closure-oversize-handle'
    $oversizePackage = Get-ChildItem -LiteralPath $oversizeCase -Filter 'Deep.Protocol.Abstractions*.nupkg'
    $oversizeStream = [IO.File]::Open(
        $oversizePackage.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $oversizeStream.SetLength(65MB); $oversizeStream.Flush($true) }
    finally { $oversizeStream.Dispose() }
    Assert-Throws {
        & $closureNormalizer -InputDirectory $oversizeCase `
            -OutputDirectory (Join-Path $root 'oversize-handle-output') `
            -ProductionVersion $version -ProfileCarrierVersion '0.2.0-p10j.2886880' `
            -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' -RepositoryUrl $repositoryUrl
    } 'oversized stable source handle'

    Copy-Item -LiteralPath $source -Destination (Join-Path $closure 'Other.Unexpected.0.0.0.nupkg')
    Assert-Throws {
        & $closureNormalizer -InputDirectory $closure `
            -OutputDirectory (Join-Path $root 'must-not-exist') `
            -ProductionVersion $version `
            -ProfileCarrierVersion '0.2.0-p10j.2886880' `
            -SourceCommit '2886880d4c2060cd819765c53c77a02e1c475ea8' `
            -RepositoryUrl $repositoryUrl
    } 'extra package in closure'

    Write-Output 'PASS exact NuGet internal dependency normalization contract'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -File |
            ForEach-Object { $_.IsReadOnly = $false }
        [IO.Directory]::Delete($root, $true)
    }
}
