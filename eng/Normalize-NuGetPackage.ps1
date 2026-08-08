param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [string[]] $ExactDependency = @(),

    [string] $ExactDependencyPrefix = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-ExactDependencyMap {
    param([string[]] $Values)

    $result = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $Values) {
        $separator = $value.IndexOf('=', [StringComparison]::Ordinal)
        if ($separator -le 0 -or $separator -eq $value.Length - 1) {
            throw "Exact dependencies must use the 'PackageId=Version' form."
        }

        $id = $value.Substring(0, $separator)
        $version = $value.Substring($separator + 1)
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$' -or
            $version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
            throw "Exact dependency '$value' is not canonical."
        }
        if ($result.ContainsKey($id)) {
            throw "Exact dependency '$id' is duplicated."
        }
        $result.Add($id, $version)
    }
    return $result
}

function Set-ExactDependencies {
    param(
        [byte[]] $ManifestBytes,
        [Collections.Generic.Dictionary[string, string]] $Expected,
        [string] $Prefix
    )

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $text = $utf8.GetString($ManifestBytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char] 0xfeff) {
        $text = $text.Substring(1)
    }
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.PreserveWhitespace = $true
        $document.XmlResolver = $null
        $document.Load($reader)
    }
    finally {
        $reader.Dispose()
    }

    $namespace = $document.DocumentElement.NamespaceURI
    $manager = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $manager.AddNamespace('n', $namespace)
    $containers = @($document.SelectNodes(
        '/n:package/n:metadata/n:dependencies', $manager))
    if ($containers.Count -gt 1) {
        throw "The nuspec contains duplicate dependencies containers."
    }
    $dependencies = @()
    if ($containers.Count -eq 1) {
        $groups = @($containers[0].SelectNodes('n:group', $manager))
        $direct = @($containers[0].SelectNodes('n:dependency', $manager))
        $elements = @($containers[0].ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
        if ($elements.Count -ne ($groups.Count + $direct.Count)) {
            throw "The nuspec dependencies container has unexpected elements."
        }
        if ($groups.Count -gt 0 -and $direct.Count -gt 0) {
            throw "The nuspec mixes grouped and direct dependencies."
        }
        $frameworks = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($group in $groups) {
            $framework = $group.GetAttribute('targetFramework')
            if ([string]::IsNullOrWhiteSpace($framework) -or
                -not $frameworks.Add($framework)) {
                throw "The nuspec contains an empty or duplicate dependency group."
            }
            $groupDependencies = @($group.SelectNodes('n:dependency', $manager))
            $groupElements = @($group.ChildNodes | Where-Object {
                $_.NodeType -eq [Xml.XmlNodeType]::Element
            })
            if ($groupElements.Count -ne $groupDependencies.Count) {
                throw "The nuspec dependency group has unexpected elements."
            }
            $dependencies += $groupDependencies
        }
        if ($groups.Count -eq 0) { $dependencies = $direct }
    }

    $identities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($dependency in $dependencies) {
        $id = $dependency.GetAttribute('id')
        if ([string]::IsNullOrWhiteSpace($id) -or -not $identities.Add($id)) {
            throw "The nuspec contains an empty or duplicate dependency identity."
        }
    }

    if (-not [string]::IsNullOrEmpty($Prefix)) {
        foreach ($dependency in $dependencies) {
            $id = $dependency.GetAttribute('id')
            if ($id.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) -and
                -not $Expected.ContainsKey($id)) {
                throw "Internal dependency '$id' is not declared in the exact dependency contract."
            }
        }
    }

    foreach ($entry in $Expected.GetEnumerator()) {
        $matches = @($dependencies | Where-Object {
            $_.GetAttribute('id') -ceq $entry.Key
        })
        if ($matches.Count -ne 1) {
            throw "Expected exactly one '$($entry.Key)' dependency, found $($matches.Count)."
        }

        if ($matches[0].GetAttribute('id') -cne $entry.Key) {
            throw "Dependency '$($entry.Key)' does not use canonical package-ID casing."
        }

        $current = $matches[0].GetAttribute('version')
        $exact = "[$($entry.Value)]"
        if ($current -cne $entry.Value -and $current -cne $exact) {
            throw "Dependency '$($entry.Key)' changed from expected version '$($entry.Value)'."
        }
        $matches[0].SetAttribute('version', $exact)
    }

    $ids = @($document.SelectNodes('/n:package/n:metadata/n:id', $manager))
    if ($ids.Count -ne 1 -or
        $ids[0].InnerText -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$') {
        throw "The nuspec package identity is not unique and canonical."
    }
    return [PSCustomObject]@{
        Bytes = $utf8.GetBytes($document.OuterXml)
        PackageId = $ids[0].InnerText
    }
}

$exactDependencies = Get-ExactDependencyMap $ExactDependency

$resolved = (Resolve-Path -LiteralPath $Path).Path
if (-not $resolved.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Only .nupkg files can be normalized."
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$entries = [Collections.Generic.List[object]]::new()
$source = [IO.Compression.ZipFile]::OpenRead($resolved)
try {
    if ($source.Entries.Count -le 0 -or $source.Entries.Count -gt 4096) {
        throw "The NuGet package entry count is outside the supported bounds."
    }
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [long] $totalLength = 0
    [long] $totalCompressedLength = 0
    foreach ($entry in $source.Entries) {
        $name = $entry.FullName
        if ([string]::IsNullOrWhiteSpace($name) -or
            $name.Length -gt 512 -or
            $name.EndsWith('/', [StringComparison]::Ordinal) -or
            $name.StartsWith('/', [StringComparison]::Ordinal) -or
            $name.IndexOf('\') -ge 0 -or
            $name -match '[:*?"''<>&|]' -or
            @($name.ToCharArray() | Where-Object {
                [int] $_ -lt 0x21 -or [int] $_ -gt 0x7e
            }).Count -gt 0 -or
            @($name.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0 -or
            -not $names.Add($name)) {
            throw "The NuGet package contains an ambiguous or non-canonical entry name."
        }
        if ($entry.Length -lt 0 -or $entry.Length -gt 32MB -or
            $entry.CompressedLength -lt 0 -or $entry.CompressedLength -gt 32MB) {
            throw "The NuGet package entry is outside the supported bounds."
        }
        $totalLength += $entry.Length
        $totalCompressedLength += $entry.CompressedLength
        if ($totalLength -gt 128MB -or $totalCompressedLength -gt 64MB) {
            throw "The NuGet package aggregate size is outside the supported bounds."
        }
        $stream = $entry.Open()
        try {
            $memory = [IO.MemoryStream]::new()
            try {
                $stream.CopyTo($memory)
                if ($memory.Length -ne $entry.Length) {
                    throw "The NuGet package entry changed while it was read."
                }
                $bytes = $memory.ToArray()
            }
            finally {
                $memory.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }

        $entries.Add([PSCustomObject]@{
            Name = $entry.FullName
            Bytes = $bytes
            ExternalAttributes = $entry.ExternalAttributes
        })
    }
}
finally {
    $source.Dispose()
}

$manifests = @($entries |
    Where-Object { $_.Name.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) })
$cores = @($entries |
    Where-Object { $_.Name.EndsWith('.psmdcp', [StringComparison]::OrdinalIgnoreCase) })
$relationshipParts = @($entries |
    Where-Object { $_.Name -eq '_rels/.rels' })
if ($manifests.Count -ne 1 -or $cores.Count -ne 1 -or $relationshipParts.Count -ne 1) {
    throw "The NuGet package does not contain one manifest, core-properties part and root relationship part."
}

$manifest = $manifests[0]
$core = $cores[0]
$relationships = $relationshipParts[0]
$rewrittenManifest = Set-ExactDependencies `
    -ManifestBytes $manifest.Bytes `
    -Expected $exactDependencies `
    -Prefix $ExactDependencyPrefix
$expectedManifestName = "$($rewrittenManifest.PackageId).nuspec"
if ($manifest.Name -cne $expectedManifestName) {
    throw "The nuspec must be the canonical root '$expectedManifestName' part."
}
$manifest.Bytes = $rewrittenManifest.Bytes
$core.Name = 'package/services/metadata/core-properties/core.psmdcp'
$relationshipXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$($manifest.Name)" Id="RManifest" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/$($core.Name)" Id="RCoreProperties" />
</Relationships>
"@
$relationships.Bytes = [Text.UTF8Encoding]::new($false).GetBytes($relationshipXml)

$temporary = "$resolved.deterministic.$([Guid]::NewGuid().ToString('N')).tmp"

try {
    $file = [IO.File]::Open(
        $temporary,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $file,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            $ordered = $entries.ToArray()
            $comparer = [Collections.Generic.Comparer[object]]::Create(
                [Comparison[object]] {
                    param($left, $right)
                    return [StringComparer]::Ordinal.Compare($left.Name, $right.Name)
                })
            [Array]::Sort($ordered, $comparer)
            foreach ($item in $ordered) {
                $entry = $archive.CreateEntry(
                    $item.Name,
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(
                    1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $entry.ExternalAttributes = $item.ExternalAttributes
                $stream = $entry.Open()
                try { $stream.Write($item.Bytes, 0, $item.Bytes.Length) }
                finally { $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $file.Dispose() }
    Move-Item -LiteralPath $temporary -Destination $resolved -Force
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        [IO.File]::Delete($temporary)
    }
}
