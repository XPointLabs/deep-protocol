param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolved = (Resolve-Path -LiteralPath $Path).Path
if (-not $resolved.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Only .nupkg files can be normalized."
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$entries = [Collections.Generic.List[object]]::new()
$source = [IO.Compression.ZipFile]::OpenRead($resolved)
try {
    foreach ($entry in $source.Entries) {
        $stream = $entry.Open()
        try {
            $memory = [IO.MemoryStream]::new()
            try {
                $stream.CopyTo($memory)
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
$core.Name = 'package/services/metadata/core-properties/core.psmdcp'
$relationshipXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$($manifest.Name)" Id="RManifest" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/$($core.Name)" Id="RCoreProperties" />
</Relationships>
"@
$relationships.Bytes = [Text.UTF8Encoding]::new($false).GetBytes($relationshipXml)

$temporary = "$resolved.deterministic.tmp"
if (Test-Path -LiteralPath $temporary) {
    Remove-Item -LiteralPath $temporary -Force
}

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
        foreach ($item in $entries | Sort-Object Name) {
            $entry = $archive.CreateEntry(
                $item.Name,
                [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(
                1980,
                1,
                1,
                0,
                0,
                0,
                [TimeSpan]::Zero)
            $entry.ExternalAttributes = $item.ExternalAttributes
            $stream = $entry.Open()
            try {
                $stream.Write($item.Bytes, 0, $item.Bytes.Length)
            }
            finally {
                $stream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}
finally {
    $file.Dispose()
}

Move-Item -LiteralPath $temporary -Destination $resolved -Force
