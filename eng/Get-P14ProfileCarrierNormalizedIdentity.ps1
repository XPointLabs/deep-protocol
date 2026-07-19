[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$ExpectedRepositoryCommit
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-Bytes {
    param([System.IO.Compression.ZipArchiveEntry]$Entry)
    $stream = $Entry.Open()
    try {
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            return $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256 {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-HexString ($sha256.ComputeHash($Bytes))
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return ([BitConverter]::ToString($Bytes) -replace "-", "").ToLowerInvariant()
}

$PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
$zip = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
try {
    $names = @($zip.Entries | ForEach-Object { $_.FullName })
    $nuspecEntries = @($zip.Entries | Where-Object { $_.FullName -like "*.nuspec" })
    $coreEntries = @($zip.Entries | Where-Object {
        $_.FullName -like "package/services/metadata/core-properties/*.psmdcp"
    })
    if ($nuspecEntries.Count -ne 1 -or $coreEntries.Count -ne 1) {
        throw "The package must contain exactly one nuspec and one random OPC core entry."
    }

    $semanticNames = @(
        $nuspecEntries[0].FullName,
        "README.md",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.dll"
    )
    $randomOpcNames = @(
        "_rels/.rels",
        "[Content_Types].xml",
        $coreEntries[0].FullName
    )
    $allowedNames = @($semanticNames + $randomOpcNames)
    $difference = Compare-Object `
        ($allowedNames | Sort-Object) `
        ($names | Sort-Object)
    if ($null -ne $difference) {
        throw "The package entry set differs from the semantic/OPC allowlist."
    }

    $nuspecBytes = Get-Bytes $nuspecEntries[0]
    $nuspecText = [Text.Encoding]::UTF8.GetString($nuspecBytes).TrimStart(
        [char]0xfeff)
    [xml]$nuspec = $nuspecText
    $metadata = $nuspec.package.metadata
    $repository = $metadata.repository
    if ($repository.type -ne "git" -or
        $repository.url -ne "https://github.com/XPointLabs/deep-protocol.git" -or
        $repository.commit -ne $ExpectedRepositoryCommit) {
        throw "The nuspec repository identity is not the verified exact commit."
    }

    # XmlDocument removes insignificant formatting differences while retaining
    # every semantic element and attribute, including target frameworks and
    # dependency metadata.
    $normalizedNuspecBytes = [Text.Encoding]::UTF8.GetBytes(
        $nuspec.OuterXml)

    $entries = @()
    foreach ($name in @(
        "README.md",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.dll"
    )) {
        $entry = $zip.GetEntry($name)
        $bytes = Get-Bytes $entry
        $entries += [ordered]@{
            path = $name
            length = $bytes.Length
            sha256 = Get-Sha256 $bytes
        }
    }
    $entries += [ordered]@{
        path = "$($nuspecEntries[0].FullName)#normalized"
        length = $normalizedNuspecBytes.Length
        sha256 = Get-Sha256 $normalizedNuspecBytes
    }
    $entries = @($entries | Sort-Object { $_.path })

    $manifest = [ordered]@{
        schema = "deep-p14-profile-carrier-normalized-package-v1"
        packageId = [string]$metadata.id
        version = [string]$metadata.version
        repositoryCommit = [string]$repository.commit
        entries = $entries
    }
    $json = $manifest | ConvertTo-Json -Depth 8 -Compress
    $identityHash = Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($json))
    [PSCustomObject]@{
        Schema = $manifest.schema
        Version = $manifest.version
        RepositoryCommit = $manifest.repositoryCommit
        Hash = $identityHash
        Manifest = $json
        DllHash = ($entries |
            Where-Object { $_.path -eq "lib/net10.0/Deep.Protocol.ProfileCarrier.dll" }
        ).sha256
    }
}
finally {
    $zip.Dispose()
}
