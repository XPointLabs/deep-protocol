[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "deep-p14-opc-identity-tests")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$commit = "0123456789abcdef0123456789abcdef01234567"
$version = "0.1.0-p14.0123456"
$identityScript = Join-Path $RepositoryRoot `
    "eng\Get-P14ProfileCarrierNormalizedIdentity.ps1"

function Add-TextEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$Name,
        [string]$Value
    )
    $entry = $Archive.CreateEntry($Name)
    $stream = $entry.Open()
    try {
        $writer = [System.IO.StreamWriter]::new(
            $stream,
            [Text.UTF8Encoding]::new($false),
            1024,
            $true)
        try {
            $writer.Write($Value)
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function New-TestPackage {
    param(
        [string]$Path,
        [string]$RelationshipSuffix,
        [string]$CoreSuffix,
        [string]$Created,
        [string]$ManifestTarget = "/Deep.Protocol.ProfileCarrier.nuspec",
        [string]$ManifestType =
            "http://schemas.microsoft.com/packaging/2010/07/manifest",
        [string]$DllContentType = "application/octet",
        [string]$Creator = "Deep.Protocol.ProfileCarrier"
    )

    $coreName = "package/services/metadata/core-properties/$CoreSuffix.psmdcp"
    $zip = [System.IO.Compression.ZipFile]::Open(
        $Path,
        [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Add-TextEntry $zip "_rels/.rels" @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="$ManifestType" Target="$ManifestTarget" Id="RManifest$RelationshipSuffix" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/$coreName" Id="RCore$RelationshipSuffix" />
</Relationships>
"@
        Add-TextEntry $zip "Deep.Protocol.ProfileCarrier.nuspec" @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Deep.Protocol.ProfileCarrier</id>
    <version>$version</version>
    <authors>Deep.Protocol.ProfileCarrier</authors>
    <readme>README.md</readme>
    <description>Unsigned exact DPF1 carrier contract over the pinned P04 trust authority.</description>
    <repository type="git" url="https://github.com/XPointLabs/deep-protocol.git" commit="$commit" />
    <dependencies>
      <group targetFramework="net10.0">
        <dependency id="Deep.Protocol" version="[0.3.0-p04.b887fa0]" exclude="Build,Analyzers" />
      </group>
    </dependencies>
  </metadata>
</package>
"@
        Add-TextEntry $zip "README.md" "semantic readme"
        Add-TextEntry $zip `
            "lib/net10.0/Deep.Protocol.ProfileCarrier.dll" `
            "semantic assembly"
        Add-TextEntry $zip `
            "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb" `
            "semantic portable symbols"
        Add-TextEntry $zip "[Content_Types].xml" @"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml" />
  <Default Extension="dll" ContentType="$DllContentType" />
  <Default Extension="md" ContentType="application/octet" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="pdb" ContentType="application/octet" />
</Types>
"@
        Add-TextEntry $zip $coreName @"
<?xml version="1.0" encoding="utf-8"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>$Creator</dc:creator>
  <dc:description>Unsigned exact DPF1 carrier contract over the pinned P04 trust authority.</dc:description>
  <dc:identifier>Deep.Protocol.ProfileCarrier</dc:identifier>
  <version>$version</version>
  <keywords></keywords>
  <lastModifiedBy>NuGet.Packaging, Version=7.6.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35;.NET 8.0</lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">$Created</dcterms:created>
</coreProperties>
"@
    }
    finally {
        $zip.Dispose()
    }
}

function Get-Identity {
    param([string]$Path)
    return & $identityScript `
        -PackagePath $Path `
        -ExpectedRepositoryCommit $commit
}

function Assert-Rejected {
    param([string]$Path, [string]$Label)
    try {
        $null = Get-Identity $Path
    }
    catch {
        return
    }
    throw "$Label was accepted by the normalized OPC identity verifier."
}

$root = Join-Path ([System.IO.Path]::GetFullPath($WorkRoot)) `
    "run-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root -Force | Out-Null

$first = Join-Path $root "first.nupkg"
$second = Join-Path $root "second.nupkg"
$third = Join-Path $root "third.nupkg"
$fourth = Join-Path $root "fourth.nupkg"
New-TestPackage `
    -Path $first `
    -RelationshipSuffix "111111" `
    -CoreSuffix "11111111111111111111111111111111" `
    -Created "2026-07-19T20:00:00Z"
New-TestPackage `
    -Path $second `
    -RelationshipSuffix "999999" `
    -CoreSuffix "99999999999999999999999999999999" `
    -Created "2026-07-20T01:59:59.9Z"
New-TestPackage `
    -Path $third `
    -RelationshipSuffix "777777" `
    -CoreSuffix "77777777777777777777777777777777" `
    -Created "2026-07-20T01:59:59.999Z"
New-TestPackage `
    -Path $fourth `
    -RelationshipSuffix "888888" `
    -CoreSuffix "88888888888888888888888888888888" `
    -Created "2026-07-20T01:59:59.9999999Z"
$firstIdentity = Get-Identity $first
$secondIdentity = Get-Identity $second
$thirdIdentity = Get-Identity $third
$fourthIdentity = Get-Identity $fourth
if ($firstIdentity.Hash -ne $secondIdentity.Hash -or
    $firstIdentity.Hash -ne $thirdIdentity.Hash -or
    $firstIdentity.Hash -ne $fourthIdentity.Hash -or
    $firstIdentity.Manifest -ne $secondIdentity.Manifest -or
    $firstIdentity.Manifest -ne $thirdIdentity.Manifest -or
    $firstIdentity.Manifest -ne $fourthIdentity.Manifest) {
    throw "Proven OPC nondeterminism changed the normalized package identity."
}

$wrongTarget = Join-Path $root "wrong-target.nupkg"
New-TestPackage `
    -Path $wrongTarget `
    -RelationshipSuffix "222222" `
    -CoreSuffix "22222222222222222222222222222222" `
    -Created "2026-07-19T20:00:00Z" `
    -ManifestTarget "/README.md"
Assert-Rejected $wrongTarget "Relationship target drift"

$wrongType = Join-Path $root "wrong-type.nupkg"
New-TestPackage `
    -Path $wrongType `
    -RelationshipSuffix "333333" `
    -CoreSuffix "33333333333333333333333333333333" `
    -Created "2026-07-19T20:00:00Z" `
    -ManifestType "urn:deep:benign-manifest-drift"
Assert-Rejected $wrongType "Relationship type drift"

$wrongContentType = Join-Path $root "wrong-content-type.nupkg"
New-TestPackage `
    -Path $wrongContentType `
    -RelationshipSuffix "444444" `
    -CoreSuffix "44444444444444444444444444444444" `
    -Created "2026-07-19T20:00:00Z" `
    -DllContentType "application/x-benign-drift"
Assert-Rejected $wrongContentType "Content-type drift"

$wrongCore = Join-Path $root "wrong-core.nupkg"
New-TestPackage `
    -Path $wrongCore `
    -RelationshipSuffix "555555" `
    -CoreSuffix "55555555555555555555555555555555" `
    -Created "2026-07-19T20:00:00Z" `
    -Creator "Benign creator drift"
Assert-Rejected $wrongCore "Core-property semantic drift"

$invalidTimestamps = @(
    @{
        Name = "text-date"
        RelationshipSuffix = "600001"
        CoreSuffix = "60000160000160000160000160000160"
        Value = "July 20, 2026Z"
        Label = "Text creation timestamp"
    },
    @{
        Name = "offset"
        RelationshipSuffix = "600002"
        CoreSuffix = "60000260000260000260000260000260"
        Value = "2026-07-20T01:59:59+00:00"
        Label = "Offset creation timestamp"
    },
    @{
        Name = "lowercase-z"
        RelationshipSuffix = "600003"
        CoreSuffix = "60000360000360000360000360000360"
        Value = "2026-07-20T01:59:59z"
        Label = "Lowercase-Z creation timestamp"
    },
    @{
        Name = "space"
        RelationshipSuffix = "600004"
        CoreSuffix = "60000460000460000460000460000460"
        Value = "2026-07-20 01:59:59Z"
        Label = "Space-separated creation timestamp"
    },
    @{
        Name = "eight-fractions"
        RelationshipSuffix = "600005"
        CoreSuffix = "60000560000560000560000560000560"
        Value = "2026-07-20T01:59:59.12345678Z"
        Label = "Over-precise creation timestamp"
    },
    @{
        Name = "invalid-calendar"
        RelationshipSuffix = "600006"
        CoreSuffix = "60000660000660000660000660000660"
        Value = "2026-02-30T01:59:59Z"
        Label = "Invalid-calendar creation timestamp"
    },
    @{
        Name = "invalid-time"
        RelationshipSuffix = "600007"
        CoreSuffix = "60000760000760000760000760000760"
        Value = "2026-07-20T24:00:00Z"
        Label = "Invalid-time creation timestamp"
    }
)

foreach ($invalidTimestamp in $invalidTimestamps) {
    $path = Join-Path $root "$($invalidTimestamp.Name).nupkg"
    New-TestPackage `
        -Path $path `
        -RelationshipSuffix $invalidTimestamp.RelationshipSuffix `
        -CoreSuffix $invalidTimestamp.CoreSuffix `
        -Created $invalidTimestamp.Value
    Assert-Rejected $path $invalidTimestamp.Label
}

Write-Output "PASS normalized-opc-positive-randomization=4"
Write-Output "PASS normalized-opc-negative-drift=11"
