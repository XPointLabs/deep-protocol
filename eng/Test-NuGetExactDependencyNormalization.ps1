[CmdletBinding()]
param([string] $RepositoryRoot = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$normalizer = Join-Path $RepositoryRoot 'eng/Normalize-ProductionProtocolClosure.ps1'
$fixture = Join-Path $RepositoryRoot 'vendor/p10j-package-closure/packages'
$root = Join-Path ([IO.Path]::GetTempPath()) "deep-exact-three-$([Guid]::NewGuid().ToString('N'))"
$productionVersion = '0.3.0-p10j.2886880'
$carrierVersion = '0.2.0-p10j.2886880'
$commit = '2886880d4c2060cd819765c53c77a02e1c475ea8'

function Rewrite-Nuspec {
    param([string] $Package, [switch] $RemoveLegacyDependencies)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($Package, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = @($zip.Entries | Where-Object { $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase) })
        if ($entry.Count -ne 1) { throw 'Fixture nuspec is not unique.' }
        $name = $entry[0].FullName
        $reader = [IO.StreamReader]::new($entry[0].Open(), [Text.UTF8Encoding]::new($false, $true))
        try { [xml]$document = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $namespace = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespace.AddNamespace('n', $document.DocumentElement.NamespaceURI)
        if ($RemoveLegacyDependencies) {
            @($document.SelectNodes('//n:dependency[starts-with(@id,"Deep.Protocol")]', $namespace)) |
                ForEach-Object { [void]$_.ParentNode.RemoveChild($_) }
        }
        $repository = $document.SelectSingleNode('/n:package/n:metadata/n:repository', $namespace)
        $repository.SetAttribute('url', 'https://github.com/XPointLabs/deep-protocol.git')
        $entry[0].Delete()
        $replacement = $zip.CreateEntry($name)
        $writer = [IO.StreamWriter]::new($replacement.Open(), [Text.UTF8Encoding]::new($false))
        try { $document.Save($writer) } finally { $writer.Dispose() }
    }
    finally { $zip.Dispose() }
}

function Read-InternalDependencies {
    param([string] $Package)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Package)
    try {
        $entry = @($zip.Entries | Where-Object { $_.FullName -like '*.nuspec' })
        $reader = [IO.StreamReader]::new($entry[0].Open())
        try { [xml]$document = $reader.ReadToEnd() } finally { $reader.Dispose() }
        return @($document.package.metadata.dependencies.group.dependency |
            Where-Object { ([string]$_.id).StartsWith('Deep.Protocol', [StringComparison]::Ordinal) } |
            ForEach-Object { "$($_.id)=$($_.version)" })
    }
    finally { $zip.Dispose() }
}

function Assert-Throws([scriptblock]$Action, [string]$Name) {
    try { & $Action } catch { return }
    throw "Expected '$Name' to fail closed."
}

[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $input = Join-Path $root 'input'
    [IO.Directory]::CreateDirectory($input) | Out-Null
    foreach ($name in @(
        "Deep.Protocol.$productionVersion.nupkg",
        "Deep.Protocol.MembershipRoutes.$productionVersion.nupkg",
        "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg")) {
        Copy-Item -LiteralPath (Join-Path $fixture $name) -Destination (Join-Path $input $name)
    }
    Get-ChildItem -LiteralPath $input -File -Filter '*.nupkg' | ForEach-Object {
        Rewrite-Nuspec $_.FullName -RemoveLegacyDependencies:($_.Name -ceq "Deep.Protocol.$productionVersion.nupkg")
    }

    $output = Join-Path $root 'output'
    & $normalizer -InputDirectory $input -OutputDirectory $output `
        -ProductionVersion $productionVersion -ProfileCarrierVersion $carrierVersion `
        -SourceCommit $commit -RepositoryUrl 'https://github.com/XPointLabs/deep-protocol.git'
    $packages = @(Get-ChildItem -LiteralPath $output -File -Filter '*.nupkg')
    if ($packages.Count -ne 3) { throw 'Normalizer output is not exact-three.' }
    if (@(Read-InternalDependencies (Join-Path $output "Deep.Protocol.$productionVersion.nupkg")).Count -ne 0) {
        throw 'Deep.Protocol retained an internal legacy dependency.'
    }
    if ((Read-InternalDependencies (Join-Path $output "Deep.Protocol.MembershipRoutes.$productionVersion.nupkg")) -cne
        "Deep.Protocol=[$productionVersion]") { throw 'MembershipRoutes dependency is not exact.' }
    if ((Read-InternalDependencies (Join-Path $output "Deep.Protocol.ProfileCarrier.$carrierVersion.nupkg")) -cne
        "Deep.Protocol=[$productionVersion]") { throw 'ProfileCarrier dependency is not exact.' }

    Copy-Item -LiteralPath (Join-Path $fixture "Deep.Protocol.Abstractions.$productionVersion.nupkg") `
        -Destination $input
    Assert-Throws {
        & $normalizer -InputDirectory $input -OutputDirectory (Join-Path $root 'extra-output') `
            -ProductionVersion $productionVersion -ProfileCarrierVersion $carrierVersion `
            -SourceCommit $commit -RepositoryUrl 'https://github.com/XPointLabs/deep-protocol.git'
    } 'legacy fourth package'
    Remove-Item -LiteralPath (Join-Path $input "Deep.Protocol.Abstractions.$productionVersion.nupkg")

    Assert-Throws {
        & $normalizer -InputDirectory $input -OutputDirectory (Join-Path $root 'bad-version') `
            -ProductionVersion '..\escape' -ProfileCarrierVersion $carrierVersion -SourceCommit $commit `
            -RepositoryUrl 'https://github.com/XPointLabs/deep-protocol.git'
    } 'unsafe version'
    Write-Output 'PASS exact-three NuGet closure normalization contract'
}
finally {
    if (Test-Path -LiteralPath $root) { [IO.Directory]::Delete($root, $true) }
}
