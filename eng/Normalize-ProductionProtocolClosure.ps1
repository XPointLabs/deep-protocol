[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InputDirectory,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [Parameter(Mandatory = $true)] [string] $ProductionVersion,
    [Parameter(Mandatory = $true)] [string] $ProfileCarrierVersion,
    [Parameter(Mandatory = $true)] [string] $SourceCommit,
    [string] $RepositoryUrl = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ($SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'SourceCommit is not canonical.' }
$numeric = '(?:0|[1-9][0-9]*)'
$prerelease = '(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
$versionPattern = "^$numeric\.$numeric\.$numeric(?:-$prerelease(?:\.$prerelease)*)?`$"
if ($ProductionVersion.Length -gt 128 -or $ProfileCarrierVersion.Length -gt 128 -or
    $ProductionVersion -notmatch $versionPattern -or
    $ProfileCarrierVersion -notmatch $versionPattern) {
    throw 'Package versions are not canonical path-safe SemVer values.'
}
$inputRoot = (Resolve-Path -LiteralPath $InputDirectory).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must not exist.' }
$parent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'OutputDirectory parent is missing.'
}
if (((Get-Item -LiteralPath $parent -Force).Attributes -band
    [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'OutputDirectory parent may not be a reparse point.'
}
$temporary = Join-Path $parent ".deep-protocol-closure-$([Guid]::NewGuid().ToString('N'))"
$normalizer = Join-Path $PSScriptRoot 'Normalize-NuGetPackage.ps1'
$expected = [ordered]@{
    'Deep.Protocol' = @()
    'Deep.Protocol.MembershipRoutes' = @("Deep.Protocol=$ProductionVersion")
    'Deep.Protocol.ProfileCarrier' = @("Deep.Protocol=$ProductionVersion")
}

function Read-Identity {
    param([string] $Path)
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -le 0 -or $archive.Entries.Count -gt 4096) {
            throw 'Package entry count is outside the supported bounds.'
        }
        $manifests = @($archive.Entries | Where-Object {
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($manifests.Count -ne 1 -or $manifests[0].Length -gt 1MB) {
            throw 'Package nuspec is missing, duplicated, or oversized.'
        }
        $reader = [IO.StreamReader]::new(
            $manifests[0].Open(), [Text.UTF8Encoding]::new($false, $true))
        try { $text = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) { $text = $text.Substring(1) }
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $xmlReader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
        try { $document = [Xml.XmlDocument]::new(); $document.XmlResolver = $null; $document.Load($xmlReader) }
        finally { $xmlReader.Dispose() }
        $ns = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $ns.AddNamespace('n', $document.DocumentElement.NamespaceURI)
        $id = @($document.SelectNodes('/n:package/n:metadata/n:id', $ns))
        $version = @($document.SelectNodes('/n:package/n:metadata/n:version', $ns))
        $repository = @($document.SelectNodes('/n:package/n:metadata/n:repository', $ns))
        if ($id.Count -ne 1 -or $version.Count -ne 1 -or $repository.Count -ne 1) {
            throw 'Package identity metadata is not unique.'
        }
        return [PSCustomObject]@{
            Id = $id[0].InnerText
            Version = $version[0].InnerText
            Commit = $repository[0].GetAttribute('commit')
            Url = $repository[0].GetAttribute('url')
            Path = $Path
        }
    }
    finally { $archive.Dispose() }
}

$files = @(Get-ChildItem -LiteralPath $inputRoot -Recurse -File -Filter '*.nupkg')
$debris = @(Get-ChildItem -LiteralPath $inputRoot -Recurse -File |
    Where-Object { $_.Extension -cne '.nupkg' })
$nested = @($files | Where-Object { $_.Directory.FullName -ine $inputRoot })
if ($files.Count -ne $expected.Count -or $debris.Count -gt 0 -or $nested.Count -gt 0) {
    throw "Input closure must contain exactly three root nupkg files and no debris (packages=$($files.Count), debris=$($debris.Count), nested=$($nested.Count))."
}

$sourceHandles = [Collections.Generic.List[IO.FileStream]]::new()
try {
    foreach ($file in $files) {
        $sourceHandles.Add([IO.File]::Open(
            $file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    }
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    if ($env:OS -eq 'Windows_NT') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
        [IO.Directory]::SetAccessControl($temporary, $security)
    }
    if (((Get-Item -LiteralPath $temporary -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Private closure work directory became a reparse point.'
    }
    $captured = Join-Path $temporary 'captured'
    $normalized = Join-Path $temporary 'normalized'
    New-Item -ItemType Directory -Path $captured, $normalized | Out-Null
    if ($env:OS -eq 'Windows_NT') {
        $sddl = $security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access)
        foreach ($child in @($captured, $normalized)) {
            $childSecurity = [Security.AccessControl.DirectorySecurity]::new()
            $childSecurity.SetSecurityDescriptorSddlForm(
                $sddl, [Security.AccessControl.AccessControlSections]::Access)
            [IO.Directory]::SetAccessControl($child, $childSecurity)
        }
        foreach ($privateDirectory in @($temporary, $captured, $normalized)) {
            if (-not (Get-Acl -LiteralPath $privateDirectory).AreAccessRulesProtected) {
                throw "Closure work directory ACL is not protected: $privateDirectory"
            }
        }
    }
    $index = 0
    for ($index = 0; $index -lt $files.Count; $index++) {
        $file = $files[$index]
        $sourceStream = $sourceHandles[$index]
        if ($sourceStream.Length -le 0 -or $sourceStream.Length -gt 64MB) {
            throw 'Input package size is outside the supported bounds.'
        }
        $capturedPath = Join-Path $captured "$index.nupkg"
        $sourceStream.Position = 0
        try {
            $destinationStream = [IO.File]::Open(
                $capturedPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                $sourceStream.CopyTo($destinationStream)
                if ($sourceStream.Position -ne $sourceStream.Length -or
                    $destinationStream.Length -ne $sourceStream.Length) {
                    throw 'Input package capture was incomplete.'
                }
                $destinationStream.Flush($true)
            }
            finally { $destinationStream.Dispose() }
        }
        finally { }
    }

    $identities = @(Get-ChildItem -LiteralPath $captured -File -Filter '*.nupkg' |
        ForEach-Object { Read-Identity $_.FullName })
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($identity in $identities) {
        $canonicalId = @($expected.Keys | Where-Object { $_ -ceq $identity.Id })
        if (-not $ids.Add($identity.Id) -or $canonicalId.Count -ne 1 -or
            $identity.Commit -cne $SourceCommit -or $identity.Url -cne $RepositoryUrl) {
            throw "Package identity or provenance is outside the exact closure."
        }
        $wantedVersion = if ($identity.Id -ceq 'Deep.Protocol.ProfileCarrier') { $ProfileCarrierVersion } else { $ProductionVersion }
        if ($identity.Version -cne $wantedVersion) { throw "Package version is outside the exact closure." }
    }
    if ($ids.Count -ne $expected.Count) { throw 'Package closure identities are incomplete.' }

    foreach ($identity in $identities) {
        $destination = Join-Path $normalized "$($identity.Id).$($identity.Version).nupkg"
        [IO.File]::Copy($identity.Path, $destination, $false)
        & $normalizer -Path $destination -ExactDependency $expected[$identity.Id] `
            -ExactDependencyPrefix 'Deep.Protocol'
    }

    $normalizedFiles = @(Get-ChildItem -LiteralPath $normalized -File -Filter '*.nupkg')
    $firstHashes = @{}
    foreach ($file in $normalizedFiles) {
        $firstHashes[$file.Name] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
    }
    $verified = @($normalizedFiles | ForEach-Object { Read-Identity $_.FullName })
    if ($verified.Count -ne $expected.Count) { throw 'Normalized closure is incomplete.' }
    $verifiedIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($identity in $verified) {
        $wantedVersion = if ($identity.Id -ceq 'Deep.Protocol.ProfileCarrier') {
            $ProfileCarrierVersion
        } else { $ProductionVersion }
        if (-not $verifiedIds.Add($identity.Id) -or
            @($expected.Keys | Where-Object { $_ -ceq $identity.Id }).Count -ne 1 -or
            $identity.Version -cne $wantedVersion -or
            $identity.Commit -cne $SourceCommit -or $identity.Url -cne $RepositoryUrl) {
            throw 'Normalized closure identity or provenance changed.'
        }
    }
    if ($verifiedIds.Count -ne $expected.Count) {
        throw 'Normalized closure identity set is incomplete.'
    }
    foreach ($file in $normalizedFiles) {
        if ($firstHashes[$file.Name] -cne
            (Get-FileHash $file.FullName -Algorithm SHA256).Hash) {
            throw 'Normalized closure changed during post-validation.'
        }
    }
    [IO.Directory]::Move($normalized, $output)
}
finally {
    foreach ($handle in $sourceHandles) { $handle.Dispose() }
    if (Test-Path -LiteralPath $temporary) {
        Get-ChildItem -LiteralPath $temporary -Recurse -Force -File | ForEach-Object { $_.IsReadOnly = $false }
        [IO.Directory]::Delete($temporary, $true)
    }
}

Write-Output "PASS exact three-package production protocol closure $ProductionVersion"
