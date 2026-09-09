[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$NdkRoot = (Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk\28.2.13676358'),
    [string]$AdbPath = '',
    [string]$DeviceSerial = '',
    [switch]$Rebuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$toolchain = '1.89.0-x86_64-pc-windows-msvc'
$expectedCargoLockSha256 = '88e4f11da6f9df9f35b2d79ea00e709eeb3e61e93118b314941e4c8205c4f466'
$expectedToolchainFileSha256 = '6d3feafc5883eb6fbf830bbc29887a7b7aedc568dd7c8a853721f3bbd2472211'
$expectedLibcruxCrateSha256 = '1d8160f7d64fd2716b4fd05cc886a042f8dcda18d9206c0d506e2c67bdf97daa'
$expectedLibcruxProvenanceSha256 = '0888551da7bbdd38f7f389a810294042b26edc886f5887f9cbf4a996db77be6c'
$expectedWindowsSbomSha256 = '7efb0a6d356f252b87ba8b4d3044ab818abf5de54254c856262172e65d9b1ceb'
$expectedAndroidSbomSha256 = '27e882cb488d0d48e677c7f14081db4dc6b839a7b5a19ecaa624d116142189bd'
$expectedWindowsArtifactSha256 = '41ba8b15429bfc55b6a66cdadbb1ad3372dfc98a9f2bd1bce75a86d54426cd25'
$expectedAndroidArtifactSha256 = 'fa287d90ffff2c6e5b199c7f8ec487e16d989f75e39c2620b07c26e1dccbdf0d'

$expectedExports = @(
    'deep_mlkem_braid_v1_ciphertext1_size',
    'deep_mlkem_braid_v1_ciphertext2_size',
    'deep_mlkem_braid_v1_decapsulate',
    'deep_mlkem_braid_v1_decapsulation_key_size',
    'deep_mlkem_braid_v1_encaps1_from_random',
    'deep_mlkem_braid_v1_encaps1_generate',
    'deep_mlkem_braid_v1_encaps2',
    'deep_mlkem_braid_v1_encapsulation_key_hash_size',
    'deep_mlkem_braid_v1_encapsulation_key_seed_size',
    'deep_mlkem_braid_v1_encapsulation_key_vector_size',
    'deep_mlkem_braid_v1_encapsulation_random_size',
    'deep_mlkem_braid_v1_keygen_random_size',
    'deep_mlkem_braid_v1_keypair_from_random',
    'deep_mlkem_braid_v1_keypair_generate',
    'deep_mlkem_braid_v1_shared_secret_size',
    'deep_mlkem_braid_v1_state_free',
    'deep_mlkem_braid_v1_zero'
)

$expectedInputs = @(
    [ordered]@{ path = 'native/Deep.MlKemBraid/.gitattributes'; size = 50L; sha256 = '6704b0c10dd088f684fdd3c9bd19bed733da59a5cc24ebcb0c8a89d3745a4681' },
    [ordered]@{ path = 'native/Deep.MlKemBraid/Cargo.toml'; size = 423L; sha256 = '66aac0d9a4ff56c1aa19d30b84b2c00e1ff1bc9909ee2aa31e88e22b958895f9' },
    [ordered]@{ path = 'native/Deep.MlKemBraid/rust-toolchain.toml'; size = 111L; sha256 = $expectedToolchainFileSha256 },
    [ordered]@{ path = 'native/Deep.MlKemBraid/src/lib.rs'; size = 34417L; sha256 = 'a1a852e6463cd784ea94f4b03bb24f8a83bbf92578f8f92b55485ee2a9cc1571' },
    [ordered]@{ path = 'native/Deep.MlKemBraid/include/deep_mlkem_braid_v1.h'; size = 3665L; sha256 = '06d0d457a29c23b33e5ed564314a4179b3aa5c24e8071b02c3ee008055a8a87b' },
    [ordered]@{ path = 'native/Deep.MlKemBraid/third-party/libcrux/provenance.json'; size = 1301L; sha256 = $expectedLibcruxProvenanceSha256 },
    [ordered]@{ path = 'native/Deep.MlKemBraid/third-party/libcrux/LICENSE-APACHE'; size = 10757L; sha256 = '89a704092ec99209cd19f1d60cd67a353e3ec069e7f19f17cd41fcac052811c4' },
    [ordered]@{ path = 'native/Deep.MlKemBraid/third-party/libcrux/LICENSE-MIT'; size = 1065L; sha256 = '182ab7e3c88dd73b9c264ae0d5ed27f73b2b28f8d187e4d42b0eed2b93bfb4c3' },
    [ordered]@{ path = 'eng/.gitattributes'; size = 268L; sha256 = 'e7754bf59833a7e100b6157f7c2ea99dfcb0a1f2f52512c07b7ed53f77e3302c' },
    [ordered]@{ path = 'eng/Build-DeepMlKemBraid.ps1'; size = 13970L; sha256 = '8b61b67575012c9f8407d64dd2a2cfe0bc4fea77bfd49e4d19aac3402f7c30c4' },
    [ordered]@{ path = 'eng/Deep.MlKemBraid.NativeProbe/deep_mlkem_braid_probe.c'; size = 4523L; sha256 = 'eba787e2432cc905172247fa27dfc2dc6d652042b6599c26d30721f5377668bb' },
    [ordered]@{ path = 'eng/Deep.MlKemBraid.AndroidProbe/deep_mlkem_braid_android_probe.c'; size = 9031L; sha256 = 'f6cdfa6022b6cb689cb89e5a015ea8f783edb180432912f593b69d5d7d84915c' }
)

function Require-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is absent: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-EvidencePath([string]$RelativePath) {
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.Contains('\\') -or
        $RelativePath -match '(^|/)\.\.(/|$)') {
        throw "Evidence path is not a canonical repository-relative path: $RelativePath"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $script:resolvedRepositoryRoot ($RelativePath.Replace('/', '\'))))
    $prefix = $script:resolvedRepositoryRoot.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Evidence path escapes the repository: $RelativePath"
    }
    return $candidate
}

function Get-LowerSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Equal([object]$Actual, [object]$Expected, [string]$Context) {
    if ($null -eq $Actual -or $null -eq $Expected) {
        if ($null -ne $Actual -or $null -ne $Expected) {
            throw "$Context differs."
        }
        return
    }
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Context differs. Expected '$Expected'; actual '$Actual'."
    }
}

function Assert-Sequence([object[]]$Actual, [object[]]$Expected, [string]$Context) {
    $actualValues = @($Actual)
    $expectedValues = @($Expected)
    if ($actualValues.Count -ne $expectedValues.Count) {
        throw "$Context count differs. Expected $($expectedValues.Count); actual $($actualValues.Count)."
    }
    for ($index = 0; $index -lt $expectedValues.Count; $index++) {
        if ([string]$actualValues[$index] -cne [string]$expectedValues[$index]) {
            throw "$Context differs at index $index. Expected '$($expectedValues[$index])'; actual '$($actualValues[$index])'."
        }
    }
}

function Assert-PropertySet([object]$Object, [string[]]$Expected, [string]$Context) {
    $actualNames = @($Object.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $expectedNames = @($Expected | Sort-Object -CaseSensitive)
    Assert-Sequence $actualNames $expectedNames "$Context properties"
}

function Assert-FileIdentity([string]$RelativePath, [long]$ExpectedSize, [string]$ExpectedSha256) {
    $path = Require-File (Resolve-EvidencePath $RelativePath)
    $actualSize = (Get-Item -LiteralPath $path).Length
    if ($actualSize -ne $ExpectedSize) {
        throw "File length drift for $RelativePath. Expected $ExpectedSize; actual $actualSize."
    }
    $actualSha256 = Get-LowerSha256 $path
    if ($actualSha256 -cne $ExpectedSha256) {
        throw "SHA-256 drift for $RelativePath. Expected $ExpectedSha256; actual $actualSha256."
    }
}

function Get-Target([object]$Manifest, [string]$Id) {
    $matches = @($Manifest.targets | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "Manifest must contain exactly one '$Id' target."
    }
    return $matches[0]
}

function Get-LockChecksum([string]$LockText, [string]$Name, [string]$Version) {
    $blocks = [regex]::Matches($LockText, '(?ms)^\[\[package\]\]\r?\n(?<body>.*?)(?=^\[\[package\]\]|\z)')
    $matches = @()
    foreach ($block in $blocks) {
        $body = $block.Groups['body'].Value
        $nameMatch = [regex]::Match($body, '(?m)^name = "(?<value>[^"]+)"\r?$')
        $versionMatch = [regex]::Match($body, '(?m)^version = "(?<value>[^"]+)"\r?$')
        if ($nameMatch.Success -and $versionMatch.Success -and
            $nameMatch.Groups['value'].Value -ceq $Name -and
            $versionMatch.Groups['value'].Value -ceq $Version) {
            $matches += $body
        }
    }
    if ($matches.Count -ne 1) {
        throw "Cargo.lock must contain exactly one $Name $Version package."
    }
    $checksumMatch = [regex]::Match($matches[0], '(?m)^checksum = "(?<value>[0-9a-f]{64})"\r?$')
    if (-not $checksumMatch.Success) {
        throw "Cargo.lock package $Name $Version has no canonical SHA-256 checksum."
    }
    return $checksumMatch.Groups['value'].Value
}

function Get-CargoMetadata([string]$Cargo, [string]$ManifestPath, [string]$Target) {
    $metadataText = (& $Cargo "+$toolchain" metadata --manifest-path $ManifestPath --locked --offline --format-version 1 --filter-platform $Target | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for $Target."
    }
    try {
        return $metadataText | ConvertFrom-Json
    } catch {
        throw "cargo metadata emitted invalid JSON for ${Target}: $($_.Exception.Message)"
    }
}

function Get-Purl([object]$Package) {
    return "pkg:cargo/$($Package.name)@$($Package.version)"
}

function Assert-CrateArchives([object[]]$MetadataSets, [string]$LockText, [string]$CacheRoot) {
    $packages = @($MetadataSets |
        ForEach-Object { $_.packages } |
        Where-Object { [string]$_.source -like 'registry+*' } |
        Sort-Object name, version -Unique)
    foreach ($package in $packages) {
        $name = [string]$package.name
        $version = [string]$package.version
        $expectedChecksum = Get-LockChecksum $LockText $name $version
        $archiveName = "$name-$version.crate"
        $archives = @(Get-ChildItem -LiteralPath $CacheRoot -Recurse -Filter $archiveName -File -ErrorAction SilentlyContinue)
        if ($archives.Count -lt 1) {
            throw "The locked Cargo archive is absent from the offline cache: $archiveName"
        }
        foreach ($archive in $archives) {
            Assert-Equal (Get-LowerSha256 $archive.FullName) $expectedChecksum "crate archive hash $($archive.FullName)"
        }
    }
}

function Assert-SbomClosure([object]$Sbom, [object]$Metadata, [string]$LockText, [string]$Target, [int]$ExpectedPackageCount) {
    Assert-Equal $Sbom.'$schema' 'http://cyclonedx.org/schema/bom-1.5.schema.json' "$Target SBOM schema"
    Assert-Equal $Sbom.bomFormat 'CycloneDX' "$Target SBOM format"
    Assert-Equal $Sbom.specVersion '1.5' "$Target SBOM specVersion"
    Assert-Equal $Sbom.version 1 "$Target SBOM version"
    Assert-Equal $Sbom.metadata.component.'bom-ref' 'pkg:cargo/deep-mlkem-braid@0.1.0' "$Target root bom-ref"
    Assert-Equal $Sbom.metadata.component.licenses[0].expression 'Apache-2.0' "$Target root license"

    $packages = @($Metadata.packages)
    if ($packages.Count -ne $ExpectedPackageCount) {
        throw "$Target Cargo closure drifted. Expected $ExpectedPackageCount packages including root; actual $($packages.Count)."
    }
    $rootPackages = @($packages | Where-Object { [string]$_.name -ceq 'deep-mlkem-braid' -and [string]$_.version -ceq '0.1.0' })
    if ($rootPackages.Count -ne 1) {
        throw "$Target Cargo closure has no unique deep-mlkem-braid root."
    }

    $expectedComponents = @($packages | Where-Object { $_.id -cne $rootPackages[0].id } | Sort-Object name, version)
    $actualComponents = @($Sbom.components)
    if ($actualComponents.Count -ne $expectedComponents.Count) {
        throw "$Target SBOM component count differs. Expected $($expectedComponents.Count); actual $($actualComponents.Count)."
    }
    for ($index = 0; $index -lt $expectedComponents.Count; $index++) {
        $package = $expectedComponents[$index]
        $component = $actualComponents[$index]
        $purl = Get-Purl $package
        $checksum = Get-LockChecksum $LockText ([string]$package.name) ([string]$package.version)
        Assert-PropertySet $component @('type', 'bom-ref', 'name', 'version', 'licenses', 'hashes', 'purl', 'properties') "$Target SBOM component $purl"
        Assert-Equal $component.type 'library' "$target $purl type"
        Assert-Equal $component.'bom-ref' $purl "$target $purl bom-ref"
        Assert-Equal $component.name $package.name "$target $purl name"
        Assert-Equal $component.version $package.version "$target $purl version"
        Assert-Equal $component.licenses.Count 1 "$target $purl license count"
        Assert-Equal $component.licenses[0].expression $package.license "$target $purl license"
        Assert-Equal $component.hashes.Count 1 "$target $purl hash count"
        Assert-Equal $component.hashes[0].alg 'SHA-256' "$target $purl hash algorithm"
        Assert-Equal $component.hashes[0].content $checksum "$target $purl checksum"
        Assert-Equal $component.purl $purl "$target $purl purl"
        Assert-Equal $component.properties.Count 1 "$target $purl property count"
        Assert-Equal $component.properties[0].name 'cargo:source' "$target $purl source property"
        Assert-Equal $component.properties[0].value $package.source "$target $purl source"
    }

    $packageById = @{}
    foreach ($package in $packages) {
        $packageById[[string]$package.id] = $package
    }
    $expectedNodes = @()
    $rootNode = @($Metadata.resolve.nodes | Where-Object { $_.id -ceq $rootPackages[0].id })
    if ($rootNode.Count -ne 1) {
        throw "$Target Cargo metadata has no unique root resolve node."
    }
    $orderedNodes = @($rootNode[0]) + @($Metadata.resolve.nodes |
        Where-Object { $_.id -cne $rootPackages[0].id } |
        Sort-Object { [string]$packageById[[string]$_.id].name }, { [string]$packageById[[string]$_.id].version })
    foreach ($node in $orderedNodes) {
        $package = $packageById[[string]$node.id]
        $dependsOn = @($node.deps | ForEach-Object { Get-Purl $packageById[[string]$_.pkg] } | Sort-Object -CaseSensitive -Unique)
        $expectedNodes += [pscustomobject]@{ ref = (Get-Purl $package); dependsOn = $dependsOn }
    }
    $actualNodes = @($Sbom.dependencies)
    if ($actualNodes.Count -ne $expectedNodes.Count) {
        throw "$Target SBOM dependency-node count differs. Expected $($expectedNodes.Count); actual $($actualNodes.Count)."
    }
    for ($index = 0; $index -lt $expectedNodes.Count; $index++) {
        Assert-Equal $actualNodes[$index].ref $expectedNodes[$index].ref "$target SBOM dependency ref $index"
        Assert-Sequence @($actualNodes[$index].dependsOn) @($expectedNodes[$index].dependsOn) "$target SBOM dependencies for $($expectedNodes[$index].ref)"
    }
}

function Invoke-BuildAndCapture([string]$Target, [switch]$WithDevice) {
    $buildScript = Require-File (Resolve-EvidencePath 'eng/Build-DeepMlKemBraid.ps1')
    $parameters = @{ Target = $Target }
    if ($WithDevice) {
        $parameters.DeviceSerial = $DeviceSerial
        $parameters.AdbPath = $AdbPath
    }
    $environmentSnapshot = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $environmentSnapshot[[string]$entry.Key] = [string]$entry.Value
    }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $buildScript @parameters 2>&1 | ForEach-Object { $_.ToString() })
        $succeeded = $?
    } finally {
        $ErrorActionPreference = $previousPreference
        foreach ($key in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
            if (-not $environmentSnapshot.ContainsKey([string]$key)) {
                [Environment]::SetEnvironmentVariable([string]$key, $null, 'Process')
            }
        }
        foreach ($entry in $environmentSnapshot.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'Process')
        }
    }
    $output = $lines -join "`n"
    if (-not $succeeded) {
        throw "Candidate rebuild failed: $output"
    }
    return $output
}

function Get-WindowsX64Dumpbin {
    $vsWhere = Require-File (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')
    $vsPath = (& $vsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($vsPath)) {
        throw 'Visual Studio x64 C++ tools are unavailable.'
    }
    $msvcRoot = Join-Path $vsPath 'VC\Tools\MSVC'
    $candidates = @(Get-ChildItem -LiteralPath $msvcRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\dumpbin.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($candidates.Count -lt 1) {
        throw 'The Visual Studio x64 dumpbin tool is unavailable.'
    }
    return (Resolve-Path -LiteralPath $candidates[0]).Path
}

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$manifestPath = Require-File (Resolve-EvidencePath 'native/Deep.MlKemBraid/evidence/candidate-manifest.v1.json')
$manifestText = Get-Content -LiteralPath $manifestPath -Raw
if ($manifestText -match '(?i)approvedforproduction') {
    throw 'Candidate evidence must not contain an ApprovedForProduction assertion.'
}
$manifest = $manifestText | ConvertFrom-Json
Assert-PropertySet $manifest @('schema', 'releaseDisposition', 'scope', 'source', 'sboms', 'abi', 'targets') 'manifest'
Assert-Equal $manifest.schema 'deep-mlkem-braid-candidate-evidence.v1' 'manifest schema'
Assert-Equal $manifest.releaseDisposition 'candidate-evidence-only' 'release disposition'
Assert-PropertySet $manifest.scope @('runtimeIntegration', 'productionApproval', 'supportedEvidenceTargets', 'pendingEvidenceTargets') 'manifest scope'
Assert-Equal $manifest.scope.runtimeIntegration 'unchanged-and-out-of-scope' 'runtime scope'
Assert-Equal $manifest.scope.productionApproval 'not-granted' 'production approval'
Assert-Sequence @($manifest.scope.supportedEvidenceTargets) @('windows-x64', 'android-arm64') 'supported evidence targets'
Assert-Sequence @($manifest.scope.pendingEvidenceTargets) @('windows-arm64') 'pending evidence targets'

Assert-PropertySet $manifest.source @('rustToolchain', 'cargoLock', 'libcrux', 'inputs') 'manifest source'
Assert-PropertySet $manifest.source.rustToolchain @('channel', 'release', 'commitHash', 'commitDate', 'host', 'llvmVersion', 'fileSha256') 'Rust toolchain evidence'
Assert-PropertySet $manifest.source.cargoLock @('version', 'path', 'size', 'sha256') 'Cargo.lock evidence'
Assert-PropertySet $manifest.source.libcrux @('package', 'version', 'crateSha256', 'repositoryCommit', 'repositoryTag', 'provenanceSha256') 'libcrux evidence'
Assert-Equal $manifest.source.rustToolchain.channel $toolchain 'Rust toolchain channel'
Assert-Equal $manifest.source.rustToolchain.release '1.89.0' 'Rust release'
Assert-Equal $manifest.source.rustToolchain.commitHash '29483883eed69d5fb4db01964cdf2af4d86e9cb2' 'rustc commit'
Assert-Equal $manifest.source.rustToolchain.commitDate '2025-08-04' 'rustc commit date'
Assert-Equal $manifest.source.rustToolchain.host 'x86_64-pc-windows-msvc' 'rustc host'
Assert-Equal $manifest.source.rustToolchain.llvmVersion '20.1.7' 'LLVM version'
Assert-Equal $manifest.source.rustToolchain.fileSha256 $expectedToolchainFileSha256 'toolchain file hash'
Assert-Equal $manifest.source.cargoLock.version 4 'Cargo.lock version'
Assert-Equal $manifest.source.cargoLock.path 'native/Deep.MlKemBraid/Cargo.lock' 'Cargo.lock path'
Assert-Equal $manifest.source.cargoLock.size 18941 'Cargo.lock size'
Assert-Equal $manifest.source.cargoLock.sha256 $expectedCargoLockSha256 'Cargo.lock hash'
Assert-Equal $manifest.source.libcrux.package 'libcrux-ml-kem' 'libcrux package'
Assert-Equal $manifest.source.libcrux.version '0.0.10' 'libcrux version'
Assert-Equal $manifest.source.libcrux.crateSha256 $expectedLibcruxCrateSha256 'libcrux crate hash'
Assert-Equal $manifest.source.libcrux.repositoryCommit 'c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd' 'libcrux commit'
Assert-Equal $manifest.source.libcrux.repositoryTag 'libcrux-ml-kem-v0.0.10' 'libcrux tag'
Assert-Equal $manifest.source.libcrux.provenanceSha256 $expectedLibcruxProvenanceSha256 'libcrux provenance hash'

$manifestInputs = @($manifest.source.inputs)
if ($manifestInputs.Count -ne $expectedInputs.Count) {
    throw "Source input count differs. Expected $($expectedInputs.Count); actual $($manifestInputs.Count)."
}
for ($index = 0; $index -lt $expectedInputs.Count; $index++) {
    $expected = $expectedInputs[$index]
    $actual = $manifestInputs[$index]
    Assert-PropertySet $actual @('path', 'size', 'sha256') "source input $index"
    Assert-Equal $actual.path $expected.path "source input path $index"
    Assert-Equal $actual.size $expected.size "source input size $($expected.path)"
    Assert-Equal $actual.sha256 $expected.sha256 "source input hash $($expected.path)"
    Assert-FileIdentity $expected.path $expected.size $expected.sha256
}
Assert-FileIdentity 'native/Deep.MlKemBraid/Cargo.lock' 18941 $expectedCargoLockSha256

$provenancePath = Require-File (Resolve-EvidencePath 'native/Deep.MlKemBraid/third-party/libcrux/provenance.json')
$provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
Assert-Equal $provenance.package 'libcrux-ml-kem' 'libcrux provenance package'
Assert-Equal $provenance.crateVersion '0.0.10' 'libcrux provenance version'
Assert-Equal $provenance.crateSha256 $expectedLibcruxCrateSha256 'libcrux provenance crate hash'
Assert-Equal $provenance.repositoryCommit 'c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd' 'libcrux provenance commit'
Assert-Equal $provenance.repositoryTag 'libcrux-ml-kem-v0.0.10' 'libcrux provenance tag'
Assert-Equal $provenance.declaredCrateLicense 'Apache-2.0' 'libcrux declared license'

$cargoLockPath = Require-File (Resolve-EvidencePath 'native/Deep.MlKemBraid/Cargo.lock')
$cargoLockText = Get-Content -LiteralPath $cargoLockPath -Raw
Assert-Equal (Get-LockChecksum $cargoLockText 'libcrux-ml-kem' '0.0.10') $expectedLibcruxCrateSha256 'Cargo.lock libcrux checksum'

$crateCacheRoot = Join-Path $env:USERPROFILE '.cargo\registry\cache'
$crateArchives = @(Get-ChildItem -LiteralPath $crateCacheRoot -Recurse -Filter 'libcrux-ml-kem-0.0.10.crate' -File -ErrorAction SilentlyContinue)
if ($crateArchives.Count -lt 1) {
    throw 'The pinned libcrux-ml-kem 0.0.10 crate archive is absent from the Cargo cache.'
}
foreach ($crateArchive in $crateArchives) {
    Assert-Equal (Get-LowerSha256 $crateArchive.FullName) $expectedLibcruxCrateSha256 "crate archive hash $($crateArchive.FullName)"
}

$cargo = Require-File (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe')
$rustc = Require-File (Join-Path $env:USERPROFILE ".rustup\toolchains\$toolchain\bin\rustc.exe")
$rustVersion = (& $rustc --version --verbose | Out-String)
if ($LASTEXITCODE -ne 0 -or
    $rustVersion -notmatch '(?m)^release: 1\.89\.0\s*$' -or
    $rustVersion -notmatch '(?m)^commit-hash: 29483883eed69d5fb4db01964cdf2af4d86e9cb2\s*$' -or
    $rustVersion -notmatch '(?m)^commit-date: 2025-08-04\s*$' -or
    $rustVersion -notmatch '(?m)^host: x86_64-pc-windows-msvc\s*$' -or
    $rustVersion -notmatch '(?m)^LLVM version: 20\.1\.7\s*$') {
    throw 'The installed Rust toolchain differs from the candidate evidence pin.'
}

$nativeManifestPath = Require-File (Resolve-EvidencePath 'native/Deep.MlKemBraid/Cargo.toml')
$windowsMetadata = Get-CargoMetadata $cargo $nativeManifestPath 'x86_64-pc-windows-msvc'
$androidMetadata = Get-CargoMetadata $cargo $nativeManifestPath 'aarch64-linux-android'
Assert-CrateArchives @($windowsMetadata, $androidMetadata) $cargoLockText $crateCacheRoot
$sboms = @($manifest.sboms)
if ($sboms.Count -ne 2) {
    throw "Manifest must contain exactly two target-specific SBOMs; actual $($sboms.Count)."
}
$windowsSbomEntry = @($sboms | Where-Object { [string]$_.target -ceq 'windows-x64' })
$androidSbomEntry = @($sboms | Where-Object { [string]$_.target -ceq 'android-arm64' })
if ($windowsSbomEntry.Count -ne 1 -or $androidSbomEntry.Count -ne 1) {
    throw 'Manifest must contain unique Windows x64 and Android arm64 SBOM entries.'
}
$windowsSbomEntry = $windowsSbomEntry[0]
$androidSbomEntry = $androidSbomEntry[0]
Assert-PropertySet $windowsSbomEntry @('target', 'format', 'specVersion', 'path', 'componentCountIncludingRoot', 'sha256') 'Windows SBOM entry'
Assert-PropertySet $androidSbomEntry @('target', 'format', 'specVersion', 'path', 'componentCountIncludingRoot', 'sha256') 'Android SBOM entry'
Assert-Equal $windowsSbomEntry.format 'CycloneDX' 'Windows SBOM format'
Assert-Equal $windowsSbomEntry.specVersion '1.5' 'Windows SBOM spec version'
Assert-Equal $windowsSbomEntry.path 'native/Deep.MlKemBraid/evidence/candidate-windows-x64-sbom.cdx.json' 'Windows SBOM path'
Assert-Equal $windowsSbomEntry.componentCountIncludingRoot 22 'Windows SBOM component count'
Assert-Equal $windowsSbomEntry.sha256 $expectedWindowsSbomSha256 'Windows SBOM manifest hash'
Assert-Equal $androidSbomEntry.format 'CycloneDX' 'Android SBOM format'
Assert-Equal $androidSbomEntry.specVersion '1.5' 'Android SBOM spec version'
Assert-Equal $androidSbomEntry.path 'native/Deep.MlKemBraid/evidence/candidate-android-arm64-sbom.cdx.json' 'Android SBOM path'
Assert-Equal $androidSbomEntry.componentCountIncludingRoot 21 'Android SBOM component count'
Assert-Equal $androidSbomEntry.sha256 $expectedAndroidSbomSha256 'Android SBOM manifest hash'
$windowsSbomPath = Require-File (Resolve-EvidencePath $windowsSbomEntry.path)
$androidSbomPath = Require-File (Resolve-EvidencePath $androidSbomEntry.path)
Assert-Equal (Get-LowerSha256 $windowsSbomPath) $expectedWindowsSbomSha256 'Windows SBOM file hash'
Assert-Equal (Get-LowerSha256 $androidSbomPath) $expectedAndroidSbomSha256 'Android SBOM file hash'
$windowsSbom = Get-Content -LiteralPath $windowsSbomPath -Raw | ConvertFrom-Json
$androidSbom = Get-Content -LiteralPath $androidSbomPath -Raw | ConvertFrom-Json
Assert-SbomClosure $windowsSbom $windowsMetadata $cargoLockText 'windows-x64' 22
Assert-SbomClosure $androidSbom $androidMetadata $cargoLockText 'android-arm64' 21

Assert-Sequence @($manifest.abi.exports) $expectedExports 'ABI export allowlist'
Assert-PropertySet $manifest.abi @('exports') 'ABI evidence'
if (@($manifest.targets).Count -ne 3) {
    throw "Manifest must contain exactly three target records; actual $(@($manifest.targets).Count)."
}
$windows = Get-Target $manifest 'windows-x64'
$android = Get-Target $manifest 'android-arm64'
$windowsArm64 = Get-Target $manifest 'windows-arm64'
Assert-PropertySet $windows @('id', 'status', 'triple', 'artifact', 'toolchain', 'binary', 'testEvidence') 'Windows x64 target'
Assert-PropertySet $windows.artifact @('path', 'size', 'sha256') 'Windows x64 artifact'
Assert-PropertySet $windows.toolchain @('windowsSdk', 'msvcHost', 'msvcTarget') 'Windows x64 build toolchain'
Assert-PropertySet $windows.binary @('format', 'machine', 'dependencies', 'requiredHardening') 'Windows x64 binary evidence'
Assert-PropertySet $windows.testEvidence[0] @('id', 'expectedPassed', 'expectedFailed') 'Windows Rust test evidence'
Assert-PropertySet $windows.testEvidence[1] @('id', 'expectedMarker') 'Windows C probe evidence'
Assert-Equal $windows.status 'evidenced-candidate' 'Windows x64 status'
Assert-Equal $windows.triple 'x86_64-pc-windows-msvc' 'Windows x64 triple'
Assert-Equal $windows.artifact.path 'native/Deep.MlKemBraid/target/x86_64-pc-windows-msvc/release/deep_mlkem_braid.dll' 'Windows x64 artifact path'
Assert-Equal $windows.artifact.size 526336 'Windows x64 artifact size'
Assert-Equal $windows.artifact.sha256 $expectedWindowsArtifactSha256 'Windows x64 artifact hash'
Assert-Equal $windows.toolchain.windowsSdk '10.0.26100.0' 'Windows SDK'
Assert-Equal $windows.toolchain.msvcHost 'x64' 'Windows MSVC host'
Assert-Equal $windows.toolchain.msvcTarget 'x64' 'Windows MSVC target'
Assert-Equal $windows.binary.format 'PE32+ DLL' 'Windows binary format'
Assert-Equal $windows.binary.machine 'x64' 'Windows machine'
Assert-Sequence @($windows.binary.dependencies) @('api-ms-win-core-synch-l1-2-0.dll', 'bcryptprimitives.dll', 'KERNEL32.dll', 'ntdll.dll') 'Windows dependencies'
Assert-Sequence @($windows.binary.requiredHardening) @('Dynamic base', 'High Entropy Virtual Addresses', 'NX compatible', 'Control Flow Guard') 'Windows hardening policy'
Assert-Equal @($windows.testEvidence).Count 2 'Windows test-evidence count'
Assert-Equal $windows.testEvidence[0].id 'rust-release-tests' 'Windows Rust test id'
Assert-Equal $windows.testEvidence[0].expectedPassed 7 'Windows Rust passed-test count'
Assert-Equal $windows.testEvidence[0].expectedFailed 0 'Windows Rust failed-test count'
Assert-Equal $windows.testEvidence[1].id 'native-c-abi-probe' 'Windows C probe id'
Assert-Equal $windows.testEvidence[1].expectedMarker 'Deep ML-KEM Braid native C ABI probe passed.' 'Windows probe marker'

Assert-PropertySet $android @('id', 'status', 'triple', 'artifact', 'toolchain', 'binary', 'testEvidence') 'Android arm64 target'
Assert-PropertySet $android.artifact @('path', 'size', 'sha256') 'Android artifact'
Assert-PropertySet $android.toolchain @('ndkVersion', 'androidApi') 'Android build toolchain'
Assert-PropertySet $android.binary @('format', 'machine', 'endianness', 'dependencies', 'requiredHardening', 'forbiddenFeatures') 'Android binary evidence'
Assert-Equal $android.status 'evidenced-candidate' 'Android arm64 status'
Assert-Equal $android.triple 'aarch64-linux-android' 'Android arm64 triple'
Assert-Equal $android.artifact.path 'native/Deep.MlKemBraid/target/aarch64-linux-android/release/libdeep_mlkem_braid.so' 'Android artifact path'
Assert-Equal $android.artifact.size 612344 'Android artifact size'
Assert-Equal $android.artifact.sha256 $expectedAndroidArtifactSha256 'Android artifact hash'
Assert-Equal $android.toolchain.ndkVersion '28.2.13676358' 'Android NDK version'
Assert-Equal $android.toolchain.androidApi 26 'Android API'
Assert-Equal $android.binary.format 'ELF64 shared object' 'Android binary format'
Assert-Equal $android.binary.machine 'AArch64' 'Android machine'
Assert-Equal $android.binary.endianness 'little' 'Android endianness'
Assert-Sequence @($android.binary.dependencies) @('libc.so', 'libdl.so') 'Android dependencies'
Assert-Sequence @($android.binary.requiredHardening) @('BIND_NOW', 'GNU_RELRO', 'non-executable GNU_STACK') 'Android hardening policy'
Assert-Sequence @($android.binary.forbiddenFeatures) @('TEXTREL') 'Android forbidden features'
$androidProbeEvidence = $android.testEvidence[0]
Assert-Equal @($android.testEvidence).Count 1 'Android test-evidence count'
Assert-PropertySet $androidProbeEvidence @('id', 'requiredAbi', 'minimumApi', 'expected') 'Android probe evidence'
Assert-PropertySet $androidProbeEvidence.expected @('schema', 'result', 'roundTrips', 'replayRejected', 'doubleDisposeRejected', 'reloadPassed', 'secretsEmitted') 'Android probe expected result'
Assert-Equal $androidProbeEvidence.id 'android-native-device-probe' 'Android probe id'
Assert-Equal $androidProbeEvidence.requiredAbi 'arm64-v8a' 'Android probe ABI'
Assert-Equal $androidProbeEvidence.minimumApi 26 'Android probe minimum API'
Assert-Equal $androidProbeEvidence.expected.schema 'deep-mlkem-braid-android-probe-v1' 'Android probe schema'
Assert-Equal $androidProbeEvidence.expected.result 'pass' 'Android probe result'
Assert-Equal $androidProbeEvidence.expected.roundTrips 2 'Android probe round trips'
Assert-Equal $androidProbeEvidence.expected.replayRejected $true 'Android replay rejection'
Assert-Equal $androidProbeEvidence.expected.doubleDisposeRejected $true 'Android double-dispose rejection'
Assert-Equal $androidProbeEvidence.expected.reloadPassed $true 'Android reload evidence'
Assert-Equal $androidProbeEvidence.expected.secretsEmitted $false 'Android secret-output evidence'

Assert-PropertySet $windowsArm64 @('id', 'status', 'triple', 'artifact', 'reason') 'Windows arm64 target'
Assert-Equal $windowsArm64.status 'pending' 'Windows arm64 status'
Assert-Equal $windowsArm64.triple 'aarch64-pc-windows-msvc' 'Windows arm64 triple'
if ($null -ne $windowsArm64.artifact) {
    throw 'Windows arm64 must remain pending without an artifact claim.'
}
Assert-Equal $windowsArm64.reason 'The required Visual Studio ARM64 C++ toolchain is not installed; no artifact or execution evidence is accepted.' 'Windows arm64 pending reason'
$unexpectedWindowsArm64Artifact = Resolve-EvidencePath 'native/Deep.MlKemBraid/target/aarch64-pc-windows-msvc/release/deep_mlkem_braid.dll'
if (Test-Path -LiteralPath $unexpectedWindowsArm64Artifact -PathType Leaf) {
    throw 'A Windows arm64 artifact exists while the evidence target is pending; review and repin explicitly.'
}

if ($Rebuild) {
    if ([string]::IsNullOrWhiteSpace($DeviceSerial) -or [string]::IsNullOrWhiteSpace($AdbPath)) {
        throw 'Rebuild evidence requires DeviceSerial and AdbPath so the Android runtime probe is not silently skipped.'
    }
    $windowsBuildOutput = Invoke-BuildAndCapture 'windows-x64'
    if ($windowsBuildOutput -notmatch 'test result: ok\. 7 passed; 0 failed;' -or
        $windowsBuildOutput -notmatch [regex]::Escape($windows.testEvidence[1].expectedMarker)) {
        throw 'Windows rebuild output does not contain the exact Rust/C probe evidence.'
    }
    $androidBuildOutput = Invoke-BuildAndCapture 'android-arm64' -WithDevice
    $probeMatch = [regex]::Match($androidBuildOutput, '\{\s*"schema":"deep-mlkem-braid-android-probe-v1"[^\r\n]*\}')
    if (-not $probeMatch.Success) {
        throw 'Android rebuild output does not contain the bounded runtime-probe evidence.'
    }
    $probe = $probeMatch.Value | ConvertFrom-Json
    Assert-Equal $probe.result 'pass' 'rebuilt Android probe result'
    Assert-Equal $probe.roundTrips 2 'rebuilt Android probe round trips'
    Assert-Equal $probe.replayRejected $true 'rebuilt Android replay rejection'
    Assert-Equal $probe.doubleDisposeRejected $true 'rebuilt Android double-dispose rejection'
    Assert-Equal $probe.reloadPassed $true 'rebuilt Android reload evidence'
    Assert-Equal $probe.secretsEmitted $false 'rebuilt Android secret-output evidence'
}

$windowsArtifactPath = Require-File (Resolve-EvidencePath $windows.artifact.path)
$androidArtifactPath = Require-File (Resolve-EvidencePath $android.artifact.path)
Assert-FileIdentity $windows.artifact.path 526336 $expectedWindowsArtifactSha256
Assert-FileIdentity $android.artifact.path 612344 $expectedAndroidArtifactSha256

$dumpbin = Get-WindowsX64Dumpbin
$windowsHeaders = (& $dumpbin /nologo /headers $windowsArtifactPath | Out-String)
if ($LASTEXITCODE -ne 0 -or $windowsHeaders -notmatch '(?im)^\s*8664 machine \(x64\)\s*$') {
    throw 'Windows artifact is not an x64 PE image.'
}
foreach ($flag in @($windows.binary.requiredHardening)) {
    if ($windowsHeaders -notmatch [regex]::Escape([string]$flag)) {
        throw "Windows artifact is missing hardening flag: $flag"
    }
}
$windowsExports = @(& $dumpbin /nologo /exports $windowsArtifactPath |
    ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(deep_mlkem_braid_v1_\S+)(?:\s+=.*)?$') { $Matches[1] }
    } | Sort-Object -CaseSensitive -Unique)
Assert-Sequence $windowsExports $expectedExports 'Windows export surface'
$windowsDependents = (& $dumpbin /nologo /dependents $windowsArtifactPath | Out-String)
$windowsDependencies = @([regex]::Matches($windowsDependents, '(?im)^\s+(?<name>[A-Za-z0-9_.-]+\.dll)\s*$') |
    ForEach-Object { $_.Groups['name'].Value } | Sort-Object -CaseSensitive -Unique)
Assert-Sequence $windowsDependencies @($windows.binary.dependencies | Sort-Object -CaseSensitive) 'Windows imported libraries'

$ndkProperties = Require-File (Join-Path $NdkRoot 'source.properties')
if ((Get-Content -LiteralPath $ndkProperties -Raw) -notmatch '(?m)^Pkg\.Revision\s*=\s*28\.2\.13676358\s*$') {
    throw 'Android NDK differs from exact 28.2.13676358.'
}
$ndkBin = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$llvmNm = Require-File (Join-Path $ndkBin 'llvm-nm.exe')
$llvmReadElf = Require-File (Join-Path $ndkBin 'llvm-readelf.exe')
$androidExports = @(& $llvmNm -D --defined-only --format=posix $androidArtifactPath |
    ForEach-Object {
        if ($_ -match '^(deep_mlkem_braid_v1_\S+)\s') { $Matches[1] }
    } | Sort-Object -CaseSensitive -Unique)
Assert-Sequence $androidExports $expectedExports 'Android export surface'
$androidHeader = (& $llvmReadElf --file-header $androidArtifactPath | Out-String)
if ($LASTEXITCODE -ne 0 -or
    $androidHeader -notmatch 'Class:\s+ELF64' -or
    $androidHeader -notmatch "Data:\s+2's complement, little endian" -or
    $androidHeader -notmatch 'Type:\s+DYN \(Shared object file\)' -or
    $androidHeader -notmatch 'Machine:\s+AArch64') {
    throw 'Android artifact ELF identity drifted.'
}
$androidDynamic = (& $llvmReadElf --dynamic $androidArtifactPath | Out-String)
$androidProgramHeaders = (& $llvmReadElf --program-headers $androidArtifactPath | Out-String)
if ($androidDynamic -notmatch '\bBIND_NOW\b' -and $androidDynamic -notmatch 'Flags:.*NOW') {
    throw 'Android artifact is missing BIND_NOW.'
}
if ($androidDynamic -match '\bTEXTREL\b') {
    throw 'Android artifact contains TEXTREL.'
}
if ($androidProgramHeaders -notmatch '\bGNU_RELRO\b') {
    throw 'Android artifact is missing GNU_RELRO.'
}
$stackLine = @($androidProgramHeaders -split "`r?`n" | Where-Object { $_ -match '\bGNU_STACK\b' })
if ($stackLine.Count -ne 1 -or $stackLine[0] -match '\sRWE\s') {
    throw 'Android artifact does not have one non-executable GNU_STACK.'
}
$androidDependencies = @([regex]::Matches($androidDynamic, '\(NEEDED\).*?\[(?<name>[^\]]+)\]') |
    ForEach-Object { $_.Groups['name'].Value } | Sort-Object -CaseSensitive -Unique)
Assert-Sequence $androidDependencies @($android.binary.dependencies | Sort-Object -CaseSensitive) 'Android needed libraries'

[ordered]@{
    schema = 'deep-mlkem-braid-evidence-gate-result.v1'
    status = 'pass'
    releaseDisposition = 'candidate-evidence-only'
    cargoPackages = [ordered]@{ windowsX64 = 22; androidArm64 = 21 }
    exportsPerArtifact = $expectedExports.Count
    windowsX64 = [ordered]@{ size = 526336; sha256 = $expectedWindowsArtifactSha256; hardening = 'pass'; tests = 7 }
    androidArm64 = [ordered]@{ size = 612344; sha256 = $expectedAndroidArtifactSha256; hardening = 'pass'; deviceProbe = $(if ($Rebuild) { 'pass' } else { 'not-rerun' }) }
    windowsArm64 = 'pending'
} | ConvertTo-Json -Depth 5 -Compress
