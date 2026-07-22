[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$PackagePath = "",
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if ([string]::IsNullOrWhiteSpace($PackagePath)) {
    $PackagePath = Join-Path (Split-Path -Parent $RepositoryRoot) `
        "p14e2-package-final\Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg"
}

$sourceCommit = "69a712a894b024a09859096025c2bb8fe68a642e"
$sourceTree = "d83bbdd001b723738357689bbb2150a51357cb3b"
$carrierRelativePath = "artifacts/survival/P14E2/p14e2-evidence.md"
$validatorRelativePath = "eng/verify-p14e2-evidence.ps1"
$carrierPath = Join-Path $RepositoryRoot ($carrierRelativePath -replace "/", "\")
$allowedChanges = @($carrierRelativePath, $validatorRelativePath)

function Invoke-Git {
    param([string[]]$Arguments)
    $output = & git -C $RepositoryRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($Arguments -join ' ')"
    }
    return @($output)
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) {
        throw "$Label mismatch. Expected '$Expected', actual '$Actual'."
    }
}

function Assert-ContainsExact {
    param([string]$Text, [string]$Expected, [string]$Label)
    $lines = @($Text -split "\r?\n")
    if ($lines -notcontains $Expected -and $lines -notcontains "- $Expected") {
        throw "$Label is missing or drifted."
    }
}

function Assert-CanonicalStructuredEvidence {
    param([string]$Text)
}

if ($SelfTest) {
    $mutationCases = @(
        @(
            "reviewer-attribution",
            "Reviewer-1-Label: /root/p14e2_implementation/p14e2_protocol_review"
        ),
        @(
            "source-tree",
            "Source-Tree: d83bbdd001b723738357689bbb2150a51357cb3b"
        ),
        @(
            "chosen-package",
            "Chosen-Package-SHA256: fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498"
        ),
        @(
            "release-boundary",
            "CROSS-RID-EXECUTION-PENDING"
        )
    )
    foreach ($mutationCase in $mutationCases) {
        $label = $mutationCase[0]
        $expected = $mutationCase[1]
        $mutated = "$expected-drift"
        $rejected = $false
        try {
            Assert-ContainsExact $mutated $expected $label
        }
        catch {
            if ($_.Exception.Message -notlike "*missing or drifted*") {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            throw "Evidence validator accepted $label suffix drift."
        }
    }
    if ($allowedChanges -contains "artifacts/survival/P14E2/forbidden.bin") {
        throw "Evidence validator allowlist accepted a binary path."
    }

    $canonicalCarrier = [IO.File]::ReadAllText($carrierPath)
    $structuredMutations = @(
        @("production-signer-positive", "- PRODUCTION-SIGNER-GO"),
        @("client-activation-positive", "- CLIENT-ACTIVATION-GO"),
        @("cross-rid-positive", "- CROSS-RID-EXECUTION-GO"),
        @("external-review-complete", "- EXTERNAL-CRYPTO-PROFILE-REVIEW-COMPLETE"),
        @("external-review-positive", "- EXTERNAL-CRYPTO-PROFILE-REVIEW-GO"),
        @("duplicate-reviewer-1-label", "- Reviewer-1-Label: /root/p14e2_implementation/p14e2_protocol_review"),
        @("duplicate-reviewer-2-label", "- Reviewer-2-Label: /root/p14e2_implementation/p14e2_security_review"),
        @("duplicate-reviewer-1-verdict", "- Reviewer-1-Verdict: GO"),
        @("duplicate-reviewer-2-verdict", "- Reviewer-2-Verdict: GO"),
        @("duplicate-reviewer-1-findings", "- Reviewer-1-P0-P3: 0"),
        @("duplicate-reviewer-2-findings", "- Reviewer-2-P0-P3: 0"),
        @("duplicate-source-commit", "- Source-Commit: 69a712a894b024a09859096025c2bb8fe68a642e"),
        @("duplicate-source-tree", "- Source-Tree: d83bbdd001b723738357689bbb2150a51357cb3b"),
        @("duplicate-package-hash", "- Chosen-Package-SHA256: fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498"),
        @("duplicate-package-identity", "- Normalized-Identity-SHA256: baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f"),
        @("duplicate-package-version", "- Chosen-NuGet-Version: 0.2.0-p14.69a712a"),
        @("duplicate-package-source", "- Chosen-Nuspec-Repository-Commit: 69a712a894b024a09859096025c2bb8fe68a642e"),
        @("unexpected-structured-key", "- Unexpected-Evidence-Key: value"),
        @("unexpected-structured-status", "- UNEXPECTED-RELEASE-GO")
    )
    $acceptedMutations = @()
    foreach ($structuredMutation in $structuredMutations) {
        $label = $structuredMutation[0]
        $mutatedCarrier = "$canonicalCarrier`n$($structuredMutation[1])`n"
        try {
            Assert-CanonicalStructuredEvidence $mutatedCarrier
            $acceptedMutations += $label
        }
        catch {
            continue
        }
    }
    if ($acceptedMutations.Count -ne 0) {
        throw "Evidence validator accepted contradictory or duplicate structured claims: $($acceptedMutations -join ', ')."
    }

    "PASS P14E2 evidence validator mutation self-test"
    return
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha512Base64 {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA512]::Create()
        try {
            return [Convert]::ToBase64String($algorithm.ComputeHash($stream))
        }
        finally {
            $algorithm.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-EntryBytes {
    param(
        [IO.Compression.ZipArchive]$Archive,
        [string]$Name
    )
    $entry = $Archive.GetEntry($Name)
    if ($null -eq $entry) {
        throw "Chosen package entry is missing: $Name"
    }
    $entryStream = $entry.Open()
    try {
        $memory = [IO.MemoryStream]::new()
        try {
            $entryStream.CopyTo($memory)
            return $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $entryStream.Dispose()
    }
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes)) -replace "-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

$dirty = @(Invoke-Git @("status", "--porcelain=v1", "--untracked-files=all"))
if ($dirty.Count -ne 0) {
    throw "The evidence gate requires an exact clean committed worktree."
}

$materializedSourceTree = (Invoke-Git @("show", "-s", "--format=%T", $sourceCommit) | Out-String).Trim()
Assert-Equal $sourceTree $materializedSourceTree "Exact P14E2 source tree"
& git -C $RepositoryRoot merge-base --is-ancestor $sourceCommit HEAD
if ($LASTEXITCODE -ne 0) {
    throw "Evidence HEAD is not a descendant of the exact P14E2 source."
}

$changedFiles = @(Invoke-Git @("diff", "--name-only", "$sourceCommit..HEAD"))
foreach ($changedFile in $changedFiles) {
    if ($allowedChanges -notcontains $changedFile) {
        throw "Evidence branch contains a forbidden source or binary change: $changedFile"
    }
}
foreach ($requiredChange in $allowedChanges) {
    if ($changedFiles -notcontains $requiredChange) {
        throw "Evidence branch is missing required carrier file: $requiredChange"
    }
}
$binaryChanges = @(Invoke-Git @("diff", "--numstat", "$sourceCommit..HEAD") |
    Where-Object { $_ -match "^\-\s+\-\s+" })
if ($binaryChanges.Count -ne 0) {
    throw "Binary content is forbidden in the evidence carrier."
}

if (-not (Test-Path -LiteralPath $carrierPath -PathType Leaf)) {
    throw "The sanitized P14E2 Markdown carrier is missing."
}
$artifactFiles = @(Get-ChildItem -LiteralPath (Split-Path -Parent $carrierPath) -Recurse -File)
if ($artifactFiles.Count -ne 1 -or $artifactFiles[0].FullName -ne (Get-Item -LiteralPath $carrierPath).FullName) {
    throw "P14E2 artifact directory must contain only the sanitized Markdown carrier."
}
$carrierBytes = [IO.File]::ReadAllBytes($carrierPath)
if ($carrierBytes.Length -gt 65536 -or $carrierBytes -contains 0) {
    throw "Evidence Markdown is oversized or not plain text."
}
$carrier = [Text.Encoding]::UTF8.GetString($carrierBytes)
if ($carrier.IndexOf('```', [StringComparison]::Ordinal) -ge 0 -or
    $carrier -match "(?i)BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" -or
    $carrier -match "(?im)^\s*(password|api[_-]?key|private[_-]?key|seed|mnemonic|secret|token)\s*[:=]") {
    throw "Evidence Markdown contains forbidden raw-output or secret-shaped content."
}

$requiredEvidence = @(
    "Source-Commit: $sourceCommit",
    "Source-Tree: $sourceTree",
    "Reviewer-1-Label: /root/p14e2_implementation/p14e2_protocol_review",
    "Reviewer-1-Scope: independent protocol/architecture exact-source review",
    "Reviewer-1-Participation: read-only review; no edits; worktree clean before and after",
    "Reviewer-1-Verdict: GO",
    "Reviewer-1-P0-P3: 0",
    "Reviewer-2-Label: /root/p14e2_implementation/p14e2_security_review",
    "Reviewer-2-Scope: independent security/crypto/supply-chain exact-source review",
    "Reviewer-2-Participation: read-only review; no edits; worktree clean before and after",
    "Reviewer-2-Verdict: GO",
    "Reviewer-2-P0-P3: 0",
    "ActivationTransition-Debug: 19/19",
    "ActivationTransition-Release: 19/19",
    "Ed25519-Release: 15/15",
    "ProfileCarrier-Debug: 85/85",
    "ProfileCarrier-Release: 85/85",
    "Protocol-Debug: 173/173",
    "Protocol-Release: 173/173",
    "ActivationTransition-Release-Stress: 25/25",
    "Release-Build: 0 warnings / 0 errors",
    "Offline-Package-Closure: 21 packages",
    "Provenance-XNode-Commit: eff452368fa4cb1324c5b3c8ee06e2f10e96b835",
    "Provenance-XNode-Tree: ee7a54e9eb0bc4c0803b9508627355eec75f0405",
    "Provenance-XNode-Files: 167",
    "Provenance-Differential-SHA256: cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe",
    "CROSS-RID-EXECUTION-PENDING",
    "PRODUCTION-SIGNER-NO-GO",
    "CLIENT-ACTIVATION-NO-GO",
    "EXTERNAL-CRYPTO-PROFILE-REVIEW-PENDING",
    "Chosen-Package-Bytes: 29399",
    "Chosen-Package-SHA256: fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498",
    "Chosen-Package-SHA512: x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==",
    "Normalized-Identity-SHA256: baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f",
    "Chosen-DLL-SHA256: 20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034",
    "Chosen-PDB-SHA256: 80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a",
    "Chosen-NuGet-Version: 0.2.0-p14.69a712a",
    "Chosen-Nuspec-Repository-Commit: $sourceCommit",
    "Independent-Security-Pack-Bytes: 29401",
    "Independent-Security-Pack-SHA256: a2fcbe31dcbed2105f3bf2a627825930e463974db3be1d2fa1da8ae33deadf42",
    "Independent-Security-Pack-Normalized-Identity-SHA256: baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f",
    "The independent security pack raw ZIP size and SHA-256 differ because permitted OPC/ZIP metadata randomness changes raw container bytes; its normalized identity is identical to the chosen package.",
    "No runtime, DI, network, client, UAT, contract, or deployment change is authorized by this carrier."
)
foreach ($expected in $requiredEvidence) {
    Assert-ContainsExact $carrier $expected "Evidence field '$expected'"
}

$chain = @(
    "9e27410dbbaf4380be4b6975dd6be238458827b2|8668ab068277bee68c1cb16bec9ab341eafe23d9|test(p14e2): define activation trust prerequisites",
    "9296abf1daf88626827894bb3e1902232b535cdd|7f35560a1eeb29f780a36c0085dc18347a608ff5|test(p14e2): keep invalid rotation vector parser-free",
    "3724fb16cf9c2f022832c816dc05e195e2e8a1fe|31cacb738ff123c11570915e22d77fefa998511e|test(p14e2): correct transition boundary controls",
    "13b92927762787b335c6a6f772e813471a48edb6|da85a337798cf882e2d26ac31d7c059ee7cfc4a9|test(p14e2): materialize memory mutation vectors",
    "825449fd704c046f56e734e027491a409037e4b3|101c6a1d2767c96597e8f4a49f9d8c6312a6dc5b|test(p14e2): bound cross-rid supply proof",
    "c08cf3b37581314dbd300fb4ff1102ea1171096b|e1e9de9517dcf3b26a7060239d290a185c404993|test(p14e2): require ephemeral continuity cleanup",
    "1bf2bb89cfce71f6d141897e40f9ce5507bc0b28|e48258f97456e206ce645df77eb316d9130fa041|feat(p14e2): add dormant activation trust prerequisites",
    "a08f8dcdc9a46afa449440f52d2a576bd4d151b1|c69e994b1388470be2e3c2c7e1a09826840a1d3f|fix(p14e2): make win arm64 gate powershell compatible",
    "080b026b1739c76c1d6287bce457649ff932bd30|5ff69abe861c11e4b664ac815a2c5813e4d9e429|test(p14e2): require nested projection cleanup",
    "f295b20a881e427a04456dc3680cee9d0c2c6415|d5358d30f1ec65df596e27ffbf6084cebe36ac4a|fix(p14e2): close continuity ownership edges",
    "428b181e1ccc05ebd7f02b33083ddbf34e923f91|47b12242c0190d01cb2cf33541e35d8e50e6fdaa|fix(p14e2): lock differential crypto graph",
    "764420b8b944d22de457239dee2ec24d1fe59a4e|c419afc286a6721a7581bf9eba979f43cfbd9398|test(p14e2): expose bridge ownership oom gap",
    "69a712a894b024a09859096025c2bb8fe68a642e|d83bbdd001b723738357689bbb2150a51357cb3b|fix(p14e2): retain bridge commitment ownership"
)
foreach ($entry in $chain) {
    Assert-ContainsExact $carrier $entry "RED/GREEN chain entry '$entry'"
    $parts = $entry.Split("|", 3)
    $actualTree = (Invoke-Git @("show", "-s", "--format=%T", $parts[0]) | Out-String).Trim()
    Assert-Equal $parts[1] $actualTree "RED/GREEN chain tree for $($parts[0])"
}

$package = Get-Item -LiteralPath $PackagePath
Assert-Equal 29399 $package.Length "Chosen package byte length"
Assert-Equal "fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498" `
    (Get-Sha256 $package.FullName) "Chosen package SHA-256"
Assert-Equal "x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==" `
    (Get-Sha512Base64 $package.FullName) "Chosen package SHA-512 content hash"

$identity = & (Join-Path $RepositoryRoot "eng\Get-P14ProfileCarrierNormalizedIdentity.ps1") `
    -PackagePath $package.FullName `
    -ExpectedRepositoryCommit $sourceCommit
Assert-Equal "baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f" `
    $identity.Hash "Chosen package normalized identity"
Assert-Equal "0.2.0-p14.69a712a" $identity.Version "Chosen package normalized version"
Assert-Equal $sourceCommit $identity.RepositoryCommit "Chosen package normalized repository commit"

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    $dllBytes = Get-EntryBytes $archive "lib/net10.0/Deep.Protocol.ProfileCarrier.dll"
    $pdbBytes = Get-EntryBytes $archive "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb"
    $nuspecBytes = Get-EntryBytes $archive "Deep.Protocol.ProfileCarrier.nuspec"
}
finally {
    $archive.Dispose()
}
Assert-Equal "20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034" `
    (Get-BytesSha256 $dllBytes) "Chosen package DLL SHA-256"
Assert-Equal "80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a" `
    (Get-BytesSha256 $pdbBytes) "Chosen package PDB SHA-256"

$nuspecText = [Text.Encoding]::UTF8.GetString($nuspecBytes).TrimStart([char]0xfeff)
$nuspec = [xml]$nuspecText
$namespace = [Xml.XmlNamespaceManager]::new($nuspec.NameTable)
$namespace.AddNamespace("n", "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd")
$metadata = $nuspec.SelectSingleNode("/n:package/n:metadata", $namespace)
Assert-Equal "Deep.Protocol.ProfileCarrier" $metadata.id "Chosen nuspec package id"
Assert-Equal "0.2.0-p14.69a712a" $metadata.version "Chosen nuspec version"
$repository = $metadata.SelectSingleNode("n:repository", $namespace)
Assert-Equal "git" $repository.type "Chosen nuspec repository type"
Assert-Equal "https://github.com/XPointLabs/deep-protocol.git" $repository.url "Chosen nuspec repository URL"
Assert-Equal $sourceCommit $repository.commit "Chosen nuspec repository commit"
$dependencies = @($metadata.SelectNodes("n:dependencies/n:group/n:dependency", $namespace))
Assert-Equal 3 $dependencies.Count "Chosen nuspec dependency count"
$expectedDependencies = @{
    "Deep.Protocol" = "[0.3.0-p04.b887fa0]"
    "Sodium.Core" = "[1.4.1]"
    "libsodium" = "[1.0.22]"
}
foreach ($dependency in $dependencies) {
    if (-not $expectedDependencies.ContainsKey($dependency.id)) {
        throw "Unexpected chosen nuspec dependency: $($dependency.id)"
    }
    Assert-Equal $expectedDependencies[$dependency.id] $dependency.version `
        "Chosen nuspec dependency $($dependency.id)"
}

"PASS P14E2 evidence carrier source=$sourceCommit tree=$sourceTree package-sha256=fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498"
