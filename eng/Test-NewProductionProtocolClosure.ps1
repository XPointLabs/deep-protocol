[CmdletBinding()]
param([string] $RepositoryRoot = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$commonPath = Join-Path $RepositoryRoot 'eng/ProductionProtocolClosure.Common.ps1'
$materializerPath = Join-Path $RepositoryRoot 'eng/New-ProductionProtocolClosure.ps1'
$normalizerPath = Join-Path $RepositoryRoot 'eng/Normalize-ProductionProtocolClosure.ps1'
$policyPath = Join-Path $RepositoryRoot 'eng/production-protocol-closure.policy.json'
$schemaPath = Join-Path $RepositoryRoot 'eng/production-protocol-closure.policy.schema.json'
$nugetConfigPath = Join-Path $RepositoryRoot 'eng/production-protocol-closure.NuGet.Config'
$auditTargetsPath = Join-Path $RepositoryRoot 'eng/ProductionProtocolClosure.InputAudit.targets'
foreach ($path in @($commonPath, $materializerPath, $normalizerPath, $policyPath, $schemaPath, $nugetConfigPath, $auditTargetsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required materializer contract file is missing: $path" }
}
. $commonPath

function Assert-Rejects([scriptblock] $Action, [string] $Name, [string] $ExpectedMessage) {
    try { & $Action } catch {
        if ($_.Exception.Message.IndexOf($ExpectedMessage, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "Hostile case '$Name' rejected for an unexpected reason. Expected message fragment '$ExpectedMessage'; actual: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected hostile case '$Name' to fail closed."
}

function Write-Utf8([string] $Path, [string] $Value) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function New-TestNupkg([string] $Path, [string] $Nuspec) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $entries = [ordered]@{
                '[Content_Types].xml' = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types" />'
                '_rels/.rels' = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships" />'
                'package/services/metadata/core-properties/test.psmdcp' = '<coreProperties xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" />'
                'Test.Package.nuspec' = $Nuspec
            }
            foreach ($entry in $entries.GetEnumerator()) {
                $zipEntry = $archive.CreateEntry($entry.Key)
                $writer = [IO.StreamWriter]::new($zipEntry.Open(), [Text.UTF8Encoding]::new($false))
                try { $writer.Write($entry.Value) } finally { $writer.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Invoke-Git([string] $Repository, [string[]] $Arguments) {
    & git -C $Repository @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fixture git command failed: $($Arguments -join ' ')" }
}

function Assert-ExactPolicy([Collections.IDictionary] $Policy) {
    $expected = [ordered]@{
        'Deep.Protocol' = [ordered]@{ project = 'src/Deep.Protocol/Deep.Protocol.csproj'; packages = @('Sodium.Core=[1.4.1]'); projects = @(); targets = @(
            'lib/net10.0/Deep.Protocol.dll',
            'lib/net10.0/Deep.Protocol.pdb',
            'runtimes/android-arm64/native/libdeep_mlkem.so',
            'runtimes/android-arm64/native/libdeep_mlkem_braid.so',
            'runtimes/win-arm64/native/deep_mlkem.dll',
            'runtimes/win-arm64/native/deep_mlkem_braid.dll',
            'runtimes/win-x64/native/deep_mlkem.dll',
            'runtimes/win-x64/native/deep_mlkem_braid.dll') }
        'Deep.Protocol.MembershipRoutes' = [ordered]@{ project = 'src/Deep.Protocol.MembershipRoutes/Deep.Protocol.MembershipRoutes.csproj'; packages = @(); projects = @('Deep.Protocol'); targets = @('lib/net10.0/Deep.Protocol.MembershipRoutes.dll', 'lib/net10.0/Deep.Protocol.MembershipRoutes.pdb') }
        'Deep.Protocol.ProfileCarrier' = [ordered]@{ project = 'src/Deep.Protocol.ProfileCarrier/Deep.Protocol.ProfileCarrier.csproj'; packages = @('libsodium=[1.0.22]', 'Sodium.Core=[1.4.1]'); projects = @('Deep.Protocol'); targets = @('lib/net10.0/Deep.Protocol.ProfileCarrier.dll', 'lib/net10.0/Deep.Protocol.ProfileCarrier.pdb', 'README.md') }
    }
    if ($Policy.repositoryUrl -cne 'https://github.com/XPointLabs/deep-protocol.git' -or $Policy.repositoryType -cne 'git' -or $Policy.packages.Count -ne 3) {
        throw 'Policy repository identity or exact-three package count drifted.'
    }
    foreach ($id in $expected.Keys) {
        $package = Get-PolicyPackage $Policy $id
        if ($package.project -cne $expected[$id].project -or
            (@($package.packageReferences | ForEach-Object { "{0}={1}" -f $_.id, $_.version }) -join "`n") -cne (@($expected[$id].packages) -join "`n") -or
            (@($package.projectReferences) -join "`n") -cne (@($expected[$id].projects) -join "`n") -or
            (@($package.packTargets) -join "`n") -cne (@($expected[$id].targets) -join "`n")) {
            throw "Exact policy contract drifted for $id."
        }
    }
}

$materializerText = Get-Content -Raw -LiteralPath $materializerPath
$normalizerText = Get-Content -Raw -LiteralPath $normalizerPath
$commonText = Get-Content -Raw -LiteralPath $commonPath
foreach ($required in @('Assert-TrackedTreeNoReparse', 'git-cat-file-batch', 'New-ExactGitSnapshot', 'Get-EvaluatedProjectContract', 'Assert-HermeticEvaluatedInputClosure', 'Invoke-HermeticAuditedTarget', 'Get-LockedGraph', 'Invoke-LockedRestoreValidation', 'Move-PublishedStage', 'Move-StageToQuarantine', 'Remove-VerifiedPrivateDirectory', 'PublishRepositoryUrl=true', 'RepositoryCommit', 'ImportDirectoryBuildTargets=false', 'inventorySha512', 'repositoryUrl = $archivedPolicy.repositoryUrl', 'independentRandomRootBuilds', 'outOfScope', 'exactly three nupkg')) {
    if (($materializerText + $commonText).IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Materializer lost required mechanism: $required" }
}
if ($materializerText -match '-p:RepositoryType=') { throw 'Materializer must not self-fulfill RepositoryType during verification or build.' }
foreach ($forbidden in @('$HOME', '$env:HOME', '$CODEX_HOME', '$env:CODEX_HOME', 'git push', 'nuget push', 'nuget add source', '[string] $RepositoryUrl', 'remote', 'get-url', 'origin')) {
    if ($materializerText.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw "Materializer contains forbidden override/external-state mechanism: $forbidden" }
}
if ($normalizerText -match 'Set-Acl|Directory\]::Delete|Move-PrivateStage|LocalApplicationData') {
    throw 'Normalizer regained staging ACL/cleanup responsibilities.'
}

$root = Join-Path ([IO.Path]::GetTempPath()) "deep-protocol-closure-hostile-$([Guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($root) | Out-Null
$reparsePath = $null
try {
    $policy = Read-ClosurePolicy $policyPath $schemaPath
    Assert-ExactPolicy $policy
    foreach ($package in $policy.packages) {
        $project = Join-Path $RepositoryRoot $package.project
        $repositoryType = (& dotnet msbuild $project -nologo -verbosity:quiet '-getProperty:RepositoryType' 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or ($repositoryType -cne 'git' -and $repositoryType -notmatch '"RepositoryType"\s*:\s*"git"')) {
            throw "Source project RepositoryType does not MSBuild-evaluate to git: $($package.id): $repositoryType"
        }
        [void] (Get-EvaluatedProjectContract $RepositoryRoot $policy $package '1.2.3-test')
    }

    $mutatedPolicyPath = Join-Path $root 'mutated.policy.json'
    $mutatedPolicy = Get-Content -Raw -LiteralPath $policyPath | ConvertFrom-Json -AsHashtable
    $mutatedPolicy['unexpected'] = $true
    Write-Utf8 $mutatedPolicyPath ($mutatedPolicy | ConvertTo-Json -Depth 12)
    Assert-Rejects { Read-ClosurePolicy $mutatedPolicyPath $schemaPath | Out-Null } 'policy additional property' 'complete tracked JSON schema'
    $duplicatePolicyPath = Join-Path $root 'duplicate.policy.json'
    $policyText = Get-Content -Raw -LiteralPath $policyPath
    Write-Utf8 $duplicatePolicyPath $policyText.Replace(
        '"schema": "deep-production-protocol-closure-policy/v1",',
        '"schema": "deep-production-protocol-closure-policy/v1","schema":"deep-production-protocol-closure-policy/v1",')
    Assert-Rejects { Read-ClosurePolicy $duplicatePolicyPath $schemaPath | Out-Null } 'duplicate policy JSON property' 'duplicate JSON property'

    $mutatedSchemaPath = Join-Path $root 'mutated.schema.json'
    $mutatedSchema = Get-Content -Raw -LiteralPath $schemaPath | ConvertFrom-Json -AsHashtable
    $mutatedSchema.additionalProperties = $true
    Write-Utf8 $mutatedSchemaPath ($mutatedSchema | ConvertTo-Json -Depth 20)
    Assert-Rejects { Read-ClosurePolicy $policyPath $mutatedSchemaPath | Out-Null } 'schema loses additionalProperties false' 'strict exact-three'

    $gitFixture = Join-Path $root 'git-fixture'
    [IO.Directory]::CreateDirectory((Join-Path $gitFixture 'tracked')) | Out-Null
    Write-Utf8 (Join-Path $gitFixture 'tracked/child.txt') 'tracked'
    & git init -q $gitFixture
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize hostile git fixture.' }
    Invoke-Git $gitFixture @('config', 'user.email', 'closure-test@example.invalid')
    Invoke-Git $gitFixture @('config', 'user.name', 'Closure Test')
    Invoke-Git $gitFixture @('add', 'tracked/child.txt')
    Invoke-Git $gitFixture @('commit', '-q', '-m', 'fixture')
    $fixtureHead = Get-CheckedGitText $gitFixture @('rev-parse', 'HEAD') 'fixture HEAD'
    $trackedDirectory = Join-Path $gitFixture 'tracked'
    $reparseTarget = Join-Path $gitFixture 'reparse-target'
    [IO.Directory]::Move($trackedDirectory, $reparseTarget)
    if ($script:IsWindowsPlatform) {
        New-Item -ItemType Junction -Path $trackedDirectory -Target $reparseTarget | Out-Null
    }
    else {
        New-Item -ItemType SymbolicLink -Path $trackedDirectory -Target $reparseTarget | Out-Null
    }
    $reparsePath = $trackedDirectory
    Assert-Rejects { Assert-TrackedTreeNoReparse $gitFixture $fixtureHead | Out-Null } 'tracked descendant reparse point' 'reparse point'
    Remove-Item -LiteralPath $reparsePath -Force
    $reparsePath = $null

    $symlinkFixture = Join-Path $root 'symlink-mode-fixture'
    [IO.Directory]::CreateDirectory($symlinkFixture) | Out-Null
    Write-Utf8 (Join-Path $symlinkFixture 'target.txt') 'target'
    Write-Utf8 (Join-Path $symlinkFixture 'link') 'target.txt'
    & git init -q $symlinkFixture
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize symlink-mode fixture.' }
    Invoke-Git $symlinkFixture @('config', 'user.email', 'closure-test@example.invalid')
    Invoke-Git $symlinkFixture @('config', 'user.name', 'Closure Test')
    Invoke-Git $symlinkFixture @('config', 'core.symlinks', 'false')
    Invoke-Git $symlinkFixture @('add', 'target.txt', 'link')
    $linkBlob = (& git -C $symlinkFixture hash-object link | Out-String).Trim()
    Invoke-Git $symlinkFixture @('update-index', '--add', '--cacheinfo', "120000,$linkBlob,link")
    Invoke-Git $symlinkFixture @('commit', '-q', '-m', 'symlink fixture')
    $symlinkHead = Get-CheckedGitText $symlinkFixture @('rev-parse', 'HEAD') 'symlink fixture HEAD'
    Assert-Rejects { Get-GitTreeEntries $symlinkFixture $symlinkHead | Out-Null } 'Git symlink mode 120000' 'unsupported non-regular Git mode 120000'

    $exportFixture = Join-Path $root 'raw-blob-fixture'
    [IO.Directory]::CreateDirectory($exportFixture) | Out-Null
    Write-Utf8 (Join-Path $exportFixture '.gitattributes') '*.txt export-subst'
    Write-Utf8 (Join-Path $exportFixture 'payload.txt') '$Format:%H$'
    & git init -q $exportFixture
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize export-subst fixture.' }
    Invoke-Git $exportFixture @('config', 'user.email', 'closure-test@example.invalid')
    Invoke-Git $exportFixture @('config', 'user.name', 'Closure Test')
    Invoke-Git $exportFixture @('add', '.gitattributes', 'payload.txt')
    Invoke-Git $exportFixture @('commit', '-q', '-m', 'export fixture')
    $exportHead = Get-CheckedGitText $exportFixture @('rev-parse', 'HEAD') 'export fixture HEAD'
    Invoke-Git $exportFixture @('config', 'core.autocrlf', 'true')
    $exportEntries = @(Get-GitTreeEntries $exportFixture $exportHead)
    $exportArchive = Join-Path $root 'export-subst.zip'
    Invoke-Git $exportFixture @('archive', '--format=zip', "--output=$exportArchive", $exportHead)
    $exportExtracted = Join-Path $root 'export-subst-extracted'
    [IO.Directory]::CreateDirectory($exportExtracted) | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory($exportArchive, $exportExtracted)
    Assert-Rejects { Get-ExactGitSnapshotManifest $exportExtracted $exportEntries | Out-Null } 'git archive export-subst byte transformation' 'archive export transformation is forbidden'
    $rawExtracted = Join-Path $root 'raw-blob-extracted'
    $rawManifest = New-ExactGitSnapshot $exportFixture $exportHead $rawExtracted $exportEntries
    if ($rawManifest.transport -cne 'git-cat-file-batch' -or $rawManifest.fileCount -ne $exportEntries.Count) {
        throw 'Raw Git snapshot did not preserve the complete exact-blob fixture.'
    }

    $eolFixture = Join-Path $root 'eol-policy-fixture'
    Write-Utf8 (Join-Path $eolFixture '.gitattributes') "*.json text`n"
    Write-Utf8 (Join-Path $eolFixture '.hidden/nested.txt') 'hidden tracked input'
    foreach ($name in @($script:ClosurePolicyFileName, $script:ClosurePolicySchemaFileName)) {
        Write-Utf8 (Join-Path $eolFixture "eng/$name") ([IO.File]::ReadAllText((Join-Path $RepositoryRoot "eng/$name")).Replace("`r`n", "`n"))
    }
    & git init -q $eolFixture
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize EOL fixture.' }
    Invoke-Git $eolFixture @('config', 'user.email', 'closure-test@example.invalid')
    Invoke-Git $eolFixture @('config', 'user.name', 'Closure Test')
    Invoke-Git $eolFixture @('config', 'core.autocrlf', 'false')
    Invoke-Git $eolFixture @('add', '.')
    Invoke-Git $eolFixture @('commit', '-q', '-m', 'LF policy fixture')
    $eolHead = Get-CheckedGitText $eolFixture @('rev-parse', 'HEAD') 'EOL fixture HEAD'
    $eolCheckout = Join-Path $root 'clean-crlf-checkout'
    & git clone --quiet --no-local -c core.autocrlf=true $eolFixture $eolCheckout
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create clean CRLF clone.' }
    $eolFixture = $eolCheckout
    $eolStatus = Get-CheckedGitText $eolFixture @('status', '--porcelain=v1', '--untracked-files=all') 'EOL clean check'
    if (-not [string]::IsNullOrWhiteSpace($eolStatus)) {
        $eolDetails = Get-CheckedGitText $eolFixture @('diff', '--numstat') 'EOL diff diagnostic'
        $eolKinds = Get-CheckedGitText $eolFixture @('ls-files', '--eol') 'EOL diagnostic'
        throw "CRLF fixture is not clean: $eolStatus; $eolDetails; $eolKinds"
    }
    $eolEntries = @(Assert-TrackedTreeNoReparse $eolFixture $eolHead)
    $eolSnapshot = Join-Path $root 'eol-policy-snapshot'
    $eolManifest = New-ExactGitSnapshot $eolFixture $eolHead $eolSnapshot $eolEntries
    $eolPolicy = Read-ExactSnapshotPolicy $eolSnapshot $eolEntries
    foreach ($pair in @(@($script:ClosurePolicyFileName, 'policySha256'), @($script:ClosurePolicySchemaFileName, 'schemaSha256'))) {
        $checkout = Join-Path $eolFixture "eng/$($pair[0])"
        $snapshotFile = Join-Path $eolSnapshot "eng/$($pair[0])"
        if (-not [IO.File]::ReadAllText($checkout).Contains("`r`n") -or [IO.File]::ReadAllText($snapshotFile).Contains("`r") -or
            (Get-FileDigest $checkout) -ceq $eolPolicy[$pair[1]] -or (Get-FileDigest $snapshotFile) -cne $eolPolicy[$pair[1]]) {
            throw 'Exact policy trust/hash was not independent of clean CRLF checkout bytes.'
        }
    }
    if ($script:IsWindowsPlatform) {
        $hiddenDirectory = Join-Path $eolSnapshot '.hidden'
        [IO.File]::SetAttributes($hiddenDirectory, ([IO.File]::GetAttributes($hiddenDirectory) -bor [IO.FileAttributes]::Hidden))
    }
    $hiddenManifest = Get-ExactGitSnapshotManifest $eolSnapshot $eolEntries
    if ($eolManifest.fileCount -ne 4 -or $hiddenManifest.fileCount -ne 4) { throw 'Dotfile/hidden tracked subtree was lost.' }
    [IO.File]::Copy((Join-Path $eolFixture "eng/$script:ClosurePolicyFileName"), (Join-Path $eolSnapshot "eng/$script:ClosurePolicyFileName"), $true)
    Assert-Rejects { Read-ExactSnapshotPolicy $eolSnapshot $eolEntries | Out-Null } 'policy snapshot substitution' 'Policy bytes differ from exact Git blob'

    $caseRoot = Join-Path $root 'case-root'
    $caseSibling = Join-Path $root 'CASE-ROOT/outside.cs'
    if ((Test-PathWithin $caseSibling $caseRoot) -ne $script:IsWindowsPlatform -or
        (Test-PathWithin (Join-Path $root 'case-root-sibling/outside.cs') $caseRoot)) { throw 'OS-specific path boundary is incorrect.' }
    if (-not $script:IsWindowsPlatform) {
        Write-Utf8 $caseSibling 'case-distinct Unix sibling'
        [IO.Directory]::CreateDirectory($caseRoot) | Out-Null
        if (Test-PathWithin $caseSibling $caseRoot) { throw 'Case-distinct Unix sibling escaped the boundary.' }
    }

    $workspaceFixture = Join-Path $root 'workspace-inventory-fixture'
    [IO.Directory]::CreateDirectory($workspaceFixture) | Out-Null
    Write-Utf8 (Join-Path $workspaceFixture '.gitignore') 'ignored/'
    Write-Utf8 (Join-Path $workspaceFixture 'modified.txt') 'committed'
    Write-Utf8 (Join-Path $workspaceFixture 'deleted.txt') 'delete-me'
    & git init -q $workspaceFixture
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize workspace-inventory fixture.' }
    Invoke-Git $workspaceFixture @('config', 'user.email', 'closure-test@example.invalid')
    Invoke-Git $workspaceFixture @('config', 'user.name', 'Closure Test')
    Invoke-Git $workspaceFixture @('add', '.gitignore', 'modified.txt', 'deleted.txt')
    Invoke-Git $workspaceFixture @('commit', '-q', '-m', 'workspace fixture')
    Write-Utf8 (Join-Path $workspaceFixture 'modified.txt') 'working-copy-bytes'
    [IO.File]::Delete((Join-Path $workspaceFixture 'deleted.txt'))
    Write-Utf8 (Join-Path $workspaceFixture 'untracked.txt') 'untracked-bytes'
    [IO.Directory]::CreateDirectory((Join-Path $workspaceFixture 'ignored')) | Out-Null
    Write-Utf8 (Join-Path $workspaceFixture 'ignored/debris.txt') 'ignored'
    $workspaceEntries = @(Get-CanonicalWorkspaceEntries $workspaceFixture)
    $workspaceSnapshot = Join-Path $root 'workspace-inventory-snapshot'
    $workspaceManifest = Copy-CanonicalWorkspaceSnapshot $workspaceFixture $workspaceSnapshot $workspaceEntries
    if ($workspaceManifest.fileCount -ne 3 -or
        [IO.File]::ReadAllText((Join-Path $workspaceSnapshot 'modified.txt')) -cne 'working-copy-bytes' -or
        [IO.File]::ReadAllText((Join-Path $workspaceSnapshot 'untracked.txt')) -cne 'untracked-bytes' -or
        (Test-Path -LiteralPath (Join-Path $workspaceSnapshot 'deleted.txt')) -or
        (Test-Path -LiteralPath (Join-Path $workspaceSnapshot 'ignored/debris.txt'))) {
        throw 'Canonical current-workspace snapshot omitted or rewrote tracked/untracked/deleted/ignored state.'
    }

    $ambientParent = Join-Path $root 'ambient-parent'
    $sourceFixture = Join-Path $ambientParent 'source-fixture'
    $projectDirectory = Join-Path $sourceFixture 'src/Deep.Protocol'
    [IO.Directory]::CreateDirectory($projectDirectory) | Out-Null
    $projectPath = Join-Path $projectDirectory 'Deep.Protocol.csproj'
    $baseProject = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><RepositoryType>git</RepositoryType></PropertyGroup><ItemGroup><PackageReference Include="Sodium.Core" Version="[1.4.1]" /></ItemGroup></Project>'
    Write-Utf8 $projectPath $baseProject
    $fixtureEng = Join-Path $sourceFixture 'eng'
    [IO.Directory]::CreateDirectory($fixtureEng) | Out-Null
    [IO.File]::Copy($auditTargetsPath, (Join-Path $fixtureEng 'ProductionProtocolClosure.InputAudit.targets'), $false)
    [void] (Get-EvaluatedProjectContract $sourceFixture $policy (Get-PolicyPackage $policy 'Deep.Protocol') '1.2.3-test')
    Write-Utf8 $projectPath $baseProject.Replace('<RepositoryType>git</RepositoryType>', '')
    Assert-Rejects { Get-EvaluatedProjectContract $sourceFixture $policy (Get-PolicyPackage $policy 'Deep.Protocol') '1.2.3-test' | Out-Null } 'project omits intrinsic RepositoryType' 'RepositoryType differs'
    Write-Utf8 $projectPath $baseProject
    Write-Utf8 $projectPath $baseProject.Replace('</ItemGroup>', '<PackageReference Include="Injected.Direct" Version="9.9.9" /></ItemGroup>')
    Assert-Rejects { Get-EvaluatedProjectContract $sourceFixture $policy (Get-PolicyPackage $policy 'Deep.Protocol') '1.2.3-test' | Out-Null } 'extra direct PackageReference' 'Evaluated direct PackageReference'
    Write-Utf8 $projectPath $baseProject.Replace('Version="[1.4.1]"', 'Version="[1.4.2]"')
    Assert-Rejects { Get-EvaluatedProjectContract $sourceFixture $policy (Get-PolicyPackage $policy 'Deep.Protocol') '1.2.3-test' | Out-Null } 'direct PackageReference exact constraint drift' 'Evaluated direct PackageReference'
    Write-Utf8 $projectPath $baseProject
    $ambientSentinel = Join-Path $ambientParent 'ambient-target-ran.txt'
    Write-Utf8 (Join-Path $ambientParent 'Directory.Build.targets') @"
<Project>
  <PropertyGroup><TargetPath>$ambientSentinel</TargetPath></PropertyGroup>
  <ItemGroup><PackageReference Include="Injected.FromAmbientParent" Version="9.9.9" /></ItemGroup>
  <Target Name="ReplaceClosureOutput" BeforeTargets="Build"><WriteLinesToFile File="$ambientSentinel" Lines="ambient target executed" Overwrite="true" /></Target>
</Project>
"@
    [void] (Get-EvaluatedProjectContract $sourceFixture $policy (Get-PolicyPackage $policy 'Deep.Protocol') '1.2.3-test')
    if (Test-Path -LiteralPath $ambientSentinel) { throw 'Hostile ambient Directory.Build.targets executed.' }
    $fixturePackage = Get-PolicyPackage $policy 'Deep.Protocol'
    $lockPath = Join-Path $sourceFixture $fixturePackage.lockFile
    [IO.File]::Copy((Join-Path $RepositoryRoot $fixturePackage.lockFile), $lockPath, $true)
    $fixtureConfig = Join-Path $sourceFixture 'eng/production-protocol-closure.NuGet.Config'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $fixtureConfig)) | Out-Null
    [IO.File]::Copy($nugetConfigPath, $fixtureConfig, $true)
    $fixtureProperties = @(Get-HermeticMsBuildProperties $sourceFixture $fixturePackage '1.2.3-test' $policy ('0' * 40))
    Invoke-Checked dotnet (@('restore', $projectPath, '--locked-mode', '--configfile', $fixtureConfig) + $fixtureProperties) 'hostile-parent hermetic restore' | Out-Null
    Assert-HermeticEvaluatedInputClosure $sourceFixture $policy $fixturePackage '1.2.3-test' ('0' * 40)
    Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.3-test' ('0' * 40) Build
    if ((Test-Path -LiteralPath $ambientSentinel) -or
        -not (Test-Path -LiteralPath (Join-Path $projectDirectory 'bin/Release/net10.0/Deep.Protocol.dll') -PathType Leaf)) {
        throw 'Hostile ambient Directory.Build.targets replaced or intercepted hermetic output.'
    }

    $selectedSdk = Get-SelectedDotNetSdkContract
    $hostileSdks = Join-Path $root 'hostile-ambient-sdks'
    $hostileSdk = Join-Path $hostileSdks 'Microsoft.NET.Sdk/Sdk'
    [IO.Directory]::CreateDirectory($hostileSdk) | Out-Null
    $hostileSdkSentinel = Join-Path $root 'hostile-sdk-ran.txt'
    $hostileProps = '<Project><Import Project="' + (Join-Path $selectedSdk.SdksPath 'Microsoft.NET.Sdk/Sdk/Sdk.props') + '" /></Project>'
    $hostileTargets = '<Project><Import Project="' + (Join-Path $selectedSdk.SdksPath 'Microsoft.NET.Sdk/Sdk/Sdk.targets') + '" /><Target Name="HostileAmbientSdkTarget" BeforeTargets="Build"><WriteLinesToFile File="' + $hostileSdkSentinel + '" Lines="hostile sdk ran" Overwrite="true" /></Target></Project>'
    Write-Utf8 (Join-Path $hostileSdk 'Sdk.props') $hostileProps
    Write-Utf8 (Join-Path $hostileSdk 'Sdk.targets') $hostileTargets
    $previousSdkPath = [Environment]::GetEnvironmentVariable('MSBuildSDKsPath', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('MSBuildSDKsPath', $hostileSdks, 'Process')
        Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.4-test' ('0' * 40) Build
    }
    finally { [Environment]::SetEnvironmentVariable('MSBuildSDKsPath', $previousSdkPath, 'Process') }
    if (Test-Path -LiteralPath $hostileSdkSentinel) { throw 'Ambient MSBuildSDKsPath overrode the pinned exact SDK.' }

    $outsideReference = Join-Path $ambientParent 'external-reference.dll'
    [IO.File]::Copy((Join-Path $selectedSdk.SdkRoot 'Microsoft.Build.Framework.dll'), $outsideReference)
    $outsideResource = Join-Path $ambientParent 'external-resource.bin'
    Write-Utf8 $outsideResource 'not an approved resource'
    $outsideSource = Join-Path $ambientParent 'response-source.cs'
    Write-Utf8 $outsideSource '#error external response-file source was compiled'
    $innerResponse = Join-Path $ambientParent 'inner.rsp'
    $outerResponse = Join-Path $ambientParent 'outer.rsp'
    Write-Utf8 $innerResponse ('"' + $outsideSource + '" /reference:"' + $outsideReference + '" /resource:"' + $outsideResource + '",Hostile.External')
    Write-Utf8 $outerResponse ('@"' + $innerResponse + '"')
    $previousCompilerEnvironment = @{}
    $hostileCompilerEnvironment = @{ CompilerResponseFile = $outerResponse; CscToolPath = $ambientParent; CscToolExe = 'missing-hostile-compiler.exe' }
    try {
        foreach ($name in $hostileCompilerEnvironment.Keys) {
            $previousCompilerEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $hostileCompilerEnvironment[$name], 'Process')
        }
        # Real build must succeed: the external #error source, reference and
        # embedded resource, and the nonexistent compiler, must never enter.
        Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.6-test' ('0' * 40) Build
    }
    finally { foreach ($name in $previousCompilerEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $previousCompilerEnvironment[$name], 'Process') } }
    $fixtureAssembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes((Join-Path $projectDirectory 'bin/Release/net10.0/Deep.Protocol.dll')))
    if ($fixtureAssembly.GetManifestResourceNames() -contains 'Hostile.External' -or $fixtureAssembly.GetReferencedAssemblies().Name -contains 'Microsoft.Build.Framework') {
        throw 'Response-file reference/resource entered the actual assembly.'
    }
    $compilerPrefix = '"' + (Get-Command dotnet).Source + '" exec "' + (Join-Path $selectedSdk.SdkRoot 'Roslyn/bincore/csc.dll') + '" /noconfig /nostdlib+ '
    foreach ($response in @($innerResponse, $outerResponse)) {
        Assert-Rejects { Assert-CompilerCommand ($compilerPrefix + '@"' + $response + '"') $projectPath $sourceFixture } 'direct/nested actual response file' 'response files'
    }
    foreach ($argument in @(('"' + $outsideSource + '"'), ('/reference:"' + $outsideReference + '"'), ('/resource:"' + $outsideResource + '",Hostile.External'))) {
        Assert-Rejects { Assert-CompilerCommand ($compilerPrefix + $argument) $projectPath $sourceFixture } 'actual command external source/reference/resource' 'escaped the audited roots'
    }
    $compilerOverrides = '<PropertyGroup><CompilerResponseFile>' + $outerResponse + '</CompilerResponseFile><CscToolPath>' + $ambientParent + '</CscToolPath><CscToolExe>missing-hostile-compiler.exe</CscToolExe></PropertyGroup>'
    Write-Utf8 $projectPath $baseProject.Replace('</Project>', ($compilerOverrides + '</Project>'))
    Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.7-test' ('0' * 40) Build
    Write-Utf8 $projectPath ($baseProject.Replace('<Project ', '<Project TreatAsLocalProperty="CompilerResponseFile;CscToolPath;CscToolExe" ').Replace('</Project>', ($compilerOverrides + '</Project>')))
    Assert-Rejects { Assert-HermeticEvaluatedInputClosure $sourceFixture $policy $fixturePackage '1.2.8-test' ('0' * 40) } 'evaluated locally overridden compiler properties' 'Evaluated compiler override differs'
    Assert-Rejects { Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.8-test' ('0' * 40) Build } 'locally overridden compiler properties' 'compiler overrides/response files are forbidden'
    Write-Utf8 $projectPath $baseProject
    foreach ($compilerPropertyName in @('CompilerResponseFile', 'CscToolPath', 'CscToolExe')) {
        Assert-Rejects { Invoke-PinnedDotNetText (@('msbuild', $projectPath) + $fixtureProperties + "-p:${compilerPropertyName}=hostile") 'duplicate compiler override' | Out-Null } 'duplicate compiler global override' 'exact compiler global pin'
    }

    foreach ($injectedInput in @(
        ('<ReferencePathWithRefAssemblies Include="' + $outsideReference + '" />'),
        ('<_CoreCompileResourceInputs Include="' + $outsideResource + '"><LogicalName>Hostile.External</LogicalName></_CoreCompileResourceInputs>'))) {
        $injection = '<Target Name="InjectExternalCompilerInput" BeforeTargets="CoreCompile"><ItemGroup>' + $injectedInput + '</ItemGroup></Target>'
        $injection += '<Target Name="EraseInjectedInputAfterCompile" AfterTargets="CoreCompile" BeforeTargets="_CaptureProductionProtocolActualCompilerInputs"><ItemGroup><ReferencePathWithRefAssemblies Remove="' + $outsideReference + '" /><_CoreCompileResourceInputs Remove="' + $outsideResource + '" /></ItemGroup></Target>'
        Write-Utf8 $projectPath $baseProject.Replace('</Project>', ($injection + '</Project>'))
        Assert-Rejects { Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.9-test' ('0' * 40) Build } 'real external reference/resource erased after compilation' 'Actual input escaped the audited roots'
    }
    Write-Utf8 $projectPath $baseProject

    # Positive pack mapping is anchored to outputs recorded immediately after
    # the real compiler audit; both ZIP substitution and post-build drift fail.
    Write-Utf8 $projectPath $baseProject.Replace('</PropertyGroup>', '<IncludeSymbols>false</IncludeSymbols><AllowedOutputExtensionsInPackageBuildOutputFolder>.dll;.pdb</AllowedOutputExtensionsInPackageBuildOutputFolder></PropertyGroup>')
    Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.3.0-test' ('0' * 40) Build
    $fixturePack = Join-Path $root 'fixture-pack'
    New-PrivateDirectoryAtomic $fixturePack
    Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.3.0-test' ('0' * 40) Pack $fixturePack
    $fixtureNupkg = Join-Path $fixturePack 'Deep.Protocol.1.3.0-test.nupkg'
    Assert-PackagePackTargets $fixtureNupkg $fixturePackage $sourceFixture
    foreach ($extension in @('dll', 'pdb')) {
        $substituted = Join-Path $fixturePack "substituted-$extension.nupkg"
        [IO.File]::Copy($fixtureNupkg, $substituted)
        $zip = [IO.Compression.ZipFile]::Open($substituted, [IO.Compression.ZipArchiveMode]::Update)
        try {
            $zipName = "lib/net10.0/Deep.Protocol.$extension"
            $zip.GetEntry($zipName).Delete()
            $writer = [IO.StreamWriter]::new($zip.CreateEntry($zipName).Open())
            try { $writer.Write('substituted build output') } finally { $writer.Dispose() }
        }
        finally { $zip.Dispose() }
        Assert-Rejects { Assert-PackagePackTargets $substituted $fixturePackage $sourceFixture } "package $extension substitution" 'Pack input bytes changed in package'
    }
    $buildDll = Join-Path $projectDirectory 'bin/Release/net10.0/Deep.Protocol.dll'
    $savedDll = [IO.File]::ReadAllBytes($buildDll)
    try {
        Write-Utf8 $buildDll 'changed after compiler audit'
        Assert-Rejects { Assert-PackagePackTargets $fixtureNupkg $fixturePackage $sourceFixture } 'post-audit build output substitution' 'Build output changed after compiler audit'
    }
    finally { [IO.File]::WriteAllBytes($buildDll, $savedDll) }
    Write-Utf8 $projectPath $baseProject

    $outsideGenerated = Join-Path $ambientParent 'outside-generated.cs'
    $injection = '<Target Name="InjectOutsideGeneratedCompile" BeforeTargets="CoreCompile"><WriteLinesToFile File="' + $outsideGenerated + '" Lines="namespace Hostile { internal static class Injected { internal const int Value = 7%3B } }" Overwrite="true" /><ItemGroup><Compile Include="' + $outsideGenerated + '" /></ItemGroup></Target>'
    Write-Utf8 $projectPath $baseProject.Replace('</Project>', ($injection + '</Project>'))
    Assert-Rejects {
        Invoke-HermeticAuditedTarget $sourceFixture $policy $fixturePackage '1.2.5-test' ('0' * 40) Build
    } 'post-target generated compile outside closure' 'actual input escaped'
    Write-Utf8 $projectPath $baseProject

    $canonicalHash = [Convert]::ToBase64String([byte[]]::new(64))
    $invalidHashLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"not-a-canonical-sha512","dependencies":{"libsodium":"[1.0.22, 1.0.23)"}},"libsodium":{"type":"Transitive","resolved":"1.0.22","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $invalidHashLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'invalid NuGet contentHash' 'canonical base64 SHA-512'

    $duplicateLock = @"
{"version":1,"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $duplicateLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'duplicate lock JSON property' 'duplicate JSON property'

    $extraDirectLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash","dependencies":{"libsodium":"[1.0.22, 1.0.23)"}},"Injected.Direct":{"type":"Direct","requested":"[9.9.9, 9.9.9]","resolved":"9.9.9","contentHash":"$canonicalHash"},"libsodium":{"type":"Transitive","resolved":"1.0.22","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $extraDirectLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'extra archived lock Direct entry' 'Direct entries differ'

    $unpinnedDirectLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, )","resolved":"1.4.1","contentHash":"$canonicalHash","dependencies":{"libsodium":"[1.0.22, 1.0.23)"}},"libsodium":{"type":"Transitive","resolved":"1.0.22","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $unpinnedDirectLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'non-exact direct lock constraint' 'resolved version differs'

    $wrongFrameworkLock = @"
{"version":1,"dependencies":{"net9.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $wrongFrameworkLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'wrong lock target framework' 'unsupported shape'

    $multipleFrameworkLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash"}},"net9.0":{}}}
"@
    Write-Utf8 $lockPath $multipleFrameworkLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'multiple lock target frameworks' 'unsupported shape'

    $malformedTransitiveRangeLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash","dependencies":{"libsodium":"[not-a-version, 1.0.23)"}},"libsodium":{"type":"Transitive","resolved":"1.0.22","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $malformedTransitiveRangeLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'malformed transitive NuGet range' 'lower bound is not a supported canonical NuGet version'

    $outOfRangeTransitiveLock = @"
{"version":1,"dependencies":{"net10.0":{"Sodium.Core":{"type":"Direct","requested":"[1.4.1, 1.4.1]","resolved":"1.4.1","contentHash":"$canonicalHash","dependencies":{"libsodium":"[1.0.23, )"}},"libsodium":{"type":"Transitive","resolved":"1.0.22","contentHash":"$canonicalHash"}}}}
"@
    Write-Utf8 $lockPath $outOfRangeTransitiveLock
    Assert-Rejects { Get-LockedGraph $sourceFixture (Get-PolicyPackage $policy 'Deep.Protocol') | Out-Null } 'out-of-range transitive NuGet dependency' 'below its NuGet range'

    $multiGroupPackage = Join-Path $root 'Test.Package.1.0.0.nupkg'
    New-TestNupkg $multiGroupPackage @'
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
<id>Test.Package</id><version>1.0.0</version><authors>test</authors><description>test</description>
<repository type="git" url="https://github.com/XPointLabs/deep-protocol.git" commit="0000000000000000000000000000000000000000" />
<dependencies><group targetFramework="net10.0"><dependency id="Sodium.Core" version="[1.4.1]" /></group><group targetFramework="net9.0" /></dependencies>
</metadata></package>
'@
    Assert-Rejects { Read-PackageMetadata $multiGroupPackage 'net10.0' | Out-Null } 'nuspec injected net9 dependency group' 'exactly one dependency group'

    foreach ($unixRequired in @('CreateDirectory($Path, $mode)', 'Get-UnixIdentity', '& id -u', "stat --format='%d:%i:%u'", "stat -f '%d:%i:%u'")) {
        if ($commonText.IndexOf($unixRequired, [StringComparison]::Ordinal) -lt 0) { throw "Unix private-stage contract lost: $unixRequired" }
    }
    foreach ($windowsRequired in @('New-WindowsPrivateAcl', 'SetAccessRuleProtection($true, $false)', 'Get-DirectoryIdentity', 'Assert-PrivateExclusiveDirectory')) {
        if ($commonText.IndexOf($windowsRequired, [StringComparison]::Ordinal) -lt 0) { throw "Windows private-stage contract lost: $windowsRequired" }
    }
    if ($normalizerText.IndexOf('New-PrivateDirectoryAtomic $outputRoot', [StringComparison]::Ordinal) -lt 0) {
        throw 'Normalizer output is no longer created as a private directory.'
    }
    $privateRoot = Join-Path $root 'private-root'
    New-PrivateDirectoryAtomic $privateRoot
    Assert-PrivateExclusiveDirectory $privateRoot 'Actual private directory test root'
    $privateRootIdentity = Get-DirectoryIdentity $privateRoot
    if ($script:IsWindowsPlatform) {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $explicitCurrentAllow = @((Get-Acl -LiteralPath $privateRoot).Access | Where-Object {
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $_.IsInherited -and
            (ConvertTo-SidValue $_.IdentityReference) -ceq $currentSid -and
            (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)
        })
        if ($explicitCurrentAllow.Count -ne 1) { throw 'Windows private-directory test did not create one explicit effective current-SID allow.' }
        $currentIdentity = [Security.Principal.SecurityIdentifier]::new($currentSid)
        $systemIdentity = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $inheritOnlyAcl = [Security.AccessControl.DirectorySecurity]::new()
        $inheritOnlyAcl.SetOwner($currentIdentity)
        $inheritOnlyAcl.SetAccessRuleProtection($true, $false)
        $inheritFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        [void] $inheritOnlyAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $systemIdentity, [Security.AccessControl.FileSystemRights]::FullControl, $inheritFlags,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        $inheritOnlyRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $currentIdentity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritFlags,
            [Security.AccessControl.PropagationFlags]::InheritOnly,
            [Security.AccessControl.AccessControlType]::Allow)
        [void] $inheritOnlyAcl.AddAccessRule($inheritOnlyRule)
        Assert-Rejects { Assert-WindowsPrivateAcl $inheritOnlyAcl 'InheritOnly ACL hostile fixture' } 'InheritOnly current SID is not effective on parent' 'explicit effective FullControl'
        $denyAcl = New-WindowsPrivateAcl
        $foreignSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333-4444')
        [void] $denyAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $foreignSid, [Security.AccessControl.FileSystemRights]::Read,
            [Security.AccessControl.InheritanceFlags]::None, [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Deny))
        Assert-Rejects { Assert-WindowsPrivateAcl $denyAcl 'Deny ACL hostile fixture' } 'explicit deny ACL is forbidden' 'ACL is not an explicit private'
    }
    else { [void] (Get-UnixIdentity $privateRoot) }

    $candidate = Join-Path $privateRoot 'candidate-publication'
    New-PrivateDirectoryAtomic $candidate
    Write-Utf8 (Join-Path $candidate 'artifact.txt') 'candidate'
    $candidateManifest = @(Get-DirectoryFileManifest $candidate)
    $publishedOutput = [PSCustomObject]@{
        Path = Join-Path $privateRoot 'published-output'
        Parent = $privateRoot
        ParentIdentity = $privateRootIdentity
    }
    Move-PublishedStage $candidate $publishedOutput $candidateManifest
    if (-not (Test-Path -LiteralPath (Join-Path $publishedOutput.Path 'artifact.txt') -PathType Leaf)) { throw 'Move-PublishedStage did not preserve candidate bytes.' }
    $publishedIdentity = Get-DirectoryIdentity $publishedOutput.Path
    Remove-VerifiedPrivateDirectory $publishedOutput.Path $publishedIdentity $privateRoot $privateRootIdentity 'Published-output safe cleanup test'

    $blockedCandidate = Join-Path $privateRoot 'blocked-candidate'
    New-PrivateDirectoryAtomic $blockedCandidate
    Write-Utf8 (Join-Path $blockedCandidate 'artifact.txt') 'blocked'
    $blockedManifest = @(Get-DirectoryFileManifest $blockedCandidate)
    $blockedOutput = [PSCustomObject]@{
        Path = Join-Path $privateRoot 'blocked-output'
        Parent = $privateRoot
        ParentIdentity = $privateRootIdentity
    }
    New-PrivateDirectoryAtomic $blockedOutput.Path
    Assert-Rejects { Move-PublishedStage $blockedCandidate $blockedOutput $blockedManifest } 'output appears before publication' 'OutputDirectory appeared before publication'
    $blockedCandidateIdentity = Get-DirectoryIdentity $blockedCandidate
    Remove-VerifiedPrivateDirectory $blockedCandidate $blockedCandidateIdentity $privateRoot $privateRootIdentity 'Blocked-candidate safe cleanup test'
    $blockedOutputIdentity = Get-DirectoryIdentity $blockedOutput.Path
    Remove-VerifiedPrivateDirectory $blockedOutput.Path $blockedOutputIdentity $privateRoot $privateRootIdentity 'Blocked-output safe cleanup test'

    $quarantineStage = New-PrivateClosureStage $privateRoot
    Write-Utf8 (Join-Path $quarantineStage.Path 'failed-work.txt') 'failed'
    $quarantine = Move-StageToQuarantine $quarantineStage
    if (-not (Test-Path -LiteralPath $quarantine -PathType Container)) { throw 'Move-StageToQuarantine did not produce a verified quarantine directory.' }
    $quarantineIdentity = Get-DirectoryIdentity $quarantine
    Assert-PrivateExclusiveDirectory $quarantine 'Quarantine actual directory test'
    Remove-VerifiedPrivateDirectory $quarantine $quarantineIdentity $privateRoot $privateRootIdentity 'Quarantine safe cleanup test'

    $hostileStage = New-PrivateClosureStage $privateRoot
    $hostileTarget = Join-Path $privateRoot 'hostile-target'
    New-PrivateDirectoryAtomic $hostileTarget
    $hostileLink = Join-Path $hostileStage.Path 'hostile-link'
    if ($script:IsWindowsPlatform) { New-Item -ItemType Junction -Path $hostileLink -Target $hostileTarget | Out-Null }
    else { New-Item -ItemType SymbolicLink -Path $hostileLink -Target $hostileTarget | Out-Null }
    Assert-Rejects { Remove-VerifiedStage $hostileStage } 'safe cleanup refuses a reparse descendant' 'reparse point'
    if (-not (Test-Path -LiteralPath $hostileStage.Path -PathType Container)) { throw 'Hostile stage was unexpectedly deleted.' }
    Remove-Item -LiteralPath $hostileLink -Force
    Remove-VerifiedStage $hostileStage
    $hostileTargetIdentity = Get-DirectoryIdentity $hostileTarget
    Remove-VerifiedPrivateDirectory $hostileTarget $hostileTargetIdentity $privateRoot $privateRootIdentity 'Hostile-target safe cleanup test'

    Write-Output 'PASS strict policy; clean CRLF/exact Git blobs/hidden files; actual Csc/tool/rsp/generated-input closure; DLL/PDB substitution; hostile dependency/reparse/range/hash; platform path/private-directory move/quarantine/cleanup contract'
}
finally {
    if ($null -ne $reparsePath -and (Test-Path -LiteralPath $reparsePath)) { Remove-Item -LiteralPath $reparsePath -Force }
    if (Test-Path -LiteralPath $root) {
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        $candidate = [IO.Path]::GetFullPath($root)
        if (-not $candidate.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($candidate).StartsWith('deep-protocol-closure-hostile-', [StringComparison]::Ordinal))) {
            throw "Unsafe hostile-test cleanup path: $candidate"
        }
        Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction Stop
    }
}
