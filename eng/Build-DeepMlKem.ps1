[CmdletBinding()]
param(
    [ValidateSet('windows-x64', 'windows-arm64', 'android-arm64')]
    [string[]]$BuildTarget = @('windows-x64', 'windows-arm64', 'android-arm64'),

    [string]$AndroidNdkRoot,

    [string]$OutputRoot,

    [string]$WindowsArm64AcceptancePath,

    [switch]$SkipReproducibilityCheck,

    [switch]$AllowDirtyDevelopmentBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$nativeRoot = Join-Path $repositoryRoot 'native\Deep.MlKem'
$buildRoot = Join-Path $nativeRoot 'out'
$provenancePath = Join-Path $nativeRoot 'vendor\mlkem-native.provenance.json'
$expectedProviderCommit = 'd1b2fe782888bdb761a50336012923180be7f502'
$expectedProviderTree = 'd9d581290ea1e6fa37462bfbc61b9b4266a2e9e5'
$expectedProviderIdentifier = 'mlkem-native/v2.0.0/portable-c/deep-abi-v1'
$expectedProvenanceSha256 = '0cf82b548b1a466b7b7d2a8c684e7b9ac3d4045bd489f33896262e5611844b1a'
$expectedVendoredFileCount = 34
$expectedVsInstallationVersion = '17.14.37614.0'
$expectedVcToolsVersion = '14.44.35207'
$expectedWindowsSdkVersion = '10.0.26100.0'
$expectedCmakeSha256 = 'b540efece9172930877dff0c9fedda7a69b0dd82446e0e8bba13372aac6c8ac8'
$expectedCtestSha256 = '1fe268c79c868a70e6d725ee8f1ad46ec8e21dc3915a74cff8d4d049bf79a0f0'
$expectedNinjaSha256 = '5020138b3757035df9dca9a2243624d5810ffa6ae24444bd95f752cbd1b89123'
$expectedVsDevCmdSha256 = 'c004278e64444bf3524360f960511b5ce7b1d0306910f08a4ebcf1c42ff9bd6d'
$expectedWindowsX64CompilerSha256 = '88c8344236a27a6e727e0a8edc49aaa2690bdc7a9464b9d18cc7abe70a9f1c0d'
$expectedWindowsX64LinkerSha256 = 'ca11e6c45debd34bf652dfe984c5360a531a005ed78bf72852330c9c2590cf0d'
$expectedWindowsX64LibrarianSha256 = '3d694c782f93e998fec5db0c2df78153565da23a028ee4618561fa0c33408489'
$expectedWindowsX64InspectorSha256 = '12a1cd87238bd66dfdb788b4fcdcb91ce4b3f81236aab12a7a29e5ae1d85af50'
$expectedDotnetSha256 = 'e890cbd860379a3a984b9f6f901207625159689afc07f43c8069206441ea8c31'
$expectedDotnetX64Sha256 = 'ab1b71fd3dd71062e074c9fab8312081a81b7f2b3e0327c48c4d249c8d1a3135'
$expectedNdkRevision = '28.2.13676358'
$expectedRuntimeExports = @(
    'deep_mlkem_v1_ciphertext_size',
    'deep_mlkem_v1_decapsulate',
    'deep_mlkem_v1_decapsulation_key_size',
    'deep_mlkem_v1_encapsulate',
    'deep_mlkem_v1_encapsulation_key_size',
    'deep_mlkem_v1_encapsulation_random_size',
    'deep_mlkem_v1_keygen_random_size',
    'deep_mlkem_v1_keypair_from_random',
    'deep_mlkem_v1_shared_secret_size',
    'deep_mlkem_v1_zero'
)
$targets = @($BuildTarget | Select-Object -Unique)

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $nativeRoot 'artifacts'
}
$repositoryFullForOutput = [IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\')
$outputFullForValidation = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
$approvedRepositoryOutput = [IO.Path]::GetFullPath((Join-Path $nativeRoot 'artifacts')).TrimEnd('\')
if ($outputFullForValidation.StartsWith(
        $repositoryFullForOutput + '\',
        [StringComparison]::OrdinalIgnoreCase) -and
    $outputFullForValidation -ine $approvedRepositoryOutput) {
    throw 'An in-repository ML-KEM OutputRoot must be exactly native/Deep.MlKem/artifacts.'
}

function Require-File {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is absent: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Require-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Required directory is absent: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Quote-CmdArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '""') + '"'
}

function Get-VsEnvironmentPrefix {
    param([Parameter(Mandatory = $true)][string]$Architecture)
    $sdkInclude = Join-Path $script:WindowsSdkRoot "Include\$($script:WindowsSdkVersion)"
    $sdkLib = Join-Path $script:WindowsSdkRoot "Lib\$($script:WindowsSdkVersion)"
    $sdkBin = Join-Path $script:WindowsSdkRoot "bin\$($script:WindowsSdkVersion)\x64"
    return 'call ' + (Quote-CmdArgument $script:VsDevCmd) +
        " -no_logo -host_arch=x64 -arch=$Architecture >nul && " +
        'set "WindowsSdkDir=' + $script:WindowsSdkRoot.TrimEnd('\') + '\" && ' +
        'set "WindowsSDKVersion=' + $script:WindowsSdkVersion + '\" && ' +
        'set "WindowsSDKLibVersion=' + $script:WindowsSdkVersion + '\" && ' +
        'set "UniversalCRTSdkDir=' + $script:WindowsSdkRoot.TrimEnd('\') + '\" && ' +
        'set "UCRTVersion=' + $script:WindowsSdkVersion + '" && ' +
        'set "INCLUDE=' + (Join-Path $sdkInclude 'ucrt') + ';' +
            (Join-Path $sdkInclude 'shared') + ';' +
            (Join-Path $sdkInclude 'um') + ';' +
            (Join-Path $sdkInclude 'winrt') + ';!INCLUDE!" && ' +
        'set "LIB=' + (Join-Path $sdkLib "ucrt\$Architecture") + ';' +
            (Join-Path $sdkLib "um\$Architecture") + ';!LIB!" && ' +
        'set "PATH=' + $sdkBin + ';C:\Windows\System32;C:\Windows;!PATH!" && '
}

function Get-FileEvidence {
    param([Parameter(Mandatory = $true)][string]$Path)
    $file = Get-Item -LiteralPath $Path
    return [ordered]@{
        path = $file.FullName
        fileVersion = $file.VersionInfo.FileVersion
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Assert-CleanBuildEnvironment {
    $variables = @(
        'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
        'CL', '_CL_', 'LINK', '_LINK_', 'CMAKE_TOOLCHAIN_FILE',
        'CMAKE_GENERATOR', 'CMAKE_PREFIX_PATH'
    )
    $present = @($variables | Where-Object {
        $value = [Environment]::GetEnvironmentVariable($_, 'Process')
        -not [string]::IsNullOrWhiteSpace($value)
    })
    if ($present.Count -ne 0) {
        throw "Refusing a non-normalized build environment. Clear: $($present -join ', ')"
    }
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $childFull = [System.IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe generated-path target outside '$Parent': $Child"
    }
}

function Get-RepositoryStatusExcludingOutput {
    $repositoryFull = [IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\')
    $outputFull = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
    if ($outputFull -ceq $repositoryFull) {
        throw 'The ML-KEM output root cannot be the source repository root.'
    }

    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @('-C', $repositoryRoot, 'status', '--porcelain=v1', '--untracked-files=all', '--', '.')) {
        $arguments.Add($argument)
    }
    $repositoryPrefix = $repositoryFull + '\'
    if ($outputFull.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $relativeOutput = [IO.Path]::GetRelativePath($repositoryFull, $outputFull).Replace('\', '/')
        $arguments.Add(":(exclude)$relativeOutput")
        $arguments.Add(":(exclude)$relativeOutput/**")
    }

    $status = @(& git @arguments)
    if ($LASTEXITCODE -ne 0) {
        throw 'Cannot resolve the source repository state for ML-KEM build evidence.'
    }
    return @($status)
}

function Get-BuildInputEvidence {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    return @($Paths | ForEach-Object {
            $fullPath = Require-File (Join-Path $repositoryRoot $_)
            [ordered]@{
                path = $_
                sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
}

function Assert-BuildInputsUnchanged {
    param(
        [Parameter(Mandatory = $true)][object[]]$Initial,
        [Parameter(Mandatory = $true)][object[]]$Current
    )
    if ($Initial.Count -ne $Current.Count) {
        throw 'The ML-KEM exact build-input closure changed while evidence was produced.'
    }
    for ($index = 0; $index -lt $Initial.Count; $index++) {
        if ([string]$Initial[$index].path -cne [string]$Current[$index].path -or
            [string]$Initial[$index].sha256 -cne [string]$Current[$index].sha256) {
            throw "ML-KEM build input changed while evidence was produced: $($Initial[$index].path)"
        }
    }
}

function Build-ManagedEvidenceProject {
    param(
        [Parameter(Mandatory = $true)][string]$Project,
        [Parameter(Mandatory = $true)][string]$AssemblyName,
        [Parameter(Mandatory = $true)][string]$ArtifactsDirectory
    )
    Assert-ChildPath -Parent $buildRoot -Child $ArtifactsDirectory
    if (Test-Path -LiteralPath $ArtifactsDirectory) {
        Remove-Item -LiteralPath $ArtifactsDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ArtifactsDirectory -Force | Out-Null
    Invoke-Checked -Command $script:DotnetPath -Arguments @(
        'restore', $Project, '--locked-mode', '-r', 'win-x64', '--artifacts-path', $ArtifactsDirectory)
    Invoke-Checked -Command $script:DotnetPath -Arguments @(
        'build', $Project, '-c', 'Release', '--no-restore', '-r', 'win-x64', '--artifacts-path', $ArtifactsDirectory)
    $binRoot = Require-Directory (Join-Path $ArtifactsDirectory 'bin')
    $matches = @(Get-ChildItem -LiteralPath $binRoot -Filter $AssemblyName -File -Recurse)
    if ($matches.Count -ne 1) {
        throw "Expected one isolated managed evidence assembly '$AssemblyName', found $($matches.Count)."
    }
    return $matches[0].FullName
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$VsArchitecture
    )

    if ([string]::IsNullOrWhiteSpace($VsArchitecture)) {
        $commandOutput = @(& $Command @Arguments 2>&1)
    }
    else {
        $argumentLine = ($Arguments | ForEach-Object { Quote-CmdArgument $_ }) -join ' '
        $commandLine = (Get-VsEnvironmentPrefix -Architecture $VsArchitecture) +
            (Quote-CmdArgument $Command) + ' ' + $argumentLine
        $commandOutput = @(& $env:ComSpec /d /v:on /c $commandLine 2>&1)
    }
    $exitCode = $LASTEXITCODE
    foreach ($line in $commandOutput) {
        Write-Host $line
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $Command $($Arguments -join ' ')"
    }
}

function Invoke-CapturedChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$VsArchitecture
    )

    if ([string]::IsNullOrWhiteSpace($VsArchitecture)) {
        $commandOutput = @(& $Command @Arguments 2>&1)
    }
    else {
        $argumentLine = ($Arguments | ForEach-Object { Quote-CmdArgument $_ }) -join ' '
        $commandLine = (Get-VsEnvironmentPrefix -Architecture $VsArchitecture) +
            (Quote-CmdArgument $Command) + ' ' + $argumentLine
        $commandOutput = @(& $env:ComSpec /d /v:on /c $commandLine 2>&1)
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command $($Arguments -join ' ')"
    }
    return @($commandOutput | ForEach-Object { [string]$_ })
}

function Get-WindowsEnvironmentEvidence {
    param([Parameter(Mandatory = $true)][string]$Architecture)
    $commandLine = (Get-VsEnvironmentPrefix -Architecture $Architecture) +
        '@echo __DEEP_CL__ && where cl.exe && ' +
        '@echo __DEEP_LINK__ && where link.exe && ' +
        '@echo __DEEP_LIB__ && where lib.exe && ' +
        '@echo __DEEP_DUMPBIN__ && where dumpbin.exe && ' +
        '@echo __DEEP_VALUES__ && ' +
        '@echo VC_TOOLS_VERSION=!VCToolsVersion! && ' +
        '@echo WINDOWS_SDK_VERSION=!WindowsSDKVersion! && ' +
        '@echo WINDOWS_SDK_DIR=!WindowsSdkDir!'
    $lines = @(& $env:ComSpec /d /v:on /c $commandLine)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect the VS2022 $Architecture environment."
    }
    $values = @{}
    $section = ''
    foreach ($line in $lines) {
        $cleanLine = $line.Trim()
        if ($cleanLine -ceq '__DEEP_CL__') { $section = 'CL_PATH'; continue }
        if ($cleanLine -ceq '__DEEP_LINK__') { $section = 'LINK_PATH'; continue }
        if ($cleanLine -ceq '__DEEP_LIB__') { $section = 'LIB_PATH'; continue }
        if ($cleanLine -ceq '__DEEP_DUMPBIN__') { $section = 'DUMPBIN_PATH'; continue }
        if ($cleanLine -ceq '__DEEP_VALUES__') { $section = ''; continue }
        if (-not [string]::IsNullOrWhiteSpace($section) -and -not $values.ContainsKey($section)) {
            $values[$section] = $cleanLine
            continue
        }
        $separator = $cleanLine.IndexOf('=')
        if ($separator -gt 0) {
            $values[$cleanLine.Substring(0, $separator)] = $cleanLine.Substring($separator + 1)
        }
    }
    foreach ($required in @('CL_PATH', 'LINK_PATH', 'LIB_PATH', 'DUMPBIN_PATH', 'VC_TOOLS_VERSION', 'WINDOWS_SDK_VERSION', 'WINDOWS_SDK_DIR')) {
        if (-not $values.ContainsKey($required) -or [string]::IsNullOrWhiteSpace($values[$required])) {
            throw "VS2022 environment evidence '$required' is absent for $Architecture."
        }
    }
    return [ordered]@{
        architecture = $Architecture
        vcToolsVersion = $values['VC_TOOLS_VERSION'].TrimEnd('\')
        windowsSdkVersion = $values['WINDOWS_SDK_VERSION'].TrimEnd('\')
        windowsSdkDirectory = $values['WINDOWS_SDK_DIR'].TrimEnd('\')
        compiler = Get-FileEvidence (Require-File $values['CL_PATH'])
        linker = Get-FileEvidence (Require-File $values['LINK_PATH'])
        librarian = Get-FileEvidence (Require-File $values['LIB_PATH'])
        symbolInspector = Get-FileEvidence (Require-File $values['DUMPBIN_PATH'])
    }
}

function Get-AndroidEnvironmentEvidence {
    param([Parameter(Mandatory = $true)][string]$NdkRoot)
    $bin = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
    $clang = Require-File (Join-Path $bin 'clang.exe')
    $linker = Require-File (Join-Path $bin 'ld.lld.exe')
    $archiver = Require-File (Join-Path $bin 'llvm-ar.exe')
    $symbolInspector = Require-File (Join-Path $bin 'llvm-nm.exe')
    $elfInspector = Require-File (Join-Path $bin 'llvm-readelf.exe')
    $clangVersion = (& $clang --version | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to query Android NDK clang.'
    }
    return [ordered]@{
        ndkRevision = $expectedNdkRevision
        ndkRoot = $NdkRoot
        apiLevel = 28
        abi = 'arm64-v8a'
        compilerVersion = $clangVersion
        compiler = Get-FileEvidence $clang
        linker = Get-FileEvidence $linker
        archiver = Get-FileEvidence $archiver
        symbolInspector = Get-FileEvidence $symbolInspector
        elfInspector = Get-FileEvidence $elfInspector
    }
}

function Assert-ExactExports {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [string]$VsArchitecture
    )

    if ($Target -like 'windows-*') {
        $lines = Invoke-CapturedChecked -Command $script:WindowsSymbolInspector -Arguments @('/nologo', '/exports', $RuntimePath) -VsArchitecture $VsArchitecture
        $actual = @($lines | ForEach-Object {
                if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$') { $Matches[1] }
            } | Sort-Object -Unique)
    }
    else {
        $lines = Invoke-CapturedChecked -Command $script:AndroidSymbolInspector -Arguments @('--dynamic', '--defined-only', '--extern-only', $RuntimePath)
        $actual = @($lines | ForEach-Object {
                if ($_ -match '^\s*[0-9A-Fa-f]+\s+[A-Za-z]\s+(\S+)\s*$') { $Matches[1] }
            } | Sort-Object -Unique)
    }
    $expected = @($expectedRuntimeExports | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "Runtime export surface mismatch for $Target. Expected [$($expected -join ', ')], actual [$($actual -join ', ')]."
    }
}

function Assert-WindowsImports {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [Parameter(Mandatory = $true)][string]$VsArchitecture
    )
    $lines = Invoke-CapturedChecked -Command $script:WindowsSymbolInspector `
        -Arguments @('/nologo', '/dependents', $RuntimePath) -VsArchitecture $VsArchitecture
    $actual = @($lines | ForEach-Object {
            if ($_ -match '^\s+([A-Za-z0-9_.-]+[.]dll)\s*$') { $Matches[1].ToUpperInvariant() }
        } | Sort-Object -Unique)
    $expected = @('KERNEL32.DLL')
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "Final Windows runtime dependency mismatch. Expected [$($expected -join ', ')], actual [$($actual -join ', ')]."
    }
}

function Assert-FinalRuntimeHardening {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [string]$VsArchitecture
    )

    if ($Target -like 'windows-*') {
        $headers = (Invoke-CapturedChecked -Command $script:WindowsSymbolInspector -Arguments @('/nologo', '/headers', $RuntimePath) -VsArchitecture $VsArchitecture) -join "`n"
        foreach ($required in @('Dynamic base', 'NX compatible', 'High Entropy Virtual Addresses', 'Control Flow Guard')) {
            if ($headers -notmatch [regex]::Escape($required)) {
                throw "Final Windows runtime lacks required PE hardening marker '$required'."
            }
        }
        $loadConfig = (Invoke-CapturedChecked -Command $script:WindowsSymbolInspector -Arguments @('/nologo', '/loadconfig', $RuntimePath) -VsArchitecture $VsArchitecture) -join "`n"
        if ($loadConfig -notmatch '(?m)^\s+[1-9A-Fa-f][0-9A-Fa-f]* Guard CF function count\s*$') {
            throw 'Final Windows runtime lacks a non-empty CFG function table.'
        }
        Assert-WindowsImports -RuntimePath $RuntimePath -VsArchitecture $VsArchitecture
    }
    else {
        $elf = (Invoke-CapturedChecked -Command $script:AndroidElfInspector -Arguments @('--program-headers', '--dynamic', $RuntimePath)) -join "`n"
        if ($elf -notmatch 'GNU_RELRO' -or $elf -notmatch '(BIND_NOW|NOW)') {
            throw 'Final Android runtime lacks full RELRO/NOW evidence.'
        }
        $symbols = (Invoke-CapturedChecked -Command $script:AndroidSymbolInspector -Arguments @('--dynamic', $RuntimePath)) -join "`n"
        if ($symbols -notmatch '__stack_chk_fail') {
            throw 'Final Android runtime lacks stack-protector linkage evidence.'
        }
    }
}

function Invoke-BuildPass {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$BuildDirectory
    )

    Assert-ChildPath -Parent $buildRoot -Child $BuildDirectory
    if (Test-Path -LiteralPath $BuildDirectory) {
        Remove-Item -LiteralPath $BuildDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null

    $configure = @(
        '-S', $nativeRoot,
        '-B', $BuildDirectory,
        '-G', 'Ninja',
        "-DCMAKE_MAKE_PROGRAM=$script:NinjaPath",
        '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'
    )

    $vsArchitecture = ''
    if ($Target -eq 'windows-x64') {
        $vsArchitecture = 'x64'
        $configure += '-DDEEP_MLKEM_BUILD_TESTS=ON'
    }
    elseif ($Target -eq 'windows-arm64') {
        $vsArchitecture = 'arm64'
        $configure += '-DDEEP_MLKEM_BUILD_TESTS=OFF'
    }
    elseif ($Target -eq 'android-arm64') {
        $configure += @(
            "-DCMAKE_TOOLCHAIN_FILE=$script:AndroidToolchainFile",
            "-DANDROID_NDK=$script:ResolvedNdkRoot",
            '-DANDROID_ABI=arm64-v8a',
            '-DANDROID_PLATFORM=android-28',
            '-DANDROID_STL=none',
            '-DDEEP_MLKEM_BUILD_TESTS=OFF'
        )
    }
    else {
        throw "Unsupported target: $Target"
    }

    $oldSourceDateEpoch = $env:SOURCE_DATE_EPOCH
    $oldParallel = $env:CMAKE_BUILD_PARALLEL_LEVEL
    try {
        $env:SOURCE_DATE_EPOCH = '0'
        $env:CMAKE_BUILD_PARALLEL_LEVEL = '1'
        Invoke-Checked -Command $script:CmakePath -Arguments $configure -VsArchitecture $vsArchitecture
        Invoke-Checked -Command $script:CmakePath -Arguments @('--build', $BuildDirectory, '--config', 'Release') -VsArchitecture $vsArchitecture
        if ($Target -eq 'windows-x64') {
            Invoke-Checked -Command $script:CtestPath -Arguments @('--test-dir', $BuildDirectory, '-C', 'Release', '--output-on-failure') -VsArchitecture $vsArchitecture
        }
    }
    finally {
        $env:SOURCE_DATE_EPOCH = $oldSourceDateEpoch
        $env:CMAKE_BUILD_PARALLEL_LEVEL = $oldParallel
    }

    $runtimeName = if ($Target -eq 'android-arm64') { 'libdeep_mlkem.so' } else { 'deep_mlkem.dll' }
    $runtimePath = Require-File (Join-Path $BuildDirectory $runtimeName)
    Assert-ExactExports -Target $Target -RuntimePath $runtimePath -VsArchitecture $vsArchitecture
    Assert-FinalRuntimeHardening -Target $Target -RuntimePath $runtimePath -VsArchitecture $vsArchitecture
    $result = [ordered]@{
        runtimePath = $runtimePath
        runtimeSha256 = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
        runtimeBytes = (Get-Item -LiteralPath $runtimePath).Length
        exactExportSurface = $true
        finalRuntimeHardening = $true
    }
    Write-Host ("Native runtime candidate " + ($result | ConvertTo-Json -Compress))
    if ($Target -like 'windows-*') {
        $importLibraryPath = Require-File (Join-Path $BuildDirectory 'deep_mlkem.lib')
        $result.importLibraryPath = $importLibraryPath
        $result.importLibrarySha256 = (Get-FileHash -LiteralPath $importLibraryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $result.importLibraryBytes = (Get-Item -LiteralPath $importLibraryPath).Length
    }
    if ($Target -eq 'windows-x64') {
        $testPath = Require-File (Join-Path $BuildDirectory 'deep_mlkem_tests.exe')
        $result.testPath = $testPath
        $result.testSha256 = (Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Invoke-Checked -Command $script:DotnetX64Path -Arguments @($script:ManagedProbeAssembly, $runtimePath)
        $result.managedProbeExecuted = $true
        Invoke-Checked -Command $script:DotnetX64Path -Arguments @(
            $script:RuntimeWrapperProbeAssembly,
            $script:ProtocolTestsAssembly,
            $runtimePath)
        $result.productionWrapperProbeExecuted = $true
    }
    return $result
}

$deepSourcePaths = @(
    'global.json',
    'eng/Build-DeepMlKem.ps1',
    'eng/Generate-DeepMlKemApprovedAssets.ps1',
    'eng/Deep.MlKem.ManagedProbe/Deep.MlKem.ManagedProbe.csproj',
    'eng/Deep.MlKem.ManagedProbe/packages.lock.json',
    'eng/Deep.MlKem.ManagedProbe/Program.cs',
    'eng/Deep.MlKem.RuntimeWrapperProbe/Deep.MlKem.RuntimeWrapperProbe.csproj',
    'eng/Deep.MlKem.RuntimeWrapperProbe/packages.lock.json',
    'eng/Deep.MlKem.RuntimeWrapperProbe/Program.cs',
    'src/Deep.Protocol/Deep.Protocol.csproj',
    'src/Deep.Protocol/packages.lock.json',
    'src/Deep.Protocol/MessagingCrypto/DeepMlKemApprovedAssets.Generated.cs',
    'src/Deep.Protocol/MessagingCrypto/DeepMlKemNativeProvider.cs',
    'src/Deep.Protocol/MessagingCrypto/HybridPreKeyHandshake.cs',
    'src/Deep.Protocol/MessagingCrypto/MessagingCryptoPrimitives.cs',
    'tests/Deep.Protocol.GoldenVectors/Deep.Protocol.GoldenVectors.csproj',
    'tests/Deep.Protocol.GoldenVectors/packages.lock.json',
    'tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj',
    'tests/Deep.Protocol.Tests/packages.lock.json',
    'tests/Deep.Protocol.Tests/MessagingCrypto/DeepMlKemNativeProviderTests.cs',
    'tests/Deep.Protocol.Tests/MessagingCrypto/MessagingCryptoSurfaceTests.cs',
    'native/Deep.MlKem/CMakeLists.txt',
    'native/Deep.MlKem/README.md',
    'native/Deep.MlKem/include/deep_mlkem_v1.h',
    'native/Deep.MlKem/src/deep_mlkem_provider_config.h',
    'native/Deep.MlKem/src/deep_mlkem_v1.c',
    'native/Deep.MlKem/src/deep_mlkem_v1.def',
    'native/Deep.MlKem/tests/deep_mlkem_v1_tests.c',
    'native/Deep.MlKem/vendor/mlkem-native.provenance.json'
)
$repositoryCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $repositoryCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve the source repository commit for build evidence.'
}
$initialRepositoryStatus = @(Get-RepositoryStatusExcludingOutput)
$repositoryDirty = $initialRepositoryStatus.Count -ne 0
if ($repositoryDirty -and -not $AllowDirtyDevelopmentBuild) {
    throw 'Release ML-KEM build evidence requires a clean source repository.'
}
$initialBuildInputEvidence = @(Get-BuildInputEvidence -Paths $deepSourcePaths)

Assert-CleanBuildEnvironment
$null = Require-File (Join-Path $nativeRoot 'CMakeLists.txt')
$null = Require-File $provenancePath
$managedProbeProject = Require-File (Join-Path $repositoryRoot 'eng\Deep.MlKem.ManagedProbe\Deep.MlKem.ManagedProbe.csproj')
$runtimeWrapperProbeProject = Require-File (Join-Path $repositoryRoot 'eng\Deep.MlKem.RuntimeWrapperProbe\Deep.MlKem.RuntimeWrapperProbe.csproj')
$protocolTestsProject = Require-File (Join-Path $repositoryRoot 'tests\Deep.Protocol.Tests\Deep.Protocol.Tests.csproj')
$script:DotnetPath = Require-File ((Get-Command dotnet -ErrorAction Stop).Source)
$nestedDotnetX64Path = Join-Path (Split-Path -Parent $script:DotnetPath) 'x64\dotnet.exe'
if (Test-Path -LiteralPath $nestedDotnetX64Path -PathType Leaf) {
    $script:DotnetX64Path = (Resolve-Path -LiteralPath $nestedDotnetX64Path).Path
}
elseif ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq
    [Runtime.InteropServices.Architecture]::X64) {
    $script:DotnetX64Path = $script:DotnetPath
}
else {
    throw "Required x64 .NET host is absent: $nestedDotnetX64Path"
}
$dotnetVersion = (& $script:DotnetPath --version).Trim()
$dotnetX64Runtimes = @(& $script:DotnetX64Path --list-runtimes)
if ($LASTEXITCODE -ne 0 -or $dotnetVersion -notmatch '^10\.0\.' -or
    -not ($dotnetX64Runtimes -match '^Microsoft\.NETCore\.App 10\.0\.')) {
    throw 'The dark managed ABI probe requires a .NET 10 SDK.'
}
$managedEvidenceRoot = Join-Path $buildRoot 'managed-evidence'
Assert-ChildPath -Parent $buildRoot -Child $managedEvidenceRoot
if (Test-Path -LiteralPath $managedEvidenceRoot) {
    Remove-Item -LiteralPath $managedEvidenceRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $managedEvidenceRoot -Force | Out-Null
$script:ManagedProbeAssembly = Build-ManagedEvidenceProject `
    -Project $managedProbeProject `
    -AssemblyName 'Deep.MlKem.ManagedProbe.dll' `
    -ArtifactsDirectory (Join-Path $managedEvidenceRoot 'managed-probe')
$script:RuntimeWrapperProbeAssembly = Build-ManagedEvidenceProject `
    -Project $runtimeWrapperProbeProject `
    -AssemblyName 'Deep.MlKem.RuntimeWrapperProbe.dll' `
    -ArtifactsDirectory (Join-Path $managedEvidenceRoot 'runtime-wrapper-probe')
$protocolProjectRoot = Join-Path $repositoryRoot 'src\Deep.Protocol'
foreach ($generatedTestSeamPath in @(
        (Join-Path $protocolProjectRoot 'bin\Release\test-seam'),
        (Join-Path $protocolProjectRoot 'obj\Release\net10.0\test-seam'))) {
    Assert-ChildPath -Parent $protocolProjectRoot -Child $generatedTestSeamPath
    if (Test-Path -LiteralPath $generatedTestSeamPath) {
        Remove-Item -LiteralPath $generatedTestSeamPath -Recurse -Force
    }
}
$script:ProtocolTestsAssembly = Build-ManagedEvidenceProject `
    -Project $protocolTestsProject `
    -AssemblyName 'Deep.Protocol.Tests.dll' `
    -ArtifactsDirectory (Join-Path $managedEvidenceRoot 'protocol-tests')

$actualProvenanceHash = (Get-FileHash -LiteralPath $provenancePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualProvenanceHash -cne $expectedProvenanceSha256) {
    throw 'Provider provenance root digest differs from the reviewed mlkem-native v2.0.0 manifest.'
}
$provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
if ($provenance.upstreamCommit -cne $expectedProviderCommit -or
    $provenance.upstreamMlkemTreeGitSha1 -cne $expectedProviderTree -or
    $provenance.upstreamTag -cne 'v2.0.0' -or
    -not [bool]$provenance.upstreamFilesUnmodified) {
    throw 'Provider provenance does not match the accepted mlkem-native v2.0.0 source.'
}
$manifestPaths = @($provenance.files | ForEach-Object { [string]$_.path })
if ($manifestPaths.Count -ne $expectedVendoredFileCount -or
    @($manifestPaths | Sort-Object -Unique).Count -ne $manifestPaths.Count) {
    throw 'Provider provenance file set is incomplete or contains duplicate paths.'
}
$vendoredRoot = Join-Path $nativeRoot 'vendor\mlkem-native'
$actualPaths = @(Get-ChildItem -LiteralPath $vendoredRoot -File -Recurse | ForEach-Object {
        [IO.Path]::GetRelativePath($vendoredRoot, $_.FullName).Replace('\', '/')
    } | Sort-Object)
$expectedPaths = @($manifestPaths | Sort-Object)
if (($actualPaths -join "`n") -cne ($expectedPaths -join "`n")) {
    throw 'Vendored provider file set differs from the reviewed provenance manifest.'
}
foreach ($entry in $provenance.files) {
    $vendoredPath = Require-File (Join-Path $nativeRoot ('vendor\mlkem-native\' + $entry.path.Replace('/', '\')))
    $actualHash = (Get-FileHash -LiteralPath $vendoredPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $entry.sha256) {
        throw "Vendored provider integrity failure: $($entry.path)"
    }
}

$vsWhere = Require-File (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')
$requiredComponents = @('Microsoft.VisualStudio.Component.VC.Tools.x86.x64')
if ('windows-arm64' -in $targets) {
    $requiredComponents += 'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
}
$vsJson = & $vsWhere -products '*' -version '[17.0,18.0)' -requires @requiredComponents -format json
if ($LASTEXITCODE -ne 0) {
    throw 'Visual Studio 2022 discovery failed.'
}
$vsInstances = @($vsJson | ConvertFrom-Json)
if ($vsInstances.Count -eq 0) {
    throw 'Visual Studio 2022 Build Tools with the selected C++ components are absent.'
}
$vs = $vsInstances | Sort-Object installationVersion -Descending | Select-Object -First 1
$script:VsDevCmd = Require-File (Join-Path $vs.installationPath 'Common7\Tools\VsDevCmd.bat')
$script:CmakePath = Require-File (Join-Path $vs.installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe')
$script:CtestPath = Require-File (Join-Path $vs.installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe')
$script:NinjaPath = Require-File (Join-Path $vs.installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe')
$cmakeHash = (Get-FileHash -LiteralPath $script:CmakePath -Algorithm SHA256).Hash.ToLowerInvariant()
$ctestHash = (Get-FileHash -LiteralPath $script:CtestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$ninjaHash = (Get-FileHash -LiteralPath $script:NinjaPath -Algorithm SHA256).Hash.ToLowerInvariant()
$vsDevCmdHash = (Get-FileHash -LiteralPath $script:VsDevCmd -Algorithm SHA256).Hash.ToLowerInvariant()
$dotnetHash = (Get-FileHash -LiteralPath $script:DotnetPath -Algorithm SHA256).Hash.ToLowerInvariant()
$dotnetX64Hash = (Get-FileHash -LiteralPath $script:DotnetX64Path -Algorithm SHA256).Hash.ToLowerInvariant()
$dotnetHostsApproved = if ($script:DotnetPath -ceq $script:DotnetX64Path) {
    $dotnetHash -ceq $expectedDotnetX64Sha256
}
else {
    $dotnetHash -ceq $expectedDotnetSha256 -and $dotnetX64Hash -ceq $expectedDotnetX64Sha256
}

$script:WindowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdkVersions = @(Get-ChildItem -LiteralPath (Join-Path $script:WindowsSdkRoot 'Include') -Directory |
    ForEach-Object {
        try { [version]$_.Name } catch { $null }
    } | Where-Object { $null -ne $_ } | Sort-Object -Descending)
$script:WindowsSdkVersion = ''
foreach ($candidate in $sdkVersions) {
    $versionText = $candidate.ToString()
    $requiredSdkFiles = @(
        (Join-Path $script:WindowsSdkRoot "Include\$versionText\um\winsdkver.h"),
        (Join-Path $script:WindowsSdkRoot "Include\$versionText\ucrt\corecrt.h"),
        (Join-Path $script:WindowsSdkRoot "Lib\$versionText\ucrt\x64\ucrt.lib"),
        (Join-Path $script:WindowsSdkRoot "Lib\$versionText\um\x64\kernel32.lib"),
        (Join-Path $script:WindowsSdkRoot "bin\$versionText\x64\rc.exe"),
        (Join-Path $script:WindowsSdkRoot "bin\$versionText\x64\mt.exe")
    )
    if ('windows-arm64' -in $targets) {
        $requiredSdkFiles += @(
            (Join-Path $script:WindowsSdkRoot "Lib\$versionText\ucrt\arm64\ucrt.lib"),
            (Join-Path $script:WindowsSdkRoot "Lib\$versionText\um\arm64\kernel32.lib")
        )
    }
    if (@($requiredSdkFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -eq 0) {
        $script:WindowsSdkVersion = $versionText
        break
    }
}
if ([string]::IsNullOrWhiteSpace($script:WindowsSdkVersion)) {
    throw 'A complete Windows SDK for the selected Windows targets is absent.'
}

$script:ResolvedNdkRoot = ''
$script:AndroidToolchainFile = ''
if ('android-arm64' -in $targets) {
    if ([string]::IsNullOrWhiteSpace($AndroidNdkRoot)) {
        throw "AndroidNdkRoot is required for android-arm64; exact revision $expectedNdkRevision is required."
    }
    $script:ResolvedNdkRoot = (Resolve-Path -LiteralPath $AndroidNdkRoot -ErrorAction Stop).Path
    $sourceProperties = Require-File (Join-Path $script:ResolvedNdkRoot 'source.properties')
    $revisionLine = Get-Content -LiteralPath $sourceProperties | Where-Object { $_ -match '^Pkg\.Revision\s*=' } | Select-Object -First 1
    if ($revisionLine -notmatch '^Pkg\.Revision\s*=\s*(.+?)\s*$' -or $Matches[1] -cne $expectedNdkRevision) {
        throw "Android NDK revision must be exactly $expectedNdkRevision."
    }
    $script:AndroidToolchainFile = Require-File (Join-Path $script:ResolvedNdkRoot 'build\cmake\android.toolchain.cmake')
}

$toolchains = [ordered]@{}
if ('windows-x64' -in $targets) {
    $toolchains['windows-x64'] = Get-WindowsEnvironmentEvidence -Architecture 'x64'
}
if ('windows-arm64' -in $targets) {
    $toolchains['windows-arm64'] = Get-WindowsEnvironmentEvidence -Architecture 'arm64'
}
if ('android-arm64' -in $targets) {
    $toolchains['android-arm64'] = Get-AndroidEnvironmentEvidence -NdkRoot $script:ResolvedNdkRoot
}
$toolchainMismatches = [Collections.Generic.List[string]]::new()
if ([string]$vs.installationVersion -cne $expectedVsInstallationVersion) { $toolchainMismatches.Add('visual-studio') }
if ($cmakeHash -cne $expectedCmakeSha256) { $toolchainMismatches.Add('cmake') }
if ($ctestHash -cne $expectedCtestSha256) { $toolchainMismatches.Add('ctest') }
if ($ninjaHash -cne $expectedNinjaSha256) { $toolchainMismatches.Add('ninja') }
if ($vsDevCmdHash -cne $expectedVsDevCmdSha256) { $toolchainMismatches.Add('vsdevcmd') }
if (-not $dotnetHostsApproved) { $toolchainMismatches.Add('dotnet-host') }
if ($script:WindowsSdkVersion -cne $expectedWindowsSdkVersion) { $toolchainMismatches.Add('windows-sdk') }
foreach ($entry in $toolchains.GetEnumerator() | Where-Object { $_.Key -like 'windows-*' }) {
    if ($entry.Value.vcToolsVersion -cne $expectedVcToolsVersion) {
        $toolchainMismatches.Add("$($entry.Key)-msvc")
    }
    if ($entry.Value.windowsSdkVersion -cne $expectedWindowsSdkVersion) {
        $toolchainMismatches.Add("$($entry.Key)-sdk")
    }
}
if ($toolchains.Contains('windows-x64')) {
    $x64 = $toolchains['windows-x64']
    if ($x64.compiler.sha256 -cne $expectedWindowsX64CompilerSha256) { $toolchainMismatches.Add('x64-compiler') }
    if ($x64.linker.sha256 -cne $expectedWindowsX64LinkerSha256) { $toolchainMismatches.Add('x64-linker') }
    if ($x64.librarian.sha256 -cne $expectedWindowsX64LibrarianSha256) { $toolchainMismatches.Add('x64-librarian') }
    if ($x64.symbolInspector.sha256 -cne $expectedWindowsX64InspectorSha256) { $toolchainMismatches.Add('x64-inspector') }
}
if ($toolchainMismatches.Count -ne 0) {
    $actualToolchain = [ordered]@{
        visualStudioVersion = [string]$vs.installationVersion
        vcToolsVersions = @($toolchains.GetEnumerator() | Where-Object { $_.Key -like 'windows-*' } | ForEach-Object { $_.Value.vcToolsVersion } | Sort-Object -Unique)
        windowsSdkVersion = $script:WindowsSdkVersion
        cmakeSha256 = $cmakeHash
        ctestSha256 = $ctestHash
        ninjaSha256 = $ninjaHash
        vsDevCmdSha256 = $vsDevCmdHash
        dotnetSha256 = $dotnetHash
        dotnetX64Sha256 = $dotnetX64Hash
        windowsX64 = if ($toolchains.Contains('windows-x64')) { $toolchains['windows-x64'] } else { $null }
    }
    Write-Host ($actualToolchain | ConvertTo-Json -Depth 8 -Compress)
    throw "Windows toolchain differs from the reviewed identity: $($toolchainMismatches -join ', ')."
}
$windowsToolchain = $toolchains.GetEnumerator() | Where-Object { $_.Key -like 'windows-*' } | Select-Object -First 1
if ($null -ne $windowsToolchain) {
    $script:WindowsSymbolInspector = Require-File $windowsToolchain.Value.symbolInspector.path
}
if ($toolchains.Contains('android-arm64')) {
    $script:AndroidSymbolInspector = Require-File $toolchains['android-arm64'].symbolInspector.path
    $script:AndroidElfInspector = Require-File $toolchains['android-arm64'].elfInspector.path
}

New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$allowedOutputEntries = @('windows-x64', 'windows-arm64', 'android-arm64', 'build-manifest.v1.json')
$unexpectedOutputEntries = @(Get-ChildItem -LiteralPath $OutputRoot -Force | Where-Object {
        $allowedOutputEntries -cnotcontains $_.Name
    })
if ($unexpectedOutputEntries.Count -ne 0) {
    throw "Publish root contains unreviewed entries: $($unexpectedOutputEntries.Name -join ', ')"
}
foreach ($knownTarget in @('windows-x64', 'windows-arm64', 'android-arm64')) {
    $staleTargetOutput = Join-Path $OutputRoot $knownTarget
    Assert-ChildPath -Parent $OutputRoot -Child $staleTargetOutput
    if (Test-Path -LiteralPath $staleTargetOutput) {
        Remove-Item -LiteralPath $staleTargetOutput -Recurse -Force
    }
}
$staleManifest = Join-Path $OutputRoot 'build-manifest.v1.json'
if (Test-Path -LiteralPath $staleManifest) {
    Remove-Item -LiteralPath $staleManifest -Force
}
$artifacts = @()
foreach ($target in $targets) {
    $firstBuildDirectory = Join-Path $buildRoot "$target-pass-a"
    $first = Invoke-BuildPass -Target $target -BuildDirectory $firstBuildDirectory
    $reproducible = $false
    if (-not $SkipReproducibilityCheck) {
        $secondBuildDirectory = Join-Path $buildRoot "$target-pass-b"
        $second = Invoke-BuildPass -Target $target -BuildDirectory $secondBuildDirectory
        if ($first.runtimeSha256 -cne $second.runtimeSha256) {
            throw "Distinct-path clean rebuild mismatch for $target runtime: $($first.runtimeSha256) != $($second.runtimeSha256)"
        }
        if ($target -like 'windows-*' -and $first.importLibrarySha256 -cne $second.importLibrarySha256) {
            throw "Distinct-path clean rebuild mismatch for $target import library."
        }
        if ($target -eq 'windows-x64' -and $first.testSha256 -cne $second.testSha256) {
            throw "Distinct-path clean rebuild mismatch for $target test executable."
        }
        $first = $second
        $reproducible = $true
    }

    $targetOutput = Join-Path $OutputRoot $target
    New-Item -ItemType Directory -Path $targetOutput -Force | Out-Null
    $runtimeDestination = Join-Path $targetOutput (Split-Path -Leaf $first.runtimePath)
    Copy-Item -LiteralPath $first.runtimePath -Destination $runtimeDestination -Force
    $artifacts += [ordered]@{
        target = $target
        role = 'shared-runtime'
        file = ($target + '/' + (Split-Path -Leaf $runtimeDestination))
        bytes = (Get-Item -LiteralPath $runtimeDestination).Length
        sha256 = (Get-FileHash -LiteralPath $runtimeDestination -Algorithm SHA256).Hash.ToLowerInvariant()
        nativeTestsExecuted = ($target -eq 'windows-x64')
        managedProbeExecuted = ($target -eq 'windows-x64')
        productionWrapperProbeExecuted = ($target -eq 'windows-x64')
        exactExportSurface = $first.exactExportSurface
        finalRuntimeHardening = $first.finalRuntimeHardening
        cleanDistinctPathRebuildMatched = $reproducible
    }
    if ($target -like 'windows-*') {
        $importDestination = Join-Path $targetOutput (Split-Path -Leaf $first.importLibraryPath)
        Copy-Item -LiteralPath $first.importLibraryPath -Destination $importDestination -Force
        $artifacts += [ordered]@{
            target = $target
            role = 'import-library'
            file = ($target + '/' + (Split-Path -Leaf $importDestination))
            bytes = (Get-Item -LiteralPath $importDestination).Length
            sha256 = (Get-FileHash -LiteralPath $importDestination -Algorithm SHA256).Hash.ToLowerInvariant()
            nativeTestsExecuted = $false
            managedProbeExecuted = $false
            productionWrapperProbeExecuted = $false
            exactExportSurface = $null
            finalRuntimeHardening = $null
            cleanDistinctPathRebuildMatched = $reproducible
        }
    }
    $publishedClosure = @(Get-ChildItem -LiteralPath $targetOutput -File | Select-Object -ExpandProperty Name | Sort-Object)
    $expectedClosure = if ($target -eq 'android-arm64') { @('libdeep_mlkem.so') } else { @('deep_mlkem.dll', 'deep_mlkem.lib') }
    if (($publishedClosure -join "`n") -cne (($expectedClosure | Sort-Object) -join "`n")) {
        throw "Published artifact closure mismatch for $target."
    }
}

$expectedPublishedFiles = @($artifacts.file | Sort-Object)
$actualPublishedFiles = @(Get-ChildItem -LiteralPath $OutputRoot -File -Recurse | ForEach-Object {
        [IO.Path]::GetRelativePath($OutputRoot, $_.FullName).Replace('\', '/')
    } | Sort-Object)
if (($actualPublishedFiles -join "`n") -cne ($expectedPublishedFiles -join "`n")) {
    throw "Recursive publish file closure mismatch. Expected [$($expectedPublishedFiles -join ', ')], actual [$($actualPublishedFiles -join ', ')]."
}
$expectedPublishedDirectories = @($targets | Sort-Object)
$actualPublishedDirectories = @(Get-ChildItem -LiteralPath $OutputRoot -Directory -Recurse | ForEach-Object {
        [IO.Path]::GetRelativePath($OutputRoot, $_.FullName).Replace('\', '/')
    } | Sort-Object)
if (($actualPublishedDirectories -join "`n") -cne ($expectedPublishedDirectories -join "`n")) {
    throw "Recursive publish directory closure mismatch. Expected [$($expectedPublishedDirectories -join ', ')], actual [$($actualPublishedDirectories -join ', ')]."
}

$finalRepositoryCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $finalRepositoryCommit -cne $repositoryCommit) {
    throw 'The source repository HEAD changed while ML-KEM evidence was produced.'
}
$finalRepositoryStatus = @(Get-RepositoryStatusExcludingOutput)
if (($finalRepositoryStatus -join "`n") -cne ($initialRepositoryStatus -join "`n")) {
    throw 'The source repository state changed while ML-KEM evidence was produced.'
}
$deepSourceEvidence = @(Get-BuildInputEvidence -Paths $deepSourcePaths)
Assert-BuildInputsUnchanged -Initial $initialBuildInputEvidence -Current $deepSourceEvidence

$manifest = [ordered]@{
    schemaVersion = 1
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    provider = [ordered]@{
        name = $provenance.provider
        tag = $provenance.upstreamTag
        commit = $provenance.upstreamCommit
        licenseExpression = $provenance.licenseExpression
        provenanceFileSha256 = (Get-FileHash -LiteralPath $provenancePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    configuration = [ordered]@{
        parameterSet = 'ML-KEM-768'
        backend = 'portable-c'
        compactPrivateKeyRepresentation = 'Deep seed-backed d||z (64 bytes); not FIPS 203 serialized dk'
        androidApi = 28
        requiredAndroidNdkRevision = $expectedNdkRevision
        sourceDateEpoch = 0
        buildParallelism = 1
        runtimeAbi = 'Deep-owned C v1 shared library; provider remains internal static'
        providerIdentifier = $expectedProviderIdentifier
    }
    buildTools = [ordered]@{
        visualStudioProduct = $vs.displayName
        visualStudioVersion = $vs.installationVersion
        visualStudioPath = $vs.installationPath
        cmake = Get-FileEvidence $script:CmakePath
        ninja = Get-FileEvidence $script:NinjaPath
        dotnet = [ordered]@{
            version = $dotnetVersion
            executable = Get-FileEvidence $script:DotnetPath
            windowsX64Host = Get-FileEvidence $script:DotnetX64Path
        }
        targetToolchains = $toolchains
    }
    deepSources = [ordered]@{
        repositoryCommit = $repositoryCommit
        repositoryDirty = $repositoryDirty
        headRecheckedBeforeManifest = $true
        repositoryStateRecheckedBeforeManifest = $true
        exactBuildInputClosureRechecked = $true
        managedRestoreLocked = $true
        managedArtifactsIsolatedOrCleaned = $true
        files = $deepSourceEvidence
    }
    artifacts = @($artifacts)
    releaseGates = [ordered]@{
        acvp = 'pending'
        androidArm64Physical = if ('android-arm64' -in $targets) { 'build-only; physical pending' } else { 'pending' }
        windowsArm64Runtime = if ('windows-arm64' -in $targets) { 'build-only; runtime pending' } else { 'pending' }
        trustedPackageAppBase = 'pending; signed package/install ACL evidence required before activation'
    }
}
$manifestPath = Join-Path $OutputRoot 'build-manifest.v1.json'
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$generatorScript = Require-File (Join-Path $repositoryRoot 'eng\Generate-DeepMlKemApprovedAssets.ps1')
$generatorArguments = @{
    ManifestPath = $manifestPath
    OutputPath = (Join-Path $repositoryRoot 'src\Deep.Protocol\MessagingCrypto\DeepMlKemApprovedAssets.Generated.cs')
    Check = $true
}
if ($repositoryDirty) { $generatorArguments.AllowDirtyManifest = $true }
if ($SkipReproducibilityCheck) { $generatorArguments.AllowIncompleteEvidence = $true }
if (-not [string]::IsNullOrWhiteSpace($WindowsArm64AcceptancePath)) {
    $generatorArguments.WindowsArm64AcceptancePath = $WindowsArm64AcceptancePath
}
& $generatorScript @generatorArguments
Write-Host "Deep ML-KEM build complete. Manifest: $manifestPath"
