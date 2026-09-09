[CmdletBinding()]
param(
    [ValidateSet('windows-x64', 'windows-arm64', 'android-arm64')]
    [string]$Target = 'windows-x64',
    [string]$NdkRoot = (Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk\28.2.13676358'),
    [string]$AdbPath = '',
    [string]$DeviceSerial = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$nativeRoot = Join-Path $repositoryRoot 'native\Deep.MlKemBraid'
$manifest = Join-Path $nativeRoot 'Cargo.toml'
$targetTriple = if ($Target -ceq 'windows-arm64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
$toolchain = '1.89.0-x86_64-pc-windows-msvc'
$releaseRoot = Join-Path $nativeRoot "target\$targetTriple\release"
$dll = Join-Path $releaseRoot 'deep_mlkem_braid.dll'
$importLibrary = Join-Path $releaseRoot 'deep_mlkem_braid.dll.lib'
$probeSource = Join-Path $PSScriptRoot 'Deep.MlKemBraid.NativeProbe\deep_mlkem_braid_probe.c'
$probeRoot = Join-Path $nativeRoot 'target\native-probe'
$probe = Join-Path $probeRoot 'deep_mlkem_braid_probe.exe'

function Require-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is absent: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Assert-Sha256([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "SHA-256 mismatch for $Path. Expected $Expected; actual $actual."
    }
}

function Get-ExpectedExports {
    return @(
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
}

$cargo = Require-File (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe')
$rustc = Require-File (Join-Path $env:USERPROFILE ".rustup\toolchains\$toolchain\bin\rustc.exe")
$rustVersion = (& $rustc --version --verbose | Out-String)
if ($rustVersion -notmatch 'release: 1\.89\.0' -or $rustVersion -notmatch 'host: x86_64-pc-windows-msvc') {
    throw 'The pinned Rust 1.89.0 Windows x64 toolchain is unavailable.'
}

$provenancePath = Require-File (Join-Path $nativeRoot 'third-party\libcrux\provenance.json')
$provenance = Get-Content -Raw -LiteralPath $provenancePath | ConvertFrom-Json
if ($provenance.crateVersion -cne '0.0.10' -or
    $provenance.crateSha256 -cne '1d8160f7d64fd2716b4fd05cc886a042f8dcda18d9206c0d506e2c67bdf97daa' -or
    $provenance.repositoryCommit -cne 'c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd' -or
    $provenance.declaredCrateLicense -cne 'Apache-2.0') {
    throw 'Pinned libcrux-ml-kem provenance is invalid.'
}
Assert-Sha256 (Join-Path $nativeRoot 'third-party\libcrux\LICENSE-APACHE') '89a704092ec99209cd19f1d60cd67a353e3ec069e7f19f17cd41fcac052811c4'
Assert-Sha256 (Join-Path $nativeRoot 'third-party\libcrux\LICENSE-MIT') '182ab7e3c88dd73b9c264ae0d5ed27f73b2b28f8d187e4d42b0eed2b93bfb4c3'

$lock = Get-Content -Raw -LiteralPath (Require-File (Join-Path $nativeRoot 'Cargo.lock'))
if ($lock -notmatch '(?s)name = "libcrux-ml-kem"\s+version = "0\.0\.10"\s+source = .*?\s+checksum = "1d8160f7d64fd2716b4fd05cc886a042f8dcda18d9206c0d506e2c67bdf97daa"') {
    throw 'Cargo.lock does not contain the reviewed libcrux-ml-kem package.'
}

if ($Target -ceq 'android-arm64') {
    $androidTriple = 'aarch64-linux-android'
    $androidApi = 26
    $ndkProperties = Require-File (Join-Path $NdkRoot 'source.properties')
    $ndkMetadata = Get-Content -Raw -LiteralPath $ndkProperties
    if ($ndkMetadata -notmatch '(?m)^Pkg\.Revision\s*=\s*28\.2\.13676358\s*$') {
        throw 'The Android gate requires exact NDK 28.2.13676358 (r28c).'
    }
    $ndkBin = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
    $androidLinker = Require-File (Join-Path $ndkBin "aarch64-linux-android$androidApi-clang.cmd")
    $llvmNm = Require-File (Join-Path $ndkBin 'llvm-nm.exe')
    $llvmReadElf = Require-File (Join-Path $ndkBin 'llvm-readelf.exe')
    $rustup = Require-File (Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe')
    $installedTargets = @(& $rustup target list --installed --toolchain $toolchain)
    if ($installedTargets -cnotcontains $androidTriple) {
        throw "Rust target $androidTriple is not installed for $toolchain."
    }

    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $androidLinker
    $env:RUSTFLAGS = '-Dwarnings -Clink-arg=-Wl,-z,relro,-z,now'
    & $cargo "+$toolchain" build --manifest-path $manifest --target $androidTriple --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Android ARM64 Rust release build failed.' }

    $androidReleaseRoot = Join-Path $nativeRoot "target\$androidTriple\release"
    $sharedObject = Require-File (Join-Path $androidReleaseRoot 'libdeep_mlkem_braid.so')
    $actualExports = @(& $llvmNm -D --defined-only --format=posix $sharedObject |
        ForEach-Object {
            if ($_ -match '^(deep_mlkem_braid_v1_\S+)\s') { $Matches[1] }
        } | Sort-Object -Unique)
    $exportDifference = @(Compare-Object ((Get-ExpectedExports) | Sort-Object) $actualExports)
    if ($exportDifference.Count -ne 0) {
        throw "The Android Deep ML-KEM Braid export surface drifted: $($exportDifference | Out-String)"
    }
    $dynamic = (& $llvmReadElf --dynamic $sharedObject | Out-String)
    $programHeaders = (& $llvmReadElf --program-headers $sharedObject | Out-String)
    if ($dynamic -notmatch '\bBIND_NOW\b' -and $dynamic -notmatch 'Flags:.*NOW') {
        throw 'The Android shared object is missing BIND_NOW.'
    }
    if ($programHeaders -notmatch 'GNU_RELRO') {
        throw 'The Android shared object is missing GNU_RELRO.'
    }
    if ($dynamic -match 'TEXTREL') {
        throw 'The Android shared object contains text relocations.'
    }

    $androidProbeSource = Require-File (Join-Path $PSScriptRoot 'Deep.MlKemBraid.AndroidProbe\deep_mlkem_braid_android_probe.c')
    $androidProbeRoot = Join-Path $nativeRoot 'target\android-probe'
    $androidProbe = Join-Path $androidProbeRoot 'deep_mlkem_braid_android_probe'
    New-Item -ItemType Directory -Path $androidProbeRoot -Force | Out-Null
    & $androidLinker -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie '-Wl,-z,relro,-z,now' `
        -I (Join-Path $nativeRoot 'include') $androidProbeSource -ldl -o $androidProbe
    if ($LASTEXITCODE -ne 0) { throw 'Android ARM64 native runtime probe compilation failed.' }

    $needed = @([regex]::Matches($dynamic, '\(NEEDED\).*?\[(?<name>[^\]]+)\]') |
        ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)
    $soHash = (Get-FileHash -LiteralPath $sharedObject -Algorithm SHA256).Hash.ToLowerInvariant()
    $soSize = (Get-Item -LiteralPath $sharedObject).Length
    Write-Output "Android shared object: $sharedObject"
    Write-Output "SHA-256: $soHash"
    Write-Output "Size: $soSize"
    Write-Output "Exports: $($actualExports.Count) exact"
    Write-Output "Dependencies: $($needed -join ', ')"

    if (-not [string]::IsNullOrWhiteSpace($DeviceSerial)) {
        if ([string]::IsNullOrWhiteSpace($AdbPath)) {
            throw 'AdbPath is required when DeviceSerial is provided.'
        }
        $adb = Require-File $AdbPath
        $deviceLine = @(@(& $adb devices) | Where-Object { $_ -match "^$([regex]::Escape($DeviceSerial))\s+device$" })
        if ($deviceLine.Count -ne 1) {
            throw "The exact Android device $DeviceSerial is not connected and authorized."
        }
        $deviceAbi = (& $adb -s $DeviceSerial shell getprop ro.product.cpu.abi | Out-String).Trim()
        if ($deviceAbi -cne 'arm64-v8a') {
            throw "The exact Android device is not arm64-v8a: $deviceAbi"
        }
        $remoteRoot = '/data/local/tmp/deep_mlkem_braid_probe_v1'
        & $adb -s $DeviceSerial shell mkdir -p $remoteRoot
        if ($LASTEXITCODE -ne 0) { throw 'Unable to create the isolated Android probe directory.' }
        & $adb -s $DeviceSerial push $sharedObject "$remoteRoot/libdeep_mlkem_braid.so"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to push the isolated Android shared object.' }
        & $adb -s $DeviceSerial push $androidProbe "$remoteRoot/deep_mlkem_braid_android_probe"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to push the isolated Android runtime probe.' }
        & $adb -s $DeviceSerial shell chmod 700 "$remoteRoot/deep_mlkem_braid_android_probe"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to mark the Android runtime probe executable.' }
        & $adb -s $DeviceSerial shell chmod 600 "$remoteRoot/libdeep_mlkem_braid.so"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict Android shared-object permissions.' }
        $probeOutput = (& $adb -s $DeviceSerial shell "cd $remoteRoot && LD_LIBRARY_PATH=. ./deep_mlkem_braid_android_probe" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or
            $probeOutput -notmatch '"result":"pass"' -or
            $probeOutput -notmatch '"secretsEmitted":false') {
            throw "Android ARM64 runtime probe failed: $probeOutput"
        }
        Write-Output $probeOutput
    }
    return
}

$vsWhere = Require-File (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')
$vcComponent = if ($Target -ceq 'windows-arm64') {
    'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
} else {
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
}
$vsPath = (& $vsWhere -latest -products '*' -requires $vcComponent -property installationPath |
    Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($vsPath)) {
    throw "Visual Studio C++ tools for $Target are unavailable ($vcComponent)."
}
$vsDevCmd = Require-File (Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat')
$windowsArchitecture = if ($Target -ceq 'windows-arm64') { 'arm64' } else { 'x64' }
$environmentLines = & cmd.exe /d /s /c "`"$vsDevCmd`" -no_logo -host_arch=x64 -arch=$windowsArchitecture >nul && set"
foreach ($line in $environmentLines) {
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) {
        [Environment]::SetEnvironmentVariable($line.Substring(0, $separator), $line.Substring($separator + 1), 'Process')
    }
}

$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdkVersion = '10.0.26100.0'
$sdkInclude = Join-Path $sdkRoot "Include\$sdkVersion"
$sdkLib = Join-Path $sdkRoot "Lib\$sdkVersion"
$env:INCLUDE = (@(
    (Join-Path $sdkInclude 'ucrt'),
    (Join-Path $sdkInclude 'shared'),
    (Join-Path $sdkInclude 'um'),
    (Join-Path $sdkInclude 'winrt'),
    $env:INCLUDE
) -join ';')
$env:LIB = (@(
    (Join-Path $sdkLib "ucrt\$windowsArchitecture"),
    (Join-Path $sdkLib "um\$windowsArchitecture"),
    $env:LIB
) -join ';')
$env:RUSTFLAGS = '-Dwarnings -Ccontrol-flow-guard=yes -Ctarget-feature=+crt-static -Clink-arg=/guard:cf'

$rustup = Require-File (Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe')
$installedTargets = @(& $rustup target list --installed --toolchain $toolchain)
if ($installedTargets -cnotcontains $targetTriple) {
    throw "Rust target $targetTriple is not installed for $toolchain."
}

if ($Target -ceq 'windows-arm64') {
    & $cargo "+$toolchain" test --manifest-path $manifest --target $targetTriple --release --locked --no-run
    if ($LASTEXITCODE -ne 0) { throw 'Rust ARM64 release test cross-compilation failed.' }
} else {
    & $cargo "+$toolchain" test --manifest-path $manifest --target $targetTriple --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust release tests failed.' }
}
& $cargo "+$toolchain" build --manifest-path $manifest --target $targetTriple --release --locked
if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }

Require-File $dll | Out-Null
Require-File $importLibrary | Out-Null
$headers = (& dumpbin.exe /nologo /headers $dll | Out-String)
foreach ($requiredFlag in @('Dynamic base', 'High Entropy Virtual Addresses', 'NX compatible', 'Control Flow Guard')) {
    if ($headers -notmatch [regex]::Escape($requiredFlag)) {
        throw "The Deep ML-KEM Braid DLL is missing hardening flag: $requiredFlag"
    }
}
$expectedExports = Get-ExpectedExports
$actualExports = @(& dumpbin.exe /nologo /exports $dll |
    ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)(?:\s+=.*)?$') { $Matches[1] }
    } | Sort-Object -Unique)
$exportDifference = @(Compare-Object ($expectedExports | Sort-Object) $actualExports)
if ($exportDifference.Count -ne 0) {
    throw "The Deep ML-KEM Braid export surface drifted: $($exportDifference | Out-String)"
}

New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
$probeObject = Join-Path $probeRoot 'deep_mlkem_braid_probe.obj'
& cl.exe /nologo /W4 /WX /sdl /GS /guard:cf /I (Join-Path $nativeRoot 'include') $probeSource `
    "/Fo$probeObject" /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA $importLibrary "/OUT:$probe"
if ($LASTEXITCODE -ne 0) { throw 'Native C ABI probe compilation failed.' }

$env:PATH = "$releaseRoot;$env:PATH"
if ($Target -ceq 'windows-arm64') {
    Write-Output 'Deep ML-KEM Braid Windows ARM64 ABI probe cross-compiled; runtime execution remains a separate gate.'
} else {
    & $probe
    if ($LASTEXITCODE -ne 0) { throw 'Native C ABI probe failed.' }
}

Write-Output "Deep ML-KEM Braid host spike passed: $dll"
