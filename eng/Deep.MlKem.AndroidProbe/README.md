# Deep ML-KEM Android production-wrapper probe

This isolated Android arm64 application exercises the existing internal
`DeepMlKemNativeProvider` and `DeepMlKemProductionRuntime` against the exact
release-approved Android arm64 `libdeep_mlkem.so` identity. The probe is an
isolated package and does not widen the production assembly surface.

The native library is embedded in the APK as `deep-mlkem/libdeep_mlkem.so`.
At runtime the probe verifies its exact byte length and SHA-256, stages it below
`AppContext.BaseDirectory`, and invokes the production wrapper, which repeats
the approved path, length, digest, ABI, export-size, and zeroization checks.

Build only this probe with the official attested asset:

```powershell
$asset = '<absolute-path-to-official-bundle>\mlkem\android-arm64\libdeep_mlkem.so'
$sdk = 'C:\Program Files (x86)\Android\android-sdk'
dotnet restore .\eng\Deep.MlKem.AndroidProbe\Deep.MlKem.AndroidProbe.csproj `
  "-p:DeepMlKemAndroidAsset=$asset" "-p:AndroidSdkDirectory=$sdk"
dotnet build .\eng\Deep.MlKem.AndroidProbe\Deep.MlKem.AndroidProbe.csproj `
  -c Release --no-restore `
  "-p:DeepMlKemAndroidAsset=$asset" "-p:AndroidSdkDirectory=$sdk"
```

Install on one explicitly selected Android API 26+ arm64 probe device and read the
single sanitized JSON record:

```powershell
$adb = 'C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe'
$serial = '<physical-device-serial>'
$apk = '<absolute-path-to-org.deep.protocol.mlkemprobe-Signed.apk>'
& $adb -s $serial install -r $apk
& $adb -s $serial logcat -c
& $adb -s $serial shell monkey -p org.deep.protocol.mlkemprobe 1
& $adb -s $serial logcat -d -s 'DeepMlKemProbe:I' '*:S'
```

API 26 support here is isolated cryptographic compatibility evidence only; it
does not lower the first public application's API 28 signer-lineage requirement.
The JSON contains no key material, ciphertext, shared secret, local path,
device serial, model, or package/user data. Success is physical Android runtime
evidence for the already pinned artifact; the signed acceptance record remains
the release authority.
