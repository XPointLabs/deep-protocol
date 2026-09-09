# Incremental ML-KEM Braid Android managed-wrapper probe

This isolated `org.deep.protocol.mlkembraidprobe` application packages the
pinned Android arm64 candidate as an APK asset and exercises the managed ABI,
ownership, fail-closed allowlist, roundtrip, disposal, and concurrent
single-consumer behavior. It does not approve the candidate for production and
does not emit key material.

Build from the repository root:

```powershell
$asset = Resolve-Path .\native\Deep.MlKemBraid\target\aarch64-linux-android\release\libdeep_mlkem_braid.so
$sdk = 'C:\Program Files (x86)\Android\android-sdk'
dotnet restore .\eng\Deep.MlKemBraid.AndroidManagedProbe\Deep.MlKemBraid.AndroidManagedProbe.csproj `
  "-p:DeepMlKemBraidAndroidAsset=$asset" "-p:AndroidSdkDirectory=$sdk"
dotnet build .\eng\Deep.MlKemBraid.AndroidManagedProbe\Deep.MlKemBraid.AndroidManagedProbe.csproj `
  -c Release --no-restore "-p:DeepMlKemBraidAndroidAsset=$asset" "-p:AndroidSdkDirectory=$sdk"
```

Install only on an explicitly selected probe device. The result is logged under
tag `DEEP_MLKEM_BRAID_PROBE`.
