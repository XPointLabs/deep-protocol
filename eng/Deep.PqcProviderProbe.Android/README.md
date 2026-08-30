# Deep ML-KEM provider probe

This isolated Android application evaluates an exact candidate provider without
adding it to the production dependency graph. It uses package ID
`org.deep.protocol.pqcprobe` and never reads, clears, or modifies Deep client
data.

The checked-in candidate is `BouncyCastle.Cryptography` 2.7.0. Upstream marks
its post-quantum implementations experimental. A successful functional probe
is therefore not production-provider approval.

Build with the locked package graph:

```powershell
dotnet restore eng\Deep.PqcProviderProbe.Android\Deep.PqcProviderProbe.Android.csproj `
  -p:RuntimeIdentifier=android-arm64 `
  -p:AndroidSdkDirectory='C:\Program Files (x86)\Android\android-sdk'
dotnet build eng\Deep.PqcProviderProbe.Android\Deep.PqcProviderProbe.Android.csproj `
  -c Release -f net10.0-android --no-restore `
  -p:RuntimeIdentifier=android-arm64 `
  -p:AndroidSdkDirectory='C:\Program Files (x86)\Android\android-sdk'
```

Install only the generated `org.deep.protocol.pqcprobe-Signed.apk` with an
explicit device serial. Launch the package and read the single sanitized JSON
line from Android log tag `DeepPqcProbe`. The probe never logs keys,
ciphertexts, shared secrets, device serials, or user data.

The 2026-08-30 physical runs are under [`evidence/`](evidence/). Both runs
passed round-trip, exact-length, public modulus, and embedded-public-key
corruption checks. Production eligibility remained false because:

- upstream status is experimental;
- `MLKemPrivateKeyParameters` does not expose deterministic disposal or
  zeroization of its retained seed/expanded private-key arrays;
- a same-length private coefficient mutation is accepted by the import API.

The provider remains an interoperability oracle and benchmark candidate, not a
production dependency.
