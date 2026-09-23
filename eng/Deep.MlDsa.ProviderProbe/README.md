# ML-DSA-65 root-provider feasibility probe

This isolated `net10.0` console project is **not** referenced by the production
protocol or clients. It tests the pinned managed candidate's 32-byte-seed
recovery, signing/verification and two substitution negatives without printing
private material. Run `dotnet run -c Release --project
eng/Deep.MlDsa.ProviderProbe/Deep.MlDsa.ProviderProbe.csproj` from the
`deep-protocol` repository.

A successful functional result is **not** provider approval. The JSON always
reports `productionEligible: false` until independent FIPS 204 KAT/differential,
Android arm64 and Windows x64/arm64 execution, source/side-channel review and
deterministic secret-lifetime/zeroization gates close. Do not derive a release
Deep ID or freeze recovery vectors merely from this probe.

The pinned 2.7.0 NuGet package SHA-256 on the Windows arm64 lab host is
`F091FFCCAB4D03993E660BACE277659A79DEE0972F54D7F1F4BD46D680966241`.
The first Windows arm64 run on 2026-09-23 passed seed restoration,
sign/verify, message-tamper rejection and substituted-key rejection. It
observed a 1,952-byte public key and a 3,309-byte signature. The private-key
object has eight private `byte[]` fields and does not implement `IDisposable`;
the caller can wipe its own seed but cannot prove that retained copies are
cleared. The candidate is therefore not suitable for production identity
creation under the current zeroization gate.

`native_public_key_probe.c` uses the **public test seed** `00..1f` and writes
only its ML-DSA-65 public key. Compile it against `mldsa-native` v2.0.0 commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35` with
`MLD_CONFIG_PARAMETER_SET=65` and `MLD_CONFIG_NO_RANDOMIZED_API`, then pipe
the output through SHA-256. Compare that digest to
`testVectorPublicKeySha256` in the managed probe JSON. This is a
cross-provider keygen fixture, not yet the full FIPS 204 or signing
differential suite.

The Windows arm64 managed result and Linux/ARM64 native result both yielded
`d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9`.
The native source at the pinned commit also passed its upstream `run_func_65`
and `run_kat_65` (`META.yml ML-DSA-65 kat-sha256: OK`) inside Linux/ARM64
Docker. Physical Android native-provider checks are recorded in
`native/Deep.MlDsa/evidence/android-api31-arm64.v1.json`; Windows native-provider
gates remain open.

`native_signature_probe.c` drives the Deep-owned C ABI with the same public
`00..1f` seed, the message `Deep/PQRoot/signature-differential/v1`, empty FIPS
204 context and all-zero test randomness. Its signature SHA-256 on physical
Android arm64 matches the deterministic Bouncy Castle 2.7.0 signature on
Windows arm64:
`e8a6098e794cff6a62f2c3bceb0f2d4898d3630300f34264770e2845d321683a`.
This fixture is **test-only**: real signing must supply fresh CSPRNG randomness.
The cross-provider result proves this one transcript, not all FIPS 204 cases.
