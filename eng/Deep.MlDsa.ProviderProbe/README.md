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
