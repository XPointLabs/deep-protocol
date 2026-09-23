# Deep ML-DSA-65 native provider candidate

This is an isolated provider implementation for the Deep ID clean break. It is
**not** referenced by `Deep.Protocol` or a client release. The sole upstream
implementation is `pq-code-package/mldsa-native` v2.0.0, commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`, vendored unmodified under
`vendor/mldsa-native/mldsa`. Its `LICENSE` is included. The configuration
selects only ML-DSA-65, portable C, and the caller-randomized internal signing
API; the upstream randomized API and external RNG linkage are excluded.

The Deep-owned eight-symbol ABI accepts a protected 32-byte seed and
caller-supplied fresh 32-byte hedging randomness, derives the expanded key
only within the call, and clears its temporary secret buffers before return.
The caller must independently clear its input seed and randomness. It never
exports an expanded private key. Root transcript/context and recovery KDF are
not frozen by this provider boundary.

Build and run the native tests with CMake from an isolated build directory.
Do not copy an output library into `Deep.Protocol/runtimes` or activate it in
the client until exact asset provenance, Windows x64/arm64 and physical Android
arm64 tests, FIPS 204 KAT/differential, lifecycle/side-channel review and the
DR-0006 wire freeze are complete.

On 2026-09-23 the Linux/ARM64 CMake release test and ASan/UBSan debug test
passed. The same test source was cross-compiled with Android NDK
28.2.13676358 and passed on a physical Android 12/API 31 arm64 device, both
as a directly linked test and through the shared library's exact eight-symbol
ABI;
see `evidence/android-api31-arm64.v1.json`. The candidate also passed the
repository's exact-three production graph and immutable reference-corpus
checks. None of these results alone approves a packaged Android or Windows
release asset.

The CMake test `deep_mldsa_65_upstream_kat` reproduces the pinned upstream
`gen_KAT.c` transcript and checks its SHA-256 against the ML-DSA-65 value in
the pinned upstream `META.yml`:
`2ff0ddcd0dc08b746aa04853d6f84c82c6c8ac38783c9061aed78e29c1698ae5`.
It passed on Linux arm64 and a physical Android API 31 arm64 device. This
tests the selected backend against the upstream KAT; platform-complete ACVP,
independent differentials and production packaged runtime load remain open.

`eng/Test-DeepMlDsaAcvp.py` checks the Deep shared-library ABI against SHA-256-
pinned official ACVP-Server `v1.1.0.43` JSON: all 25 ML-DSA-65 keyGen cases,
30 seed-format pure external sigGen cases (15 deterministic and 15 randomized),
and 15 pure external sigVer cases (3 positive, 12 negative). This passed on
Linux arm64. CI is configured to run it on Linux x64/arm64. It does not claim
coverage for prehash, expanded-key or external-μ interfaces, which the Deep
ABI excludes.

The same 70 pinned cases also passed inside the Release/AOT .NET Android
probe on a physical API 31 arm64 device. The APK bundled the exact candidate
`.so` and official JSON assets, checked all digests on-device, then was
uninstalled. It also passed public-key/signature differential fixtures,
verification, tamper rejection and native buffer clearing. See
`evidence/android-api31-arm64.v1.json`. This does **not** approve an asset
for the production client or establish Windows parity.
