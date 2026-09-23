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
