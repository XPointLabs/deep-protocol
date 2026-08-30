# Deep ML-KEM v1 native provider

This directory implements the Deep-owned ML-KEM-768 C ABI without a Rust
runtime or Rust production-build dependency. The provider is the portable C
subset of `pq-code-package/mlkem-native` v2.0.0, pinned to commit
`d1b2fe782888bdb761a50336012923180be7f502`.

## ABI and key representation

`include/deep_mlkem_v1.h` is the only consumer ABI. Provider symbols and the
provider's 2400-byte expanded decapsulation-key serialization are private. The
provider is linked as an internal static library into the final shared runtime:
`deep_mlkem.dll` on Windows and `libdeep_mlkem.so` on Android. Only the ten
Deep-owned v1 functions are exported; the Windows calling convention and all
platform visibility attributes are explicit.
Deep persists only its internal seed-backed private-key representation `d || z`
(64 bytes). This is not the canonical 2400-byte FIPS 203 `dk` serialization.
Key generation and decapsulation deterministically expand the seed into a local
FIPS 203 `dk`, then wipe it before returning.

The wrapper rejects null pointers, non-exact lengths, address wraparound, and
every pairwise overlap before touching output. Provider calls write to local
buffers first, so caller outputs remain unchanged on argument or provider
failure. Exact-size ciphertexts use ML-KEM implicit rejection and therefore
produce a shared secret rather than an invalid-ciphertext status.

`deep_mlkem_provider_zeroize` is an OpenSSL-free, no-inline volatile-store
implementation with a compiler barrier. It is configured as mlkem-native's
custom zeroizer, so it covers provider intermediate buffers as well as all
Deep wrapper temporaries. As with any C implementation, this does not promise
erasure of compiler-created copies or registers after process termination.

## Vendoring

Upstream files are byte-exact Git blobs and are never locally patched. Deep
configuration and wrapper code live separately under `src/`. The selected
portable source, upstream license, deterministic known-answer vector, Git blob
IDs, and SHA-256 values are recorded in
`vendor/mlkem-native.provenance.json`. The build verifies every vendored hash.

The vendored subset contains:

- `mlkem/mlkem_native.c` and `mlkem/mlkem_native.h`;
- portable `mlkem/src` C and header files, excluding every native/assembly
  backend;
- the exact upstream `LICENSE`;
- `test/test_vectors/expected_test_vectors.h` for the upstream deterministic
  ML-KEM-768 known-answer test.

## Build

The production build uses CMake and Ninja bundled with Visual Studio 2022
Build Tools. No global CMake/Ninja or Rust toolchain is used.

```powershell
pwsh -File .\eng\Build-DeepMlKem.ps1 -BuildTarget windows-x64
```

By default every target is built twice from separate clean build directories,
and shared-runtime/import-library hashes must match. The published directory is
a closed set: shared runtime plus the Windows import library, with no provider
static library. Unknown files or directories anywhere below the publish root
reject the build. Windows uses the static MSVC runtime and the final PE import
allow-list rejects an external VC/UCRT dependency. Windows x64 executes both the native C test binary and the
unreferenced .NET 10 `LibraryImport` probe on both passes. The reviewed VS,
MSVC x64 compiler/linker/librarian/inspector, CMake, CTest, Ninja and .NET host
binaries are pinned by the script. The selected Windows SDK version and required
file closure are recorded; a hermetic full-SDK image is still a release hardening
item. `-SkipReproducibilityCheck` is only for local iteration.

The script checks the exact dynamic export table and hardening of the final
DLL/SO rather than only its constituent objects. Windows requires CFG, DEP/NX,
ASLR and high-entropy VA. Android requires hidden-by-default symbols, stack
protection and full RELRO/NOW.

Windows-only target selections do not require an Android NDK. Android arm64
requires an explicit NDK root and rejects every revision except
`28.2.13676358`; it builds the portable backend for `arm64-v8a`, API 28:

```powershell
pwsh -File .\eng\Build-DeepMlKem.ps1 `
  -BuildTarget android-arm64 `
  -AndroidNdkRoot C:\path\to\android-ndk-r28b
```

## Tests and remaining gates

The native executable covers ABI sizes, the exact upstream deterministic KAT,
repeatable key generation and encapsulation, roundtrip decapsulation, strict
length/null/overlap handling, noncanonical public-key rejection, ML-KEM
implicit rejection, explicit zeroing, and unchanged outputs on observed
failures.

`eng/Deep.MlKem.ManagedProbe` is deliberately absent from production solutions
and project references. It loads the built DLL by absolute path, exercises the
managed Span/owned-secret wrapper, and verifies KAT hashes, roundtrip, exact
implicit rejection, invalid-public-key behavior, disposal zeroization, and the
known runtime export surface.

The upstream deterministic KAT is not a substitute for an ACVP validation
campaign. Production enablement remains gated on ACVP vectors, Android arm64
build plus physical-device tests with the pinned NDK, Windows arm64 cross-build
plus runtime tests, and independent security review of the final binaries.
