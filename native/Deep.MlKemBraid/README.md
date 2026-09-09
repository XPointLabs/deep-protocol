# Deep ML-KEM Braid native provider

This directory contains the pinned Rust `cdylib` producer for the incremental
ML-KEM Braid ABI. The release-approved Windows x64 and ARM64 binaries are
packaged by `Deep.Protocol`; Android remains a separate candidate gate.

The C ABI wraps the incremental ML-KEM-768 API from exactly
`libcrux-ml-kem 0.0.10`. `Cargo.lock` pins the complete crates.io closure. The
published crate checksum, source commit/tag, declared license, and local license
file hashes are recorded in `third-party/libcrux/provenance.json`.

The published crate declares `Apache-2.0`. Although the source repository also
contains `LICENSE-MIT`, this spike conservatively consumes the crate under
Apache-2.0 and does not claim dual licensing.

## ABI ownership

- `KeypairFromRandom` and `Encaps1FromRandom` are deterministic test/vector
  entry points. Callers must provide cryptographically secure random bytes when
  using them outside tests.
- `KeypairGenerate` and `Encaps1Generate` use the operating-system CSPRNG through
  `getrandom`.
- `Encaps1` returns `ct1` and a process-local opaque `uint64_t` handle. It does
  not release the shared secret.
- `Encaps2` validates the exact seed and `H(vector || seed)`, atomically consumes
  the handle, and only then releases `ct2` and the shared secret.
- A handle is single-consumer. Wrong-key attempts after valid argument
  validation also consume it. Replay, concurrent reuse, and double-free return
  `INVALID_HANDLE`.
- At most 1,024 unfinished Encaps1 states may exist in one process. Capacity
  exhaustion fails closed before inserting another state, bounding retained
  secret memory even when callers abandon handles.
- Owned incremental state and shared-secret buffers are zeroized on completion,
  explicit free, validation failure, or unwind. After null/length/overlap
  validation, outputs are zeroed before fallible operations; rejected arguments
  do not mutate caller memory.
- Every FFI operation has a `catch_unwind` boundary. Allocation failure can
  still abort the process under Rust's global allocator and remains a
  production-hardening decision.

## Build gates

Application/release consumers do not rebuild this provider locally. The build
commands below are producer-side evidence tools. A production RID may consume
only a ready official Deep Braid ABI binary with matching signed/attested
official workflow evidence, provenance, export surface and reviewed hash. A generic
`libcrux-ml-kem` binary is not ABI-compatible with this wrapper.

Run from the repository root:

```powershell
./eng/Build-DeepMlKemBraid.ps1
```

The bounded spike builds Windows x64 with Rust 1.89.0, rejects warnings, runs
the Rust interoperability/adversarial tests, verifies the exact DLL export
allowlist, builds a separate C consumer, and runs its ABI probe. The official
workflow builds x64 and ARM64 twice in clean output roots with `/Brepro` and
rejects any DLL or import-library digest drift.

The isolated Android ARM64 gate uses exact NDK 28.2.13676358 (r28c), API 26,
and the pinned Rust toolchain. It verifies the `.so` export allowlist,
dependencies, RELRO/NOW hardening, and builds a `dlopen`-based native probe:

```powershell
./eng/Build-DeepMlKemBraid.ps1 -Target android-arm64
```

To run it on one explicitly selected, connected arm64 device, also provide
`-DeviceSerial` and `-AdbPath`. The probe performs two CSPRNG
keygen/Encaps1/Encaps2/decapsulation round trips across unload/reload, rejects
handle replay and double-dispose, and emits no key or ciphertext bytes. It is
copied only to `/data/local/tmp/deep_mlkem_braid_probe_v1`; no APK, production
package, application data, or production build graph is touched.

## Supply-chain and release evidence

The original Windows x64 and Android ARM64 candidate evidence remains under the
`evidence/candidate-*` paths. Android is still candidate-only and is not added
to a production package.

The approved Windows evidence is under `evidence/official-windows-5109980`.
Official workflow run 34356754852 attempt 1 built x64 and ARM64 twice in clean,
isolated target roots with `/Brepro`; the DLL and import-library bytes matched.
The exact artifact binaries then passed the managed state-machine and wrapper
probes on a physical Windows ARM64 host, natively for ARM64 and through Windows
x64 emulation for x64. GitHub artifact attestation was unavailable for the
private organization plan, so the official workflow record, committed hashes,
and physical acceptance record form the closed substitute evidence.

The bounded evidence package is:

- `evidence/candidate-manifest.v1.json`: fixed source, toolchain, artifact,
  export, hardening, dependency, and test expectations;
- `evidence/candidate-windows-x64-sbom.cdx.json`: the exact 22-component
  Windows x64 Cargo closure, including the root component;
- `evidence/candidate-android-arm64-sbom.cdx.json`: the exact 21-component
  Android arm64 Cargo closure, including the root component.

The SBOMs are target-specific because Cargo resolves a different closure for
Windows and Android. They are deterministic CycloneDX 1.5 documents without a
timestamp or random serial number. The gate derives both closures again with
the pinned Cargo toolchain in locked, offline mode and verifies every cached
crate archive against its `Cargo.lock` checksum; it does not trust package or
artifact hashes supplied on the command line.

Verify existing outputs without rebuilding:

```powershell
./eng/Test-DeepMlKemBraidEvidence.ps1
```

Rebuild both evidenced targets and rerun the Android device probe:

```powershell
./eng/Test-DeepMlKemBraidEvidence.ps1 -Rebuild `
  -DeviceSerial '<explicit-serial>' `
  -AdbPath '<absolute-path-to-adb.exe>'
```

The rebuild gate requires an explicitly selected Android device so a static
Android build cannot be mistaken for execution evidence. It recomputes binary
size and SHA-256, checks the exact 17-symbol ABI allowlist, validates PE/ELF
identity and imported libraries, and enforces CFG/ASLR/NX or RELRO/NOW and a
non-executable stack as appropriate.

Run the bounded hostile drift tests separately:

```powershell
./eng/Test-DeepMlKemBraidEvidenceDrift.ps1
```

Windows x64 and ARM64 consumers load only the package-relative binary whose
length, SHA-256, provider identifier, and production-approval flag match the
closed managed allowlist. Other operating systems and architectures fail closed.
