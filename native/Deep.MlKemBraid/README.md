# Deep ML-KEM Braid native spike

This directory is an isolated, non-production Rust `cdylib` feasibility spike.
It is not referenced by a managed project, package, registry, or production
build graph.

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

Application/release consumers do not rebuild this candidate locally. The build
commands below are producer-side evidence tools. A production RID may consume
only a ready official Deep Braid ABI binary with matching signed/attested
manifest, SBOM, provenance, export surface and reviewed hash. A generic
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

## Candidate supply-chain evidence

This remains candidate-only evidence. It does not approve this provider for
production, change a managed runtime provider, or add the native library to a
production package or registry.

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

Windows ARM64 is cross-built by the official workflow and remains pending until
the exact binary has passed the managed production wrapper on a physical ARM64
Windows host and its reviewed release evidence is committed.
