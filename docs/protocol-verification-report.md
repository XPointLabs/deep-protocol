# Protocol Verification Report (B3)

Updated: 2026-05-29

## Scope

This report summarizes protocol-level parity evidence added in B3:

- Expanded golden vectors from upstream deterministic fixtures.
- Cross-language differential tests against direct sodium/protobuf behavior.
- Parser/codec fuzzing gates in CI.

## Test Gates

CI workflow: `.github/workflows/ci.yml`

Mandatory protocol gates:

- `Protocol golden-vector gate` (`GoldenVectorTests`)
- `Protocol differential gate` (`SodiumDifferentialTests`, `CrossLanguageDifferentialTests`)
- `Protocol fuzz-smoke gate` (`ProtocolFuzzSmokeTests`, `ProtocolParserCodecFuzzTests`)

Any regression in these suites fails CI.

## Scenario Coverage Matrix

| Scenario | Evidence | Status |
| --- | --- | --- |
| 160-byte padding and unpadding boundaries | `GoldenVectorTests.PaddingMatchesLibsessionVectors` + vectors for `hello`, empty, and 159-byte payload | Covered |
| Deterministic key derivation parity (seed -> Ed25519 -> X25519/session id) | `GoldenVectorTests.SessionIdParsesKnownSourceTestVectors`, `GoldenVectorTests.DeterministicKeyExpansionMatchesUpstreamFixtures` | Covered |
| Proto content serialization parity | `GoldenVectorTests.ContentProtobufSerializationMatchesGoldenVector` | Covered |
| Sodium parity for signing, conversion, blinded recipient, recipient encryption | `SodiumDifferentialTests` | Covered |
| 1:1 codec output decryptability by direct sodium | `CrossLanguageDifferentialTests.OneToOneCodecCiphertextDecryptsWithDirectSodium` | Covered |
| Group codec output decryptability and envelope parse via direct sodium | `CrossLanguageDifferentialTests.GroupCodecCiphertextDecryptsWithDirectSodium` | Covered |
| Onion layered request build/decrypt parity vs direct sodium sealed-box operations | `CrossLanguageDifferentialTests.OnionBuildLayeringAndResponseDecryptMatchDirectSodium` | Covered |
| Robustness on malformed/random protocol payloads | `ProtocolFuzzSmokeTests`, `ProtocolParserCodecFuzzTests` | Covered |

## Remaining Risk Areas

The following areas remain open and are tracked as parity blockers/risk:

1. Full Groups v2 config/key lifecycle parity (`groups/info`, `groups/members`, `groups/keys`, rekey state).
2. Full upstream bt encoding parity details for all groups internals.
3. Onion network-layer parity: path construction/repair, strike accounting, cache persistence, scheduler behavior.
4. Deeper protobuf/parser fuzzing (coverage-guided fuzzing with corpus minimization) is not yet wired; current gates are deterministic random fuzz-smoke tests.

## Suggested Next Verification Hardening

1. Add corpus-guided fuzzing job (AFL/libFuzzer or SharpFuzz-style harness) for envelope/community/group/onion parsers.
2. Add upstream fixture sync script to import new deterministic vectors from `source/libsession-util/tests` into golden vector json.
3. Add nightly long-run fuzz matrix with persisted crash corpus artifacting.
