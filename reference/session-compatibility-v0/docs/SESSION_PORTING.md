# Session Porting Spec - Protocol

Last updated: 2026-06-10.

## Scope

This document governs migration of Session wire, protobuf, envelope, namespace, state, onion-request, and crypto-adapter semantics into `deep-protocol`.

## Reference Sources

Primary sources:

- `../source/session-foundation/libsession-util` when available.
- protobuf files currently checked into `src/Deep.Protocol.Protobuf/Protos`.
- Golden vectors under `tests/Deep.Protocol.GoldenVectors`.
- Existing protocol docs in `docs/`.

If upstream source is unavailable, do not guess. Document the gap in `docs/unsupported-or-unspecified.md`.

## Porting Workflow

1. Identify the exact upstream type, namespace, protobuf field, or codec behavior.
2. Add or update a golden vector when the behavior is wire-visible.
3. Add malformed-input coverage for parsers.
4. Add differential coverage when upstream tooling or known outputs exist.
5. Implement behind existing abstractions.
6. Update docs and compatibility matrix.

## Crypto Rules

- Production crypto must use verified adapters.
- Fake crypto may exist only in tests.
- Missing sodium behavior must be represented as unsupported, not approximated.
- Never log private keys, plaintext secret material, or recovery data.

## Compatibility Areas

- Session IDs and identity encodings.
- Message envelopes and padding.
- Onion request models/codecs.
- Shared config namespace parsing/state.
- Group update parsing.
- Protobuf resources.
- Proof-of-work/proof services where applicable.

## Accepted Deviations

- Managed C# implementation is allowed if output vectors match Session.
- Unsupported areas may throw explicit exceptions instead of silently producing incompatible output.
- Deep extensions must be documented as extensions and kept separate from Session wire compatibility.

## Evidence Checklist

- upstream reference,
- vector or differential test,
- parser negative tests,
- docs updated,
- downstream impact noted.

## Stop-The-Line Conditions

- A fake adapter reaches production code.
- A vector changes without an intentional migration note.
- A protobuf field number/name is changed without upstream evidence.
- Unsupported behavior is silently accepted.
