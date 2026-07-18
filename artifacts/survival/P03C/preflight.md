# P03C preflight

Status: ADR and red-vector phase. Human owner: Mr. X.

## Exact pins

- accepted P03B final GO evidence commit:
  `b1d74e5229137928bf9c70daa0dc133350a98c34`;
- accepted P03B work-package report Git-blob SHA-256:
  `22836f8e648f5d388b41b128610484669131fc4a53634f52765f9a8021f0f9f2`;
- accepted P03B package manifest Git-blob SHA-256:
  `1c820f59033bee6157ecc89c9d7123664f404a6b6a9f5a05703667be5f45f694`;
- P03C prompt SHA-256:
  `51f8d946df3498f2f3c5cefef389be6e2c671fa3c8c75cb63cabea74d9e9622c`;
- P03 work-package report SHA-256:
  `e691516691d85b0c34850430e7f5f493615658c8577344a7d8a8293b675ee0a2`;
- P03A work-package report SHA-256:
  `b08be0a0f7b047689356b1ade02a23abd47f53f49d16a3da13874af5e6e8f6a3`.

Branch `survival/w01-p03c-nearby-handshake` was fast-forwarded to the exact final P03B GO commit
before P03C edits.

## Crypto inventory decision

The repository has verified Ed25519 signing, Session sealed-box encryption and onion-request
primitives. None is an already reviewed transcript-bound mutually authenticated nearby AKE with
the required contact binding, key schedule, identity-disclosure timing and resumption semantics.
P03C therefore defines a high-level adapter contract and deterministic test-only vectors. It
ships no production adapter, registration or runtime default.

No BLE, permissions, Wi-Fi transfer, UI, background scheduler or deployment is in scope.
