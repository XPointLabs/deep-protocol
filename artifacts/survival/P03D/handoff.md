# P03D handoff

Status: `contract-only-awaiting-human-and-external-crypto-review`

## Delivered contract

`Deep.Protocol.DeepExtension.NearbySecureChannels` defines:

- bounded opaque account, device and transcript identifiers;
- untrusted credential descriptors and verifier-issued opaque credential
  capabilities with visible roster epoch, validity and revocation state;
- provider-issued local device-key handle binding the verified local
  credential to an opaque platform-key reference;
- fixed `UnassignedPendingExternalCryptoReview` profile;
- fresh-only AKE context over the existing P03C binding;
- disposable initiator/responder flights restricted to AKE bytes, with
  exactly-once state/pending transfer;
- authenticated-peer and pending-session boundaries;
- exact value-equal replay claim owned by the pending session;
- one-shot async activation through a durable replay committer returning only
  commit classification;
- opaque secure-session `Seal`/`Open` record boundary;
- role-derived send/receive directions, directional opened-record result and
  explicit fail-closed errors.

All input byte buffers are copied. Opaque values redact `ToString()`.
Opaque identifiers/digests and replay claims have value equality/hash.
Resumption is rejected. The pending base validates its local device, peer
device, transport attempt and roster epoch against the immutable AKE context.
It supplies that exact claim to the committer, rejects concurrent/repeated
activation, and disposes non-fresh outcomes. There is no reusable replay
acceptance object. `Seal` has no direction selector, and the abstract secure
session base rejects an opened result in the reflected direction. The P03D
namespace has no concrete AKE, replay committer, credential verifier, key
provider or secure channel.

## Deliberately absent

- production cryptography or approved suite;
- discovery hint derivation;
- static, ephemeral or traffic-key bytes;
- record encoding, AEAD, counters, nonces or rekey implementation;
- credentials, keys or secret generation;
- credential signature verification and device-roster authority;
- durable replay/period/roster persistence;
- DI/runtime activation;
- shared-client, MAUI, BLE/Wi-Fi or QR behavior;
- cross-language crypto vectors or production packages.

## Downstream handoff

`deep-client-shared` must eventually provide durable replay commit,
monotonic roster/period state and verified credential/provisioning material.
It must not reuse message replay or P07 membership trust as device trust.

P12 may depend on `INearbySecureSession` only after a reviewed AKE adapter and
durable replay committer exist. It must not consume P03C raw session-key
results or implement its own AEAD/nonce logic.

## Verification

Local verification is recorded as work-package engineering evidence only:

- initial RED focused tests: compiled; 7 expected failures before the initial
  contract implementation;
- corrective RED test project: 23 expected compile errors before the
  ownership/capability topology existed;
- corrective GREEN focused P03D tests: 22 passed, 0 failed;
- Release build: succeeded with 0 warnings and 0 errors;
- full protocol tests: 276 passed, 0 failed, 0 skipped;
- `dotnet format --verify-no-changes`: passed;
- `git diff --check`: passed.

Independent internal reviews, external cryptographic review, cross-language
verification and physical-device evidence are not complete. Runtime activation
remains NO-GO.
