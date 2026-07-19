# P03D handoff

Status: `contract-only-awaiting-human-and-external-crypto-review`

## Delivered contract

`Deep.Protocol.DeepExtension.NearbySecureChannels` defines:

- bounded opaque account, device and transcript identifiers;
- device credential roster epoch, validity and revocation state;
- opaque local device-key handle;
- fixed `UnassignedPendingExternalCryptoReview` profile;
- fresh-only AKE context over the existing P03C binding;
- initiator/responder flights restricted to AKE bytes;
- authenticated-peer and pending-session boundaries;
- durable replay claim/classification/acceptance/committer contracts;
- opaque secure-session `Seal`/`Open` record boundary;
- bounded directional opened-record result and explicit fail-closed errors.

All input byte buffers are copied. Opaque values redact `ToString()`.
Resumption is rejected. Replay acceptance binds local and peer device IDs,
transport attempt, transcript digest and roster epoch. The P03D namespace has
no concrete AKE, replay committer, pending session or secure channel.

## Deliberately absent

- production cryptography or approved suite;
- discovery hint derivation;
- static, ephemeral or traffic-key bytes;
- record encoding, AEAD, counters, nonces or rekey implementation;
- credentials, keys or secret generation;
- credential verification and device-roster authority;
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

- RED focused tests: compiled; 7 expected failures before implementation;
- GREEN focused P03D tests: 7 passed, 0 failed;
- Release build: succeeded with 0 warnings and 0 errors;
- full protocol tests: 261 passed, 0 failed, 0 skipped;
- `dotnet format --verify-no-changes`: passed;
- `git diff --check`: passed.

Independent internal reviews, external cryptographic review, cross-language
verification and physical-device evidence are not complete. Runtime activation
remains NO-GO.
