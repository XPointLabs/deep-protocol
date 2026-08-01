# P18A compact authenticated fragment evidence

Status: `contract-go-runtime-blocked`.

Human owner: Mr. X.

## Exact source and ancestry

- accepted protocol base:
  `b887fa088f486390be182cac4cbcb59b60ce8931`;
- required P03C ancestor:
  `261c77658c8ff1f51ba45116ca8d938b1336eaa9`;
- initial P18A source:
  `9678875578faa7e8ecf5231ce480a6ccc7b99ba3`;
- first reviewed source:
  `b34ac5f84d2e2e7e06bad347b66df18fa503d061`;
- final accepted source:
  `781054ea0c218f488e6176470901fe409f5397de`.

The final source was reached through explicit RED/GREEN corrections:

- `81c82ae` / `299324e`: recover ordinal zero under XOR reordering
  without extending descriptor expiry;
- `509cf1f`, `7308675`, `27f6e2c` / `8e7f745`: terminal
  reconciliation, relay descriptor, foreign-scope isolation and bounded
  corrupt-store enumeration;
- `7928d9d` / `3731052`: hard reconciliation timeout, caller cancellation
  and wrapped-fatal exception handling;
- `4ca7ec1` / `781054e`: deterministic late-fault race and unconditional
  fault-only continuation.

## Independent review history

The first review of `b34ac5f` was NO-GO because ordinal-zero recovery could
poison a valid message and terminal reconciliation/store records were
insufficient. The review of `8e7f745` was NO-GO because a store that ignored
cancellation could hang reconciliation and wrapped fatal cancellation could
be normalized. At `3731052`, one reviewer found the remaining late-fault
observation race.

Two reviewers independently re-ran and inspected exact source `781054e`:

| Review | Verdict | P0/P1/P2/P3 |
| --- | --- | --- |
| protocol/architecture | GO | 0/0/0/0 |
| security/resilience | GO | 0/0/0/0 |

No earlier verdict was carried forward after a source change.

## Implemented boundary

- exact `LF` V1 fixed-header/frame codec;
- strict policy-lowered parser with authentication before retained shard copy;
- exact `domain || direction || header || shard` transcript;
- canonical DPB1 descriptor, zero padding and expiry equality;
- `None` and one-XOR-per-eight planning/recovery, including ordinal zero;
- opaque provider-issued authentication and replay-scope handles;
- bounded durable replay-record interface with explicit live/terminal state;
- admission transaction and terminal generation CAS;
- bounded reconciliation even when a store ignores cancellation;
- observation of every late reconciliation fault;
- fatal and wrapped-fatal exceptions are never reduced to normal rejection;
- per-message, per-scope, global memory and tombstone ceilings;
- foreign-scope snapshots never poison the foreign scope;
- payload emission only after strict DPB1 decode and confirmed durable
  completion;
- completed output includes the canonical descriptor needed for relay
  refragmentation.

There is no production authenticator, durable replay-store implementation, DI
registration, radio, BLE/USB adapter, simulator, frequency/region/power
default or hardware behavior in P18A.

## Final verification

Environment: Windows ARM64, .NET SDK `10.0.301`, target `net10.0`, Release.
Restore ran with HTTP, HTTPS and ALL proxy values forced to an unavailable
loopback endpoint, `NuGetAudit=false` and local cached dependencies only. This
repository has no NuGet lock files, so this is offline-cache evidence rather
than a locked-restore claim.

| Gate | Result | SHA-256 |
| --- | --- | --- |
| offline restore | PASS | n/a |
| Release build | PASS, 0 warnings / 0 errors | n/a |
| focused P18A | PASS, 81/81 | `c24aa68cb4e2a91e15eede75335facf9ec9b44d68a71b5422aec93a1f86be0b5` |
| malformed/fuzz | PASS, 13/13 | `7779066dc7362a90bc0dd6ad1adb7b64fd7c1f21640c3d4f79bc6df29e08e44b` |
| full protocol | PASS, 254/254 | `f05c99e4de83df9864e2584a89a4c39e4e717bd584a967bb4221b419e953a18b` |
| coverage run | PASS, 254/254 | `70aa6c661a3f6a786b5572cd55887888f063875f30a58704f0693bd84693498d` |
| Cobertura | 5,053/8,971 lines; 1,902/4,483 branches | `c050de318d775469d2bebeb88fb78c4424f2b7ab0dadfe611657c64f6a403c4d` |
| format | PASS | n/a |
| diff check | PASS | n/a |

TRX, coverage and packages are local ignored artifacts under
`artifacts/survival/P18A`. Their exact hashes are also recorded in
`WORK_PACKAGE_REPORT.json`.

## Golden vectors and local packages

`lora-fragment-v1.json` contains canonical complete frames for `None` and
`Xor1`, reconstructed DPB1 bytes/SHA-256, descriptor, test domain/direction,
FEC mapping, limits and negative error names. Truncated HMAC-SHA-256 is
explicitly test-only and is absent from production source.

Local package version: `0.3.0-p18a.781054e`.

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| `Deep.Protocol` | 108,039 | `b409177196113371e1a127ddce0088b4e72fb69159f736c05a42e4bf5bcfbe97` |
| `Deep.Protocol.Abstractions` | 25,814 | `f84af1d36845ed532b11dfe2a916f68a35ea3a2030337389d436db411174fca0` |
| `Deep.Protocol.Protobuf` | 51,360 | `da1071205f4ed73a8e0884f00ab53fd6211fa166deff1d1759ef72bdaa159a3c` |

Every nuspec pins exact source
`781054ea0c218f488e6176470901fe409f5397de`. Packages are local-only and were
not published.

## Privacy, power, regulatory and commercial boundary

Fragment authentication is not encryption. Observers can still learn traffic
shape, size/count, timing, retries, loss, hop-local identifiers and radio
location. P18A does not claim global anonymity, unobservability, radio
unlinkability, triangulation/jamming resistance, deniability, forward secrecy,
range, acceptable battery use, censorship-proof delivery or background SLA.

The intended architecture assigns continuous receive to an externally powered
gateway, not the phone. P18A itself creates no scan loop, wake lock or
foreground service, but real battery evidence remains a P18C gate.

There is no legal or radio default. P18A has no XPNT, wallet, subscription,
entitlement, managed-node, reward or per-message dependency. Local/P2P use
remains in the free communication plane.

## Runtime blockers and handoff

Contract GO is not a working LoRa claim. P18B/P18C remain blocked by:

1. reviewed link-key provisioning and a production authenticator;
2. production durable replay/quota storage;
3. approved simulator repository ownership and P18B loss/airtime evidence;
4. named hardware and a current approved legal region profile;
5. BLE/USB lifecycle, bounded gateway queue and permissions;
6. mobile/Windows two-device E2E;
7. independent external cryptographic/privacy review;
8. real-device battery, airtime and radio-observability measurements.

No network download, Docker, deployment, blockchain, seed phrase, private key,
UAT/production credential, package publication, GitHub push or pull request
was used.
