# P18A contract/vector evidence

Status: green source and local packages awaiting two independent reviews.

Human owner: Mr. X.

## Exact commits

- accepted base:
  `b887fa088f486390be182cac4cbcb59b60ce8931`;
- required P03C ancestor:
  `261c77658c8ff1f51ba45116ca8d938b1336eaa9`;
- preflight/initial ADR:
  `e035ad92c1dd3bbc1c758179b2b34f9f26e257b1`;
- compiling public-surface RED:
  `1328e839acaed85878def7aa4eeb35ba45c5e16b`;
- atomic replay/quota ADR correction:
  `960ec3543aece7ad4b57384209debaa14a13278b`;
- codec/planner behavioral RED:
  `ec43ba39fcf64af530e7305a6bf2794956a5df26`;
- malformed/fuzz RED:
  `0c68647eb13d00370e99d98f9fc7c7524d63f720`;
- replay/restart/FEC RED:
  `4553eb27fd6165adc9e75c755ee78c4814c6e0bf`;
- complete vector RED:
  `d21270ebd0c72c5e1854632a0f4fa0d01db0e10c`;
- green source:
  `9678875578faa7e8ecf5231ce480a6ccc7b99ba3`.

The initial focused RED was compiling and produced 3 expected failures with
11 passing cases. Later RED commits added behavioral, malformed, memory-order,
restart and FEC regressions before the final source commit.

## Implemented boundary

- exact `LF` V1 fixed header/frame codec;
- strict policy-lowered parser with auth before retained shard copy;
- exact `domain || direction || header || shard` transcript;
- canonical DPB1 descriptor, zero padding and expiry equality;
- `None` and one-XOR-per-eight planning/recovery;
- opaque provider-issued authentication and replay-scope handles;
- two-mutation durable replay interface with admission transaction and
  terminal generation CAS;
- explicit provisional expiry for ordinal-zero reordering;
- per-message, per-scope, global memory and tombstone ceilings;
- payload emission only after strict DPB1 decode and durable completion.

No production authenticator, durable store, key derivation, DI registration,
BLE/USB, radio, simulator, frequency/region/power default or hardware behavior
exists.

## Verification

Environment: Windows ARM64, .NET SDK `10.0.301`, target `net10.0`, Release.
Restore ran with network proxies forced to an unavailable loopback endpoint
and resolved only existing local package-cache content. This repository has no
NuGet lock files, so the report does not claim locked restore.

| Gate | Result |
| --- | --- |
| exact base and P03C ancestry | PASS |
| W1/W2 detached raw hashes | PASS |
| offline restore | PASS |
| Release build | PASS, 0 warnings, 0 errors |
| focused P18A | PASS, 45/45 |
| malformed/fuzz | PASS, 13/13 |
| full protocol | PASS, 218/218 |
| format | PASS |
| diff check | PASS |
| line coverage | 4,881/8,767, 55.67% |
| branch coverage | 1,808/4,375, 41.32% |

Result SHA-256 values are recorded in `WORK_PACKAGE_REPORT.json`.

## Golden vectors and packages

`lora-fragment-v1.json` contains complete canonical frames for `None` and
`Xor1`, exact reconstructed DPB1 bytes/SHA-256, descriptor, test domain and
direction, FEC mapping, limits and negative error names. HMAC-SHA-256 truncated
to 16 bytes is labeled deterministic test-only and does not exist in
production source.

Local package version: `0.3.0-p18a.9678875`.

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| `Deep.Protocol` | 105,921 | `4f6f7fdfc8ea36b5c64369995d1ab83c741fd02b4b3ac55d5989f30096961cc1` |
| `Deep.Protocol.Abstractions` | 25,679 | `6fdce7098e41c8877f3e1e033c6469b9da3d1c579f9fac2231a43d765f91140b` |
| `Deep.Protocol.Protobuf` | 51,188 | `8cbbc679d591dfe5feb4ad67107ed36ce93c6ac181f9ff5efeb1f7114c7a596c` |

Every nuspec pins exact source
`9678875578faa7e8ecf5231ce480a6ccc7b99ba3`. Packages are local-only and were
not published.

## Privacy, power, regulatory and commercial boundary

Fragment authentication is not encryption. Observers can learn traffic shape,
size/count, timing, retries, loss, the hop-local message ID and
radio/location observations. P18A does not claim global anonymity,
unobservability, radio unlinkability, triangulation/jamming resistance,
deniability, forward secrecy, range, acceptable battery use, censorship-proof
delivery or background SLA.

The external powered radio, not the phone, is intended to own continuous
receive. P18A requires no scan loop, wake lock or foreground service, but this
is architecture only; real battery evidence remains a P18C blocker.

There is no frequency, region, bandwidth, spreading factor, transmit power,
duty-cycle, dwell-time, antenna or legal default. P18A is in the free
communication plane and has no XPNT, wallet, subscription, entitlement,
reward, managed-node or per-message dependency.

## Runtime blockers and handoff

P18B/P18C must not interpret contract green as working LoRa. Runtime remains
blocked by:

1. reviewed link-key provisioning and production authenticator;
2. production durable replay/quota implementation;
3. P18B vector-pinned loss/airtime feasibility;
4. named P18C hardware and approved current region profile;
5. BLE/USB lifecycle, bounded gateway queue and permissions;
6. mobile/Windows two-device E2E;
7. external cryptographic/privacy review;
8. real-device battery, airtime and radio-observability evidence.

## Non-actions

No network download, Docker, deployment, blockchain, seed phrase, private
key, UAT/production credential, package publication, GitHub push or pull
request was used. The permitted final label is
`contract-go-runtime-blocked`, and only after both independent reviews have no
unresolved P0/P1/P2.
