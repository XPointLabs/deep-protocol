# P18A contract/vector evidence

Status: corrective source and local packages awaiting two independent reviews.

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
- initial green source:
  `9678875578faa7e8ecf5231ce480a6ccc7b99ba3`;
- post-auth mutation RED/fix:
  `35957f1c42fe78484159b521183c924972e4e993` /
  `a2ed0df`;
- cross-scope and malformed-parity REDs:
  `8eebc84` and `ce2d802`;
- replay-scope/parity corrective source:
  `94b7a4d`;
- terminal-record RED/fix:
  `bb6406b` / `ac0917b`;
- authenticated-transcript ownership correction:
  `0a8d7a2`;
- quota/expiry and descriptor/vector acceptance:
  `21623d0` and `b34ac5f`;
- accepted source:
  `b34ac5f84d2e2e7e06bad347b66df18fa503d061`.

The initial focused RED was compiling and produced 3 expected failures with
11 passing cases. Later RED commits added behavioral, malformed, memory-order,
restart and FEC regressions before the final source commit.

## Implemented boundary

- exact `LF` V1 fixed header/frame codec;
- strict policy-lowered parser with one bounded authenticated transcript
  reused as the ephemeral pre-admission frame view;
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
| focused P18A | PASS, 71/71 |
| malformed/fuzz | PASS, 13/13 |
| full protocol | PASS, 244/244 |
| format | PASS |
| diff check | PASS |
| line coverage | 4,942/8,830, 55.97% |
| branch coverage | 1,855/4,401, 42.15% |

Result SHA-256 values are recorded in `WORK_PACKAGE_REPORT.json`.

## Golden vectors and packages

`lora-fragment-v1.json` contains complete canonical frames for `None` and
`Xor1`, exact reconstructed DPB1 bytes/SHA-256, descriptor, test domain and
direction, FEC mapping, limits and negative error names. HMAC-SHA-256 truncated
to 16 bytes is labeled deterministic test-only and does not exist in
production source.

Local package version: `0.3.0-p18a.b34ac5f`.

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| `Deep.Protocol` | 106,383 | `49293dcca54fcb8667c1842ba62afa8b7b3fb7f6f8cad0ed4604365129669723` |
| `Deep.Protocol.Abstractions` | 25,665 | `321d40ec8ec67b20420952b8bd59460f92e7c3dced785725ce78f44be8e5856d` |
| `Deep.Protocol.Protobuf` | 51,187 | `de9b2aaed49649a6b13df75ca8457574c3a79f5819d9e55f2f7f665d7d2581d4` |

Every nuspec pins exact source
`b34ac5f84d2e2e7e06bad347b66df18fa503d061`. Packages are local-only and were
not published.

## Inventory and dependency proof

The accepted-source diff is limited to the four P18A production files,
P18A-focused tests/vector catalog, the P18A ADR/spec, required protocol
surface/compatibility/verification/unsupported documents, and local P18A
evidence. It changes no protobuf, existing Session wire path, client, XNode,
DevOps, Docker or blockchain file.

A case-insensitive production scan of the P18A namespace and protocol project
found no `wallet`, `billing`, `staking`, `reward`, `entitlement`, `XPNT` or
`subscription` reference. The production assembly test also rejects those
assembly/namespace dependencies and proves the deterministic authenticator is
test-only.

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
