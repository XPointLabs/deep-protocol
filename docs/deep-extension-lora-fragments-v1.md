# Deep extension LoRa fragments V1

Status: P18A local contract/vector slice; runtime activation blocked.

Human owner: Mr. X.

## Purpose and isolation

P18A fragments exact, already encrypted `DPB1` V1 bundle bytes for an optional
future external-radio carrier. It does not change Session protobufs, E2EE,
sender authentication, mailbox capabilities or opaque-bundle bytes. It is not
LoRaWAN, mesh routing, link encryption or a radio implementation.

The phone or Windows client remains the frame creator/verifier. A future
external BLE/USB gateway receives only bounded opaque frame bytes and owns
continuous radio receive. P18A contains no BLE/USB behavior, wake lock,
foreground service, radio parameter, hardware or background SLA.

## Canonical frame

Every frame is exactly:

```text
16-byte header || shardSize bytes || 16-byte authentication tag
```

The header is:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 2 | ASCII `LF` |
| 2 | 1 | version `1` |
| 3 | 1 | bit 0 `Xor1`; all other bits zero |
| 4 | 8 | nonzero opaque hop-local message ID |
| 12 | 1 | canonical ordinal |
| 13 | 1 | data shards, 1..64 |
| 14 | 1 | canonical parity shards, 0..8 |
| 15 | 1 | shard size, 8..192 |

Absolute ceilings are 224 encoded bytes per frame, 72 fragments, 4096 encoded
bundle bytes and `dataCount * shardSize <= 4352`. `LoRaFragmentPolicy` can only
lower the bundle, count and shard ceilings.

Message ID is random for a radio hop/attempt. It is not derived from and must
not equal a stable identity, Session ID, wallet, mailbox capability,
`TransportAttemptId` or `EndToEndDedupId`. A relay reassembles, increments the
hop, selects a fresh message ID/authentication context and re-fragments.

## Descriptor and FEC

The first ten bytes of data shard zero contain descriptor version `1`, payload
kind `1`, opaque-bundle version `1`, current-hop/hop-limit nibbles, exact
big-endian bundle length and expiry bucket. The exact DPB1 bytes follow and
all remaining capacity is zero.

Reassembly requires:

- `64 <= bundleLength <= 4096`;
- `currentHop < hopLimit <= 15`;
- exact `ceil((10 + bundleLength) / shardSize)` data count;
- zero final padding;
- strict `OpaqueBundleCodec.Decode` under the caller policy;
- exact equality between descriptor and decoded DPB1 expiry.

Canonical DPB1 padding means the smallest currently valid accepted bundle is
256 bytes even though the fragment parser's absolute lower declaration bound
is 64. An arbitrary 64-byte input does not become a valid DPB1 bundle.

`None` has no parity. `Xor1` has one full XOR parity shard for each consecutive
group of at most eight data shards. One missing data shard per group can be
recovered; two remain incomplete. No partial bundle is returned.

## Authentication boundary

The codec-owned domain is:

```text
Deep/P18A/LoRaFragmentAuth/v1
```

The authenticated transcript is exactly:

```text
domain || direction byte || header || shard
```

`ILoRaFragmentAuthenticator` receives the domain, direction, transcript and
an opaque provider-issued `LoRaFragmentAuthenticationHandle`. Public
production APIs cannot construct a handle from raw key, identity or Session
bytes. A future provider/authenticator must bind link and network/profile
scope. The tag is exactly 16 bytes.

No production authenticator, key derivation, secret store or DI registration
is shipped. The golden vectors use truncated HMAC-SHA-256 only as an explicitly
test-only deterministic adapter.

## Durable replay and quotas

`ILoRaFragmentReplayStore` has two atomic mutation boundaries:

- `ApplyAuthenticatedFragmentAsync` authenticates first, then atomically
  evicts expired state, checks tombstones/shape/quotas, reserves the complete
  message and copies one shard;
- `TryCommitTerminalAsync` generation-CASes `Completed` or `Poisoned` before
  the coordinator can return reconstructed DPB1 bytes.

`ReadAsync` is reconciliation-only. There is no production store
implementation or fallback. Incomplete state and completed/poisoned/expired
tombstones are durable through restart.

Per scope there are at most four incomplete messages; globally at most 16.
The exact global charge is
`(dataCount + parityCount) * shardSize + 256` per incomplete message and at
most 64 KiB. Descriptor-zero reordering uses a caller-supplied provisional
expiry inside the opaque policy window; descriptor arrival may only tighten
it. Tombstones are additionally bounded to 256 per scope, 1024 globally and
128 KiB of canonical logical records. Callers may lower, never raise, every
ceiling.

Exact authenticated duplicates are idempotent. A conflicting ordinal poisons
the replay key. Scope, direction and ID never mix. Unknown persistence outcome
never emits payload.

## Claims and blockers

Authentication is not encryption. An observer/gateway sees Deep-shaped
traffic, size/count, timing, retries, loss, hop-local IDs and radio/location
observations. Reconstructed data includes already documented DPB1 outer
metadata. There is no claim of global anonymity, unobservability,
radio-unlinkability, triangulation/jamming resistance, deniability, forward
secrecy, guaranteed range, battery acceptability or censorship-proof delivery.

P18A defines no frequency, region, spreading factor, bandwidth, transmit
power, duty cycle, dwell time, antenna or certification default. Runtime is
blocked by production link-key/authentication and durable replay adapters,
P18B feasibility, named P18C hardware, a current approved region profile,
two-device E2E, external security review and real-device battery evidence.

The transport is part of the free communication plane: no XPNT, wallet,
subscription, entitlement, managed node, reward or per-message/fragment fee.
