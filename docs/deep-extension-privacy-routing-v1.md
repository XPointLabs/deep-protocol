# Deep extension privacy routing V1 — ONION-01 frozen codec and production boundary

Status: **FROZEN_CODEC_IMPLEMENTED_PUBLIC_API_INACTIVE**. This is the single
normative source for ONION-01 bytes and the clean-break production API boundary.
The exact byte codec and deterministic conformance seam are implemented, but
`runtimeActivation=false`: the production public API, listener, relay, mailbox
adapter and compatibility readers remain unavailable until section 8 gates pass.

Contract identifier: `Deep.Protocol/Deep-extension-privacy-routing-v1`.

## 1. Scope, rejection and common rules

This Deep-only extension carries one exact canonical terminal request through
exactly three independently keyed XNodes: ingress relay, core relay, service
exit. Terminal operations are authenticated mailbox Store/Retrieve/Acknowledge,
Contact Resolver, and GroupControl. It does not change DNP1, ContactV1, ApplicationCore, MSG, DEVICE, MAU2,
MQR3/MRP1/MAR1, PRQ2, or mailbox placement bytes. All integers are unsigned
big-endian. Every reserved byte and every padding byte is zero. Unknown magic,
version, suite, purpose, layer kind, operation, result kind, failure code or
non-canonical length rejects before forwarding, callback, network I/O, replay
mutation, or mailbox dispatch.

Only these records are ONION-01: `XRF1`, `XRL1`, `XRE1`, `XPR1`, `XRS1`.
`DRF1`, `DRL1`, `DRE1`, `DPR1`, and `DRS1` are hostile legacy inputs for this
extension and reject by the first four bytes. ONION-01 never offers a legacy
reader, contextual alias, length heuristic, or Sodium `PublicKeyBox` fallback.
`DPR1` and `DRS1` retain only their DNP1 meanings.

All 32-byte IDs, X25519 public keys, replay IDs, operation IDs and attempt IDs
below must be nonzero. Ed25519 and X25519 keys are independently generated;
conversion is forbidden. A receiver rejects an all-zero X25519 public input
before scalar multiplication and rejects an all-zero X25519 shared secret.

## 2. Limits, exact route and trusted time

| Item | Exact bound |
| --- | ---: |
| request route hops | exactly 3 |
| `networkId` | 16 bytes |
| router ID, key-owner ID, key ID, replay ID, operation ID, attempt ID | 32 bytes, nonzero |
| exact `MAU2` mailbox request | 1..1,048,576 bytes |
| complete `XPR1` | 20..1,048,576 bytes |
| exact Contact Resolver request (`XPU1/XIQ1/XPK1/XUW1/XUQ1`) | 1..69,649 bytes |
| exact Contact Resolver success (`XPO1/XIS1/XPC1/XUS1`) | 1..131,072 bytes |
| exact GroupControl request (`GSW1/GSQ1`) | 1..33,160 bytes |
| exact GroupControl success (`GSS1`) | 1..65,535 bytes |
| success body inside `XPR1` | 0..1,048,556 bytes |
| `XRF1` frame | 176..1,572,864 bytes inclusive |
| padding block | `2^p`, `p` in 8..16; default `p=12` (4096 bytes) |
| zero-padding length | 0..65,535 bytes, derived exactly as §6 |
| replay window | 1..65,536 entries per `(routerId,keyId,epoch)` |

The route IDs and their exact selected traffic key IDs are pairwise distinct.
Ingress decrypts only a relay layer, core only a relay layer, and service exit
only an exit layer. A relay plaintext contains no operation, terminal request,
reply key, operation ID, or attempt ID.

Traffic-key admissibility is evaluated only against the exact verified `XND1`
referenced by a complete verified `XNV1`, and a fresh nonce-bound `DTT1` time
attestation for that same view as specified by `XPOINT-NETWORK-V1`. Let its
trusted interval be `[tLow,tHigh]`; ONION-01 requires `tLow <= tHigh`, the
attestation uncertainty allowed by that verified network policy, and the whole
interval inside both descriptor and selected-key validity. Absent, stale,
cross-view, or ambiguous trusted time fails closed. A sender uses only the exact
current or next XND1 onion key whose `(ownerId,keyId,epoch,key)` entry meets that
test. The next epoch is current+1; keys differ; each lifetime is at most 24
hours; overlap is at most two hours; no handover gap is allowed. A listener
accepts only its matching current/next key during that key's admissible interval.
It retains private key and exact replay state for exactly 300 seconds after key
expiry, then securely erases both; retained material never authorizes a late
frame. Clearing replay state under a live key is forbidden. Saturation fails
closed and never evicts an accepted ID; persisted replay state restores before
forward.

Within this contract, **XTT** means the non-serializable, sealed
`OnionTrustedTimeLease` described in section 7. It is not a wire record, magic,
registry entry or alternate time source. Protocol mints XTT only from an accepted
nonce-bound DTT1 plus protected secure-time state for that DTT1's exact XNV1/XNA1
lineage. Callers cannot construct XTT from wall time, artifact validity fields or a
boolean callback.

The maximum nested construction is fixed: `XRE1 <= 1,114,255`, innermost exit
`XRF1 <= 1,114,431`, one-relay `XRL1 <= 1,180,046`, middle `XRF1 <= 1,180,222`,
two-relay `XRL1 <= 1,245,837`, and outer `XRF1 <= 1,246,013` bytes. The broader
XRF1 limit is a parser safety ceiling, not permission for a fourth hop.

## 3. `XRF1` encrypted envelope

Suite 1 is ephemeral X25519 + HKDF-SHA-512 + XChaCha20-Poly1305-IETF. Purpose
1 is request and purpose 2 response. Layer kind is 1 relay, 2 exit, or 3
response. `XRF1` has an exact 160-byte authenticated header.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `XRF1` |
| 4 | 1 | version = 1 |
| 5 | 1 | minimum reader version = 1 |
| 6 | 1 | suite = 1 |
| 7 | 1 | purpose = 1 request or 2 response |
| 8 | 1 | layer kind |
| 9 | 3 | reserved zero |
| 12 | 16 | network ID |
| 28 | 32 | recipient key-owner ID |
| 60 | 8 | traffic-key epoch; zero only for response |
| 68 | 32 | recipient traffic/reply key ID |
| 100 | 32 | ephemeral X25519 public key |
| 132 | 24 | nonce |
| 156 | 4 | ciphertext length, including 16-byte tag |
| 160 | variable | ciphertext followed by 16-byte tag |

`ciphertextLength` is exactly `frameLength - 160`, is at least 16, and equals
the AEAD output length. For purpose 1, layer kind is 1 or 2, epoch is nonzero,
and `(networkId,keyOwnerId,epoch,keyId)` exactly identifies the selected XND1
traffic key; after opening, local role agrees with layer kind. For purpose 2,
layer kind is 3, epoch is zero, and owner/key ID identify one live disposable
reply context for the same network. Other combinations reject before opening.

Define `SHA512-D(label,data) = SHA-512(ASCII(label) || 0x00 || data)` and
`SHA256-D(label,data) = SHA-256(ASCII(label) || 0x00 || data)`. Let `E` be the
header ephemeral public key and `Z = X25519(localPrivate,E)`. After both
all-zero checks, derive exactly:

```text
salt = SHA512-D("Deep/XPoint/V1/frame-salt",
  networkId16 || keyOwnerId32 || u64be(epoch) || keyId32 || E32)
prk = HKDF-Extract-SHA-512(salt, Z)
info = ASCII "Deep/XPoint/V1/frame-key" || 0x00 || u8(purpose) || u8(layerKind)
T(1) = HMAC-SHA-512(prk, info || 0x01)
key = T(1)[0..31]
```

HKDF extract and expand are RFC 5869 operations; there is exactly one expand
block. Encrypt with XChaCha20-Poly1305-IETF using `key`, the exact 24-byte
header nonce, plaintext, and associated data `frame[0..159]` (all 160 header
bytes, including ciphertext length). Output is ciphertext then its 16-byte tag.
No bytes outside that header are associated data.

## 4. Request plaintexts

### `XRL1` relay plaintext

The fixed prefix is 80 bytes.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `XRL1` |
| 4 | 1 | version = 1 |
| 5 | 1 | minimum reader version = 1 |
| 6 | 1 | layer kind = 1 |
| 7 | 1 | reserved zero |
| 8 | 32 | local hop replay ID |
| 40 | 32 | next router ID |
| 72 | 4 | inner purpose-1 `XRF1` length |
| 76 | 1 | padding block exponent `p`, 8..16 |
| 77 | 3 | zero-padding length `z` (`u24be`) |
| 80 | variable | exact inner `XRF1`, then exactly `z` zero bytes |

The inner frame is a bounded canonical purpose-1 XRF1 whose length equals tag
72, `networkId` equals the outer XRF1 network ID, first key owner equals
`nextRouterId`, and frame length is a multiple of `2^p`. A cross-network splice
rejects before replay mutation or forwarding. The relay checks/registers its
replay ID before forwarding that exact frame. It does not decrypt, reinterpret,
or re-encrypt it.

### `XRE1` exit plaintext

The fixed prefix is 144 bytes. Operation is 1 Store, 2 Retrieve, 3
Acknowledge, 4 ContactResolve, or 5 GroupControl.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `XRE1` |
| 4 | 1 | version = 1 |
| 5 | 1 | minimum reader version = 1 |
| 6 | 1 | layer kind = 2 |
| 7 | 1 | operation = 1..5 |
| 8 | 32 | exit replay ID |
| 40 | 32 | logical operation ID |
| 72 | 32 | outer attempt ID |
| 104 | 32 | client ephemeral reply X25519 public key |
| 136 | 4 | exact canonical terminal request length |
| 140 | 1 | padding block exponent `p`, 8..16 |
| 141 | 3 | zero-padding length `z` (`u24be`) |
| 144 | variable | exact canonical request, then exactly `z` zero bytes |

Before replay mutation, the exit dispatches through a closed Protocol-owned
canonical verifier. Operations 1..3 accept only exact `MAU2`; its authenticated
operation must match XRE1 and its grant `NetworkId` must equal the XRF1 network.
Operation 4 accepts only exact current ContactV1 `XPU1/XIQ1/XPK1/XUW1/XUQ1`;
its `NetworkId` must equal the XRF1 network. Operation 5 accepts only exact
GroupV1 `GSW1` or `GSQ1`; its `NetworkId` must equal the XRF1 network and no
other operation may carry those records. Unknown, empty, cross-operation,
cross-network, legacy and max+1 inputs reject. No operation has a direct HTTP
fallback. After durable replay acceptance, exact bytes pass unchanged to the
selected service adapter. The stable operation ID is derived only as:

```text
SHA256-D("Deep/XPoint/V1/canonical-mailbox-operation-id",
  u64be(exactCanonicalRequestLength) || exactCanonicalRequest)
```

The historical frozen domain label contains `mailbox` but applies to all five
ONION-01 terminal operations; no operation-specific implicit derivation or alias
is permitted.

Every retry preserves logical operation ID and creates fresh nonzero attempt ID,
each hop replay ID, every request ephemeral key, and every request nonce.

## 5. Reply context, `XPR1`, and `XRS1`

The client creates one fresh reply X25519 key pair per route attempt. With its
public key `R`, the response header uses the same network ID and exactly:

```text
replyOwnerId32 = SHA256-D("Deep/XPoint/V1/reply-owner", R)
replyKeyId32   = SHA256-D("Deep/XPoint/V1/reply-key", R)
epoch = 0; purpose = 2; layerKind = 3
```

The client maps a response by `(networkId,replyOwnerId32,0,replyKeyId32)` and
also verifies `R` after opening. A reply context is single-use and is erased on
verified terminal result or expiry; unknown, expired, consumed, owner-mismatched,
or key-ID-mismatched responses reject.

`XPR1` is exactly 20 bytes plus success body, never padded internally.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `XPR1` |
| 4 | 1 | version = 1 |
| 5 | 1 | minimum reader version = 1 |
| 6 | 1 | kind: 1 success, 2 failure |
| 7 | 1 | operation: 1 Store, 2 Retrieve, 3 Acknowledge, 4 ContactResolve, 5 GroupControl |
| 8 | 2 | failure code; zero on success |
| 10 | 1 | retryable marker |
| 11 | 1 | reserved zero |
| 12 | 4 | body length |
| 16 | 4 | reserved zero |
| 20 | variable | body, success only |

For success, failure code/retry marker are zero and body length is exact:
operation 1 carries canonical `MQR3`, 2 canonical `MRP1`, 3 canonical `MAR1`.
Operation 4 carries the response paired with the exact ContactV1 request:
`XPU1 -> XPO1`, `XIQ1 -> XIS1`, `XPK1 -> XPC1`, and
`XUW1/XUQ1 -> XUS1`. Contact response request-hash binding and the 131,072-byte
opaque-body ceiling are mandatory before sealing and after opening.
Operation 5 carries only exact request-paired `GSW1|GSQ1 -> GSS1`; operation
kind, network ID, operation ID, request hash, write tuple or fetch cursor/padding,
and the 65,535-byte success ceiling are verified before sealing and after opening.
For failure, body length is zero and record ends at byte 20. Failure codes: 1
malformed request, 2 authentication rejected, 3 authorization rejected, 4 replay
rejected, 5 mailbox not found, 6 conflict, 7 capacity exceeded, 8 unavailable,
9 outcome unknown, 10 internal failure. Only 7, 8, 9 have retryable marker 1.
`OutcomeUnknown` means mutation might have occurred, never definite rejection.

`XRS1` has a fixed 80-byte prefix and is encrypted in purpose-2/layer-3 XRF1.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `XRS1` |
| 4 | 1 | version = 1 |
| 5 | 1 | minimum reader version = 1 |
| 6 | 1 | operation copied from `XRE1` |
| 7 | 1 | reserved zero |
| 8 | 32 | operation ID copied from `XRE1` |
| 40 | 32 | attempt ID copied from `XRE1` |
| 72 | 4 | exact `XPR1` length |
| 76 | 1 | padding block exponent `p`, 8..16 |
| 77 | 3 | zero-padding length `z` (`u24be`) |
| 80 | variable | exact XPR1, then exactly `z` zero bytes |

Relays return response opaque. Client opens only with matching disposable reply
context and verifies operation, operation ID, attempt ID, XPR1 grammar, and
exact XPR1 operation before application state can advance.

## 6. Padding, construction and vectors

For every XRL1, XRE1, and XRS1 choose route attempt's one `p` and compute
`z = (2^p - ((160 + 16 + fixedPrefixLength + payloadLength) mod 2^p)) mod 2^p`.
Encode `z` as u24; it is less than `2^p`; append exactly that many zero bytes;
then seal. Thus every XRF1 length is an exact multiple of `2^p`. Exact length
fields consume plaintext with no trailing bytes. Different `p`, nonzero padding,
non-minimal `z`, bad inner length, or fourth nested XRF1 reject. Seal exit,
then core relay, then ingress relay: exactly two XRL1 and one XRE1 plaintext.

Machine inputs live in `docs/survival-program/releases/v3.0.0/specs/onion-01.vectors.json`.
Positive vectors use explicit fixed private scalars/nonces only through injectable
**test-only entropy**. The internal nondeterministic seam has no entropy injection
and obtains fresh platform-CSPRNG material, but it is not a production constructor
because the durable uniqueness authority in section 7.5 is not implemented. The checker validates frozen fixture
bytes, hashes, structural fields, hostile negatives, and `runtimeActivation=false`;
it does not load a runtime codec and is not a release/CI activation claim.
Within the deterministic manifest, `requestEphemeralPrivateScalars` and
`requestNonces` are ordered by sealing order: exit, core relay, ingress relay.
`replayIds`, router owners, traffic keys, and router private scalars are ordered
by route order: ingress, core relay, exit.

## 7. Minimal production API and capability boundary

This section freezes the only permitted production API shape. Names below are
normative .NET surface names; implementations MAY split files but MUST NOT add a
shorter overload that accepts raw keys, caller time, arbitrary routes, optional
replay state, verifier delegates or caller-supplied trust decisions.

### 7.1 Sealed verification and time capabilities

All capability classes are sealed, immutable and defensively own their bytes. Their
constructors are non-public. Serialization, reflection reconstruction and
subclassing are unsupported. Only Protocol-owned verifiers/factories can mint:

- `VerifiedOnionNetworkContext`: exact network ID, XNA1 authority core, XVP1 policy
  core, threshold-complete XNV1 core/generation and the exact verified XND1 set;
- `OnionTrustedTimeLease` (XTT): inclusive trusted interval, protected rollback
  floor, monotonic sample, boot ID, DTT1 core hash, source-set hash and a monotonic
  hard deadline;
- `VerifiedOnionPathContext`: one operation class and exactly three ordered,
  pairwise-distinct hops, each bound to an exact XND1 core, node/owner/key ID,
  epoch, X25519 public key and required role;
- `VerifiedOnionReceiveContext`: the exact verified network/view context, one local
  XND1 traffic-key handle, receive position (`Ingress`, `Core` or `Exit`), XTT and
  key-use deadline;
- `VerifiedCanonicalOnionRequest` and `VerifiedOnionTerminalResult`: exact
  operation-specific MAU2, ContactV1, or GroupV1 bytes and their Protocol-derived semantic,
  operation, network and request/result-pairing bindings.

`OnionNetworkContextVerifier.Verify(...)` accepts only Protocol-produced verified
XNA1/XVP1/XNV1/XND1/DTT1 closures and protected secure-time state. It has no key lookup,
signature, trust, time or accept/reject callback. It verifies the DTT1 nonce and
threshold, exact XNA1/XNV1 linkage, rollback floor, boot continuity and interval
intersection, then mints XTT and the network context atomically. XTT advances only
by its bound monotonic source. A boot-ID change, negative elapsed value, empty
interval, expired source/path bound or protected-state read failure invalidates the
lease; OS wall time never repairs it.

For each use, the whole advanced XTT interval MUST fit the XNV1, XVP1, XND1 and selected
traffic-key validity intersections. The 300-second retired-key retention permits
restart/replay cleanup only and never extends admissibility. A receive key is exposed
to the codec only as an opaque, lease-bound key-vault handle; raw private bytes are
not a public API value.

### 7.2 Exact-three path and receive-position proof

`OnionPathContextFactory.CreateContactResolver(...)` and
`OnionPathContextFactory.CreateGroupControl(...)` accept a verified network context,
live XTT and the operation-specific non-forgeable placement capability. GroupControl
placement is derived from a current identity-verified `GSR1` plus the exact PMT2 in
the same NETCODEC context and contains exactly the first two canonical rendezvous-ranked
replicas. The factories
selects or validates exactly three ordered hops and rejects unless:

1. positions are exactly `Ingress`, `Core`, `Exit`;
2. all three node IDs, owner IDs, traffic-key IDs, X25519 keys and physical hosts are
   pairwise distinct and satisfy the active XVP1 constraints;
3. the ingress has Entry capability, the core has Relay capability and the exit has
   the operation's required role in their exact XND1 records;
4. every selected key is admissible for the same network and complete XTT interval;
5. the path hard deadline is no later than any view, descriptor, key or policy bound.

The builder accepts only `VerifiedOnionPathContext`; there is no production overload
that accepts `IReadOnlyList<PrivacyRoutingHop>` or three public keys. Construction is
always `Relay -> Relay -> Exit`. On receive, a sealed local position capability
enforces the same proof without adding a wire field: Ingress accepts an outer relay
only when its inner XRF1 header is Relay; Core accepts a relay only when its inner
header is Exit; Exit accepts only XRE1. Every inner header must also bind the same
network and the verified next XND1 owner/key/epoch. A shorter path, reordered role,
relay after Core or fourth nested frame rejects before replay mutation. The receive
position is minted from the verified local XNode role/listener composition, never
from a request enum or carrier metadata; the codec remains independent of HTTP,
QUIC, Reality, XHTTP and peer-forwarding transports.

### 7.3 Mandatory durable replay transaction and key lease

Production opening is asynchronous and has no replay-optional overload. Before
calling `OpenAsync`, the host obtains a sealed one-use `OnionReplayOpenLease` from
`OnionReplayAuthority.BeginOpenAsync(receiveContext, exactFrameHash, cancellation)`.
The authority starts a durable transaction scoped by
`(networkId,routerOwnerId,keyId,epoch,receivePosition,exactFrameHash)` and pins the
matching private-key handle against retirement for the bounded call. A lease from a
different frame, scope, boot, position or expired XTT rejects before decryption.

`OpenAsync` performs, in order:

1. bounded header/version/purpose/length and receive-context checks;
2. XTT/key lease validation and AEAD authentication;
3. complete plaintext, zero-padding, same-network, next-hop, exact-position and
   operation-specific MAU2, ContactV1, or GroupV1 canonical payload verification with no external side effect;
4. durable `TryCommitReplayIdAsync` on the lease;
5. release of a sealed `OpenedOnionRelay` forward capability or
   `OpenedOnionExit` dispatch/reply capability.

The replay commit is atomic and durable before step 5 can return. `Replayed`,
`Saturated`, cancellation, lease loss, disk-full, ambiguous commit or durability
failure returns no opened capability and performs no forwarding/mailbox callback.
Saturation never evicts. Uncommitted disposal rolls back; a committed replay ID
remains through restart until the selected key is securely erased 300 seconds after
expiry. The integration contract MUST prove fsync/WAL durability, single-writer lease
or equivalent CAS, crash-before/after-commit behavior and restoration before the
listener becomes ready. The existing process-local replay window is test utility
only and cannot mint `OnionReplayOpenLease`.

### 7.4 Exit-to-response context and operation payload verification

Opening XRE1 returns `OpenedOnionExit` only after section 7.3. It contains a sealed
`OnionExitReplyContext` carrying the exact network ID, operation ID, attempt ID,
reply public key, derived reply owner/key IDs, XTT source/boot binding and monotonic
expiry. It never contains the client's reply private key. `SealAsync` accepts this
context plus a matching `VerifiedOnionTerminalResult`; there is no overload that
reconstructs reply state from caller fields.

The client-side `OnionReplyContext` is created by Build, owns the reply private-key
handle, carries the same bindings and is single-use. Its expiry is the earliest of
the path hard deadline, the active XVP maximum circuit lifetime and 600 monotonic
seconds after attempt creation. Verified terminal Open consumes and erases it.
Expiry, boot change, operation/attempt/network mismatch, unknown response or an
ambiguous key-vault operation returns no result capability.

`OnionTerminalPayloadVerifierV1` is one closed Protocol-owned dispatch table, not a
publicly implementable interface or `Func<bool>`. Its pure bounded methods mint
distinct Store/Retrieve/Acknowledge/ContactResolve/GroupControl request capabilities. Mailbox
requests are exact MAU2 with operation and grant-network binding; successful XPR1
bodies are exact request-bound MQR3/MRP1/MAR1. Contact requests are exact bounded
XPU1/XIQ1/XPK1/XUW1/XUQ1 and successful bodies are exact request-paired
XPO1/XIS1/XPC1/XUS1. GroupControl requests are exact bounded `GSW1` or `GSQ1`, and successful bodies
are exact request-paired `GSS1`; `GSW1`/`GSQ1` are never accepted under another
operation. Unknown operations, cross-operation/network records,
non-canonical bytes and max+1 inputs reject before replay mutation on the exit and
before reply-context consumption on the client. Stateful mailbox or Contact
authorization/dispatch occurs only after `OpenedOnionExit`; it cannot weaken the
prior canonical verification. Failure XPR1 has no body and needs no application
callback. Protocol exposes no HTTP client, URI, direct-service fallback or
transport callback.

### 7.5 CSPRNG, nonce/key reuse authority and public methods

`OnionEntropyAuthority` is a Protocol-owned production service over the platform
cryptographic RNG and a protected durable uniqueness ledger. Callers request an
attempt or response reservation but cannot supply, mutate or observe private
scalars, nonces or replay IDs. In one transaction it generates and reserves:

- one nonzero Protocol-owned attempt ID, three pairwise-distinct nonzero replay IDs and one
  disposable reply X25519 key pair per request attempt;
- three fresh request ephemeral X25519 scalars and three fresh 24-byte nonces,
  ordered exit/core/ingress;
- one fresh response ephemeral scalar and nonce per sealed response.

Before any frame is returned, the ledger durably rejects a repeated commitment of
`(networkId,purpose,layer,keyId,epoch,ephemeralPublicKey,nonce)` and a repeated live
reply key ID. Request commitments remain until the corresponding traffic key and
replay epoch are erased; response/reply commitments remain until reply-context
expiry. Reservation failure, duplicate output, zero scalar/public key/shared secret,
partial commit, cancellation or RNG failure emits no frame and zeroizes transient
material. Retry creates a new reservation while preserving only the logical operation
ID. Deterministic entropy exists solely behind the test assembly seam and is absent
from production public metadata and package APIs.

An application or Contact Resolver transport cannot supply XRE1 `attemptId`.
`BuildAsync` returns the Protocol-owned attempt ID as non-secret correlation metadata;
the transport adopts that value for the attempt it sends. Any pre-existing
application/transport retry ID remains separate and is never copied into ONION-01
entropy or used to derive keys, replay IDs or nonces.

The minimal public production methods are therefore equivalent to:

```csharp
ValueTask<PrivacyRoutingBuiltRequest> BuildAsync(
    VerifiedOnionPathContext path,
    VerifiedCanonicalOnionRequest request,
    CancellationToken cancellationToken);

ValueTask<PrivacyRoutingOpenedLayer> OpenAsync(
    ReadOnlyMemory<byte> frame,
    VerifiedOnionReceiveContext receive,
    OnionReplayOpenLease replayLease,
    CancellationToken cancellationToken);

ValueTask<ReadOnlyMemory<byte>> SealAsync(
    OnionExitReplyContext reply,
    VerifiedOnionTerminalResult result,
    CancellationToken cancellationToken);

ValueTask<PrivacyRoutingOpenedResponse> OpenResponseAsync(
    ReadOnlyMemory<byte> frame,
    OnionReplyContext reply,
    CancellationToken cancellationToken);
```

These methods are exposed only by a production codec instance created from the
Protocol-owned verified context, payload, replay, key-vault, monotonic-time and
entropy authorities. They perform no socket, DNS, HTTP, carrier, route publication,
mailbox mutation or application callback. No synchronous/raw-key/current-time/
optional-store overload is permitted.

## 8. Activation boundary and non-claims

The frozen byte codec implementation is not runtime activation. Public production
methods remain fail-closed until the section-7 capability producers, generated
registry policy, independent codec conformance, trusted-time/key-rollover/replay and
entropy-ledger persistence tests, operation payload verifiers, three-host chaos
evidence and independent cryptography/privacy review are complete. Until then all
ONION-01 runtime activation flags remain false and no consumer may call the internal
vector seam as a release codec.

First activation is a clean break. Authorized client and XNode consumers atomically
repin the exact Protocol package, provision opaque traffic/reply key stores plus empty
durable replay/entropy ledgers, and remove pre-production raw-key, optional replay and
direct-routing paths. No legacy ONION reader or state migration is permitted. This
changes no account identity, application plaintext or canonical mailbox object; it
requires reset only of disposable pre-production onion attempts/reply contexts and
replay state before listeners are enabled.

This prevents one honest non-colluding node from observing both client source and
service exit. It does not hide client IP from ingress, service selector from exit,
timing, direction, connection reuse, padded length, global observers, or colluding
nodes; it makes no Tor-equivalence, unblockability, or traffic-analysis claim.
