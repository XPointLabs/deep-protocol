# S01 retained mailbox read selection — 2026-10-07

Scope: source host/selection/MGR1 API increment under
[DR-0099](../../../docs/survival-program/decisions/DR-0099-retained-mailbox-read-selection.md).
This is not renewed issuance, native holder custody, node admission, remote
object availability, retained ACK replication, whole S01 or physical E2E.

## Actual producer and consumers

| Boundary | Actual source | Guarantee / limitation |
| --- | --- | --- |
| Verified history facts | `XPointOnionCapabilityProducer.VerifyAsync` / `CaptureRetainedPmts` | Captures only authenticated ordered PMT2 steps, including the actual verified predecessor. Existing count/byte caps apply to the aggregate; no silent eviction. Forward-only joins retain only their terminal current fact. |
| Retained selection | `VerifiedMailboxHostAuthorityV2.GetSelectedRetainedReadReplicasAsync` | Captures exact MCG3 before clock I/O; Active Retrieve only, exact verified PMT hash/epoch; current issuer/signature/generation/lifetime/full interval twice. Uses old ranking and current admitted Mailbox descriptors, without rerank. Copied facts, not dispatch authority. |
| Signed revocation | `VerifiedMailboxGrantRevocationV1.EnsureRetainedReadGrantNotRevokedAsync` | Exact current MGR1 role/issuer, protected floor read-back and current retained-grant checks around each floor callback; revoked serials reject. No replay reservation or floor deletion. |
| Unchanged current lane | `RequireGrant` / `EnsureGrantCurrentAsync` / `ResolveGrantReplicasAsync` | Exact current membership and selection epoch remain mandatory for current methods. Store cannot cross-feed retained read; expired grants are never revived. |

The fixture signs every changed PMT2/XVP1/XNV1/XNH1 and current PMA2/MGR1.
Cold cases export actual DNH2 and verify its complete signed history again.
The monotonic clock and protected MGR1 floor I/O are test-owned; this does not
prove OS secure storage, a production handover or physical delivery.

## Focused results and preserved failures

Initial compilation stopped at a fixture referencing a nonexistent method;
the fixture now calls the actual `ResolveGrantReplicasAsync`. No test receipt
was produced by that compile failure and no acceptance was claimed.

First executing focused run:191 passed /1 failed /0 skipped, terminal1.
The hostile-issuer fixture selected the Deposit public key but attempted signing
with the Retrieve private key; the signer rejected that mismatch before the
verifier ran. It now creates a genuine wrong-role signature with the matching
Deposit key; the product must still reject it.
`artifacts/s01-retained-read-focused/s01-retained-read-focused.trx` SHA256:
`115410382A98FE517DC7D8ECE8BD0E4E023A349E6A99AF664E31E89AA19EA633`.

Corrected run:192/0/0, terminal0.
`artifacts/s01-retained-read-corrected/s01-retained-read-corrected.trx` SHA256:
`818523BBC980B19100EFA2D4AAF54CCC85CBC9D344778812C54E8CE75111DC32`.

Adding actual terminal-only/removal negatives produced193 passed /1 failed,
terminal1: the terminal-only fixture expected a minted context but the existing
complete verifier rejects missing genesis even earlier. The assertion now
requires that precise `network-genesis-required` rejection; no lineage guard
was weakened.
`artifacts/s01-retained-read-final-focused/s01-retained-read-final-focused.trx` SHA256:
`CCA5551E577A71C9CC7849071FFB408F01C56E974901E004B9E8AA2958E11395`.

Final focused:194/0/0, observed terminal0. This covers both host/MGR1 APIs plus
the existing host/network/MGR1 classes, including signed unchanged/advanced
epochs, old projection expiry, actual cold history, wrong roles/issuer/signature,
missing exact history, terminal-only rejection, actually removed Mailbox node,
clock rollback/expiry/boot/cancellation, captured buffers, current protected-floor
changes/absence and revoked serials.
`artifacts/s01-retained-read-qualified-focused/s01-retained-read-qualified-focused.trx` SHA256:
`BE021C16CDF158678284A15245DDFB1488C601114935D45B6282B7100E44B9EC`.

Command:

```powershell
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj --filter 'FullyQualifiedName~MailboxHostAuthorityV2VerifierTests|FullyQualifiedName~XPointOnionCapabilityProducerTests|FullyQualifiedName~MailboxGrantRevocationV1Tests' --logger 'trx;LogFileName=s01-retained-read-qualified-focused.trx' --results-directory artifacts/s01-retained-read-qualified-focused -m:1
```

Strict registry gate:terminal0. Reviewed source repin changes exactly
`protocol-registry-v1`, `xpoint-network-v1`, `production-wire-source` hashes;
175 normative anchors unchanged. Generator updates derived registry hashes,
not wire/domain/suite allocations or approved frozen Git blobs.

## Mandatory qualification still pending at this source checkpoint

Run the Protocol restore/build/full tests, actual package/API/resource graph
and evidence-ownership checks on the frozen candidate. Focused results do not
qualify that complete matrix. Preserve the known MAU2 shipping/package blocker;
do not weaken it or imply that this source API is shipping-ready.

Renewed retained issuance, actual account-owned holder/counter scopes, node
typed Retrieve/ACK admission and peer tombstones remain unimplemented consumers.
The codec still has its shorter object lifetime. No TTL constant, deployment,
account reset, operator key, scheduler or GitHub Release changes in this slice.
