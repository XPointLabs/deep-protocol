# S05 — exact signed-origin relocation producer candidate

Date: 2026-10-15. Contract owner:
[DR-0120](../../../docs/survival-program/decisions/DR-0120-signed-operational-origin-relocation.md).
This is source candidate evidence, not operational/device activation.

The existing successor producer can relocate an existing predecessor origin
without changing its ID/transport or immutable node/staking lineage. Inputs are
bounded/copied, IPv4/IPv6 canonical, duplicate/unknown IDs and effective endpoint
collisions reject before signer callbacks. Delegated issuance retains existing
key/pin rules and exact policy/PMA bytes; no endpoint fallback or new wire reader.

Focused03 passed **59/0/0**, native0, Windows PowerShell5.1, Release:
`artifacts/s05-origin-relocation-20261015/focused-03/origins.trx`;
SHA256 `F2FB1F3152FDB8D6C68AC4234864C57ABB566248178FCD99E30DEA18301A6903`.
The scope includes existing rollover/hostile-prefix cases plus root/delegated
IPv4/IPv6 relocation with real signatures, warm/cold verified history, unchanged
namespace/epoch, no-intent renewal retaining the relocated address, unchanged
installed traffic keys/pins, hostile collections and root-callback mutation.
These fixtures use synthetic trusted time, not actual NTS or physical devices.
Focused01 passed55 before the final collection/callback cases were added;
focused02 passed59 before the positive maximum16-intent boundary was added.

Default production-reference operator Release build passed native0, zero
warnings/errors; receipt:
`deep-devops/artifacts/s05-origin-relocation-20261015/build-01/build.log`;
SHA256 `0A96604248E84F354FF6F0084760B053191BA6F7E3F064ED4FEA09D9A5B415A2`.
Read-only reflection on that actual default `Deep.Protocol.dll` confirms the
public sealed three-parameter intent and single six-parameter node constructor.
It does not qualify package ZIPs, downstream installed binaries or release graph.

The first strict generator attempt rejected a stale normative source digest.
Repository-owned repin tools then updated exactly two source digests and
reviewed line/range hashes; strict `Generate-DeepProtocolRegistry.ps1 -Check`
passed. A structural comparison against HEAD, excluding only those two digests
and anchor positions/hashes, confirmed all semantic allocations unchanged.
No frozen record/schema/vector/domain changes or new generation are introduced.

## Remaining connected scope

No runtime was changed. The old same-key PKI candidate deliberately requires
identical SANs and internal CRL distribution; it cannot be reused to pretend
that a new physical ingress was provisioned. A coordinated sealed/resumable
candidate must stage signed endpoint intent, matching same-key SAN/CRL coverage,
reachable listener publication and peer config, then use retained publisher
journal/CAS and independent current verification. Preserve original identities,
genesis, keys, histories and floors; never translate sealed endpoints in clients.

Complete that coherent operator/runtime slice and matching focused boundaries
before the next canonical full. No full is running now; previous Node1508/0/0
qualifies its previous captured source inputs only. The independent S08 MAU2/PMA1
package failure is not waived. Current queue/activation status:
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
