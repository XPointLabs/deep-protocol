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

At the producer-only checkpoint no runtime was changed. The old same-key PKI candidate deliberately requires
identical SANs and internal CRL distribution; it cannot be reused to pretend
that a new physical ingress was provisioned. A coordinated sealed/resumable
candidate must stage signed endpoint intent, matching same-key SAN/CRL coverage,
reachable listener publication and peer config, then use retained publisher
journal/CAS and independent current verification. Preserve original identities,
genesis, keys, histories and floors; never translate sealed endpoints in clients.

The subsequent coherent local operator slice is recorded in
[DevOps physical-ingress evidence](../../../deep-devops/docs/S05-PHYSICAL-INGRESS-2026-10-15.md):
same-key sealed candidate activated, strict Windows TLS/H2 reached all three
actual signed origins, and operator84/contracts22/current readiness passed.
This does not qualify device delivery; the preserved owned client exposed a
separate prekey-publication placement lifecycle defect after network renewal.
The integrated canonical full below uses the prior three-project full receipt
union plus focused03, preserving the existing package failure and seven skips.
Previous Node1508/0/0 qualifies its previous captured source inputs only.
The independent S08 MAU2/PMA1 package failure is not waived. Current queue/activation status:
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).

## Integrated source qualification after the operator slice

Canonical full01 completed at `2026-10-14T22:07:41.6411468Z`:
**2327 passed, 1 failed, 7 skipped**, 2335 exact case mappings, 1587 unchanged
captured inputs. Windows PowerShell5.1/SDK10.0.301; nested executable witness
PowerShell7.6.5/.NET10.0.11/ARM64. Build and preflight native0 (zero build
warnings/errors), full test native1, exact qualification0, `FullAccepted=false`.
Reference union was the previous same-day handover three-project full plus
focused03 above. No retirement or waived assertion was used.

Receipt root: `artifacts/s05-origin-relocation-20261015/full-01/`.
The three full TRX SHA256 values are:

- `6078C751842A17543D80D592A8E6E7AD0D0BA45B0B78F08DBE64DC39603A0DC7`
- `8E6959D4ECED3F86F213171598A01B73DD6E0E4890370D4B6F621E28AB4E0626`
- `C0CE10C04C682511D4264159151003263F01066DD5ADCD46B7B4785D28E3DDDF`

The sole failure is the same actual package/assembly/resource/public-API graph
witness: retired `MAU2` remains in `Deep.Protocol` assembly bytes through the
old PMA1 producer. The seven previously declared skips remain; this is not
shipping package acceptance. All 15 additional origin-relocation cases are
represented in the exact matrix. The next functional boundary remains the
preserved-client prekey publication lifecycle, not another unchanged full run.
