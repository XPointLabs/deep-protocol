# S05: same-day authority handover anti-replay

Date:2026-10-14. Owner: Mr. X. Contract:
[DR-0119](../../../docs/survival-program/decisions/DR-0119-dtt1-same-day-authority-handover.md).
This receipt does not activate a package, production deployment or device path.

The existing minted issuance epoch exposes only a defensive, ancestor-to-current
list of negative replay namespaces. It uses fully verified paired XNA1/DTS1
history and original signed windows intersecting the UTC day, with a64-namespace
bound. Exact current ID, DTT1 encoding/signatures and live proof authority binding
are unchanged. Ancestor IDs cannot mint or verify a current proof. Unknown/sibling
namespace, older authority presented after a successor quota, day rollback and
future markers remain failures; the supported consumer must retain same-day
nonce markers and aggregate quota, probing all known nonce paths before reserve.

Matching real-signature focused01:20/0/0, native build/test0, zero warnings/errors,
Windows PowerShell5.1/SDK10.0.301:
`artifacts/s05-same-day-handover-20261014/01/nikit_SURFACE-LT_2026-10-14_19_54_26_net10.0.trx`.
SHA256:`523FBDF78D2D64B99684FBE50BDEEB72216AC3C1C533576B7C9A214607B09747`.
Scopes include exact paired ancestry, unchanged current ID, defensive memory,
sibling exclusion, prior-day expiry, signed64/65 boundary and previous root/time
continuity/currentness cases. No historical currentness is inferred from the list.

Reviewed source/anchor repin changed3 source hashes and73 line-only anchors;
177 anchors validated and strict generator check passed. Approved frozen Git
blobs, allocations, widths, domains and CRL1/CRS1 layout were not repinned.

Canonical full01:2312/1/7,2320 exact mappings,1585 unchanged inputs;
build/preflight/qualification0, native test1, FullAccepted=false.
2026-10-14T15:02:00.8899591Z–15:04:38.6934954Z, Windows PowerShell5.1,
SDK10.0.301; executable witness7.6.5/.NET10.0.11/ARM64.
Receipt SHA256s:
`95693C78FCD174363DBABDA80595CB0CDE84BFB739B8A048113112968F58230A`,
`8D77A9C155A1A7A91E0092E4229D5983F76B0B1E1CB0309E20ECC7D5B5B96D9B`,
`05C7175D8B78BA7E66BAAABAC985045839676DD776C403D1444129FED0C7E8CE`.
The sole failure remains the actual S08 three-package graph witness rejecting
retired MAU2 in the old PMA1 producer. Seven original provider skips remain.
Neither failure nor skips were waived, retired, renamed or represented as PASS.

Registry's matching consumer and actual retained-dev acceptance are owned by
its checkpoint and DevOps. This source matrix alone proves neither issuance
activation nor physical contacts/messages/files/groups. Follow
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md) for the single current S05 queue.
