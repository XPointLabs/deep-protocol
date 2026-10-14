# S05 offline mailbox issuer rollover

Owner: Mr. X. Status: current source checked; runtime/package/device activation open.
The producer contract is [DR-0118](../../../docs/survival-program/decisions/DR-0118-offline-mailbox-issuer-rollover.md).
No magic, wire version, suite, signature domain or local custody generation changed.

The sole operational successor request takes an optional immutable fresh pair of
mailbox issuer public keys and an increased grant-generation floor. Only offline
root-threshold authoring may use it; delegated authoring rejects before callbacks.
Full protected predecessor/prefix, fresh independent role keys and increasing floor
are checked before signing. PMA2 retains network/mailbox IDs, predecessor, lifetime
bound and placement epoch; PMT2 binds its new core. Historical scalar computation
authenticates the supplied PMA under its exact ancestor, never returns currentness.
The coupled author also rejects a horizon beyond the existing14-day PMA wire bound
before callbacks rather than after signing other records.

Matching run04:119/0/0, native build/test0, zero warnings/errors, Windows
PowerShell5.1/SDK10.0.301. TRX SHA256:
`E13F31B47000A420013595DA516F58005622EAF12CFF1C8B4DFD9337D50E7506`.
Warm/cold mixed-authority verification, namespace/epoch retention, delegated
policy preservation, input copying/bounds, stale/cross-role/identity keys, floor,
forged metadata source and oversized PMA horizon are covered. Hostile authoring
checks assert no signer callbacks. Run01 failed test compilation due a byte-array
Span typo; run02/03 passed118/119 respectively. Original receipts stay unchanged.
Registry source/anchor repin and strict generator/registry validation passed;
only the reviewed normative source hash changed, not wire allocation.

Canonical full01:2309/1/7,2317 exact mappings,1583 unchanged inputs.
Build/preflight/qualification0, native1, FullAccepted=false. Interval:
2026-10-14T13:15:09.9176826Z–2026-10-14T13:17:57.8334791Z.
Witness7.6.5/.NET10.0.11/ARM64 under DR-0117. Three original TRX hashes:
`4BA75385DF46E4191E21737DE041EB14498365DF85ECF587830950CD93BEA13B`,
`E85242C13467388BF23BEAF0BD3D26D5D83C06751BD7C215179E5EDE7CFE8770`,
`EE4CBB29F5809252D1A4B9F9547F570404FFD46BA810CBA46B9E6A8B4357C8FE`.
Original native MAU2 package FAIL and seven named provider skips remain; there
is no new FAIL waiver or edited reference receipt. This is not shipping/package
acceptance. Do not rerun unchanged full. Consumer/public API/actual packages,
external signer/journal provisioning and coordinated retained deployment remain
required; [DevOps](../../../deep-devops/docs/S05-AUTHORITY-HISTORY-2026-10-14.md)
owns operational preparation/activation evidence.
