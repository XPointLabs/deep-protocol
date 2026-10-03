# S01/S03 exact Store settlement checkpoint — 2026-10-04

Owner: Mr. X. Implementation candidate, not deployment/package activation.
Execution order remains the root [implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Semantic/API owner: [DR-0086](../../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md).
Input Protocol: `a2532603e2c2686139fe81ac613667d17c5e544e`, plus this commit.

The closed current host authenticates past exact PRQ2/MQR3 Store commitments
without manufacturing a current grant, replay reservation or dispatch capability.
The complete current PMT2/PMA2, signed selector, actual selected descriptor keys,
grant issuer signature, sender signature, two distinct canonical MRR2 tuples,
coordinator signature/sequence and signed acceptance intervals are checked.
Both inputs are bounded and captured before clock callbacks. Protected current
host/time is checked across verification; receipt timestamps never become time.
Only the exact current projection/issuer history is supported. Missing retained
history fails closed; identity keys are immutable within XND lineage.

The existing public current-quorum verifier and settlement verifier share one
private signature/tuple implementation. There is no caller key/clock/crypto
callback, fabricated verified peer request, new wire ID or second journal.
The native [consumer checkpoint](../../../xnode/docs/testing/s03-store-prefix-2026-10-04.md)
exercises signed Store, hostile saved receipts and former grant expiry.

Release build: **0 warnings / 0 errors**.
Full Release tests: **2071 pass / 1 fail / 12 skips** (2084 total).
Closed-host boundary tests: **31/31**. Unknown inner Store/grant grammar and a
structurally valid non-Ed25519 quorum profile reject before the clock callback.
The unchanged failure is the actual-package witness: retained MCG2 bytes in the
old PMR1 surface. The production source graph separately rejects unchanged MAU2
in the old PMA1 codec. Neither assertion nor retained reader was renamed to hide
these S00/S02 blockers. Native-provider skips remain skips, not positive evidence.

Strict source/anchor generation passes: only two reviewed normative document
hashes, one production-source inventory hash, the derived registry hash and the
additional PMT2 consumer location change. **175 anchors, zero anchor repins**;
no allocation, approved frozen blob or lifecycle activation changes.
DNP1 ownership structure passes exact314/package219/final95 with zero mappings;
this is structural validation, not complete package evidence.

Commands from this repository:

```powershell
dotnet build Deep.Protocol.slnx -c Release --no-restore -warnaserror
dotnet test Deep.Protocol.slnx -c Release --no-build --logger trx --results-directory artifacts/s03-store-prefix/final
./eng/Generate-DeepProtocolRegistry.ps1 -Check
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
./eng/Test-Dnp1EvidenceOwnership.ps1
```

Ignored full-suite TRX SHA-256: routes
`c41042fd9d5054b76800bf9785a3bfcff86e2f8f93ffc3726634e5b766561418`,
carrier `59fc62b2566639b236db99444a1e0e9a5f7fd6587b926a4236a8d9f7a52c5882`,
Protocol `9f94729c71f25a57869a3c0ca1d8088c34d161c051650fe410e924860dd50571`.
Artifact directory: `artifacts/s03-store-prefix/final`.
Boundary TRX in `artifacts/s03-store-prefix/boundaries-after`, SHA-256
`af1e2480def27a6115a13c1c14d0f00041811fcf3806c5fa51be94d7be785eb9`.

Exact package/resource consumer repins, current writer/path integration, retained
projection/issuer lifecycle, Program activation and physical E2E remain open.
No package was published, production deployed or device/account/secret modified.
