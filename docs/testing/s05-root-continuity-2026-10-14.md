# S05 offline root continuity candidate

Owner: Mr. X. Branch: release-candidate/prod-20260909.
Normative semantics/API:
[DR-0116](../../../docs/survival-program/decisions/DR-0116-offline-root-continuity-after-expiry.md).
No source gate or current/installed activation is claimed here.

The retained dev DTS1 expired on2026-10-06. Previous overlap-only XNA1
succession made honest post-expiry offline renewal impossible. The candidate
authenticates exact root continuity independently of operational freshness;
backward signed time, altered/missing/forked history and insufficient/foreign/
forged predecessor receipts still reject. Ordinary current authority checks
are unchanged. No source secret, protected floor, node identity or deployment
has been altered to obtain this result.

The successor producer additionally separates the explicit bounded offline
XVP1/PMA2 horizon from its short XND1/XNV1/XNH1/PMT2 interval. Delegated
extensions reject before signing; exact authorized policy bytes are retained.
The two obsolete negative theory rows `root-gap`/`dts-gap` are replaced by
positive signed-gap cases and negative `root-time-rollback`/`dts-before-root`
cases. This is an authorized semantic change, not an assertion waiver.

Run01 failed compilation because the new test omitted the AccountDirectory
namespace. Run02 built with zero warnings/errors, then60/1/0: the new
over-authority test used901 even though the fixture's real ceiling was greater.
Its input now derives `authority.ExpiresAt+1`; the same assertion remains.
Run03 built with zero warnings/errors and completed **61/0/0, native0**:
`artifacts/s05-root-continuity-20261014/03/nikit_SURFACE-LT_2026-10-14_15_31_43_net10.0.trx`.
SHA256: `42141E16F5F810DFCD1BEB92D72FF504086DF68A00E5BD4578EA5623F64E16EA`.
The scope includes real Ed25519 root/DTS signatures, at/after-expiry same-key
renewal, changed-root paired-chain verification, backward time/unknown-self/
corrupt signatures, old-PMA rejection and bounded offline/delegated policy
behavior. It is not a full, independent-vector, operational or physical receipt.

Mechanical normative source repin and the strict checked-in registry generator
passed under PowerShell7; approved Git-blob anchors were not changed. Generators
require its modern filesystem/JSON APIs. Windows native tests/gates still use
PowerShell5.1 and SDK10.0.301; executable witnesses use the separate7.5.4 binary.

Canonical `preflight-01` completed build/preflight/qualification0 with1580
captured inputs,2026-10-14T10:50:37.0922696Z–10:51:21.6856944Z.
It is explicitly `PreflightOnly=true`, `TestExitCode=null`, `FullAccepted=false`.
Full was not launched. The prior complete receipt contains the two superseded
negative case identities; the exact common gate requires explicit semantic
retirement handling before that prior/full+new/focused union can qualify.
Do not edit historical TRX, silently omit their rows or weaken exact mapping.
The existing S08 package FAIL and seven provider skips remain separate blockers.

Next: finish that explicit matrix transition, unfiltered source/API/package
checks, supported dev renewal preparation/activation, current issuer/node/client
recovery with retained state and certificates, then S06/device flows. No root
online, backdated time, reinitialized genesis or empty-volume substitute.
