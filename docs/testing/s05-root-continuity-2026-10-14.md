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

The common gate now supports accepted exact old-case -> replacement bindings,
without modifying historical TRX. Qualification retains the prior method and
decision digest, requires old cases absent and every replacement actually passed;
FAIL/skip exceptions cannot waive replacements. Its contracts passed46/0.

Full01 completed build/preflight0, native/qualification1, **2295/3/7**.
Two new failures were stale frozen-manifest hash pins: the previous DR-0116
change added only a positive root-continuity obligation, not changed primitive
bytes or negative vectors. The reviewed raw-file SHA pin is now
`2539f70d18330d5993a4df844eaa036c2ed7b21dc1412d7fa5df68cab3e0a39c`.
PowerShell also concatenated two unparenthesized replacement expressions into
one string; the gate correctly rejected that mapping. Corrected arrays use
explicit parentheses. No final unchanged-input qualification is claimed for01.

Matching run04 built with zero warnings/errors and passed **107/0/0, native0**,
including the actual primitive/negative frozen-manifest checks. TRX SHA256:
`015CA979F34A07DD9CF73B95AD245012937607EAA0E712BA5D0F2AB107F45892`.
It is under `artifacts/s05-root-continuity-20261014/04/`.

Full02 completed **2297/1/7**,2305 exact mappings, two explicit retirements,
build/preflight/qualification0, native1 and1580 unchanged captured inputs.
Interval2026-10-14T11:07:51.7811522Z–11:10:31.5114122Z.
`FullAccepted=false`: the package witness FAIL is preserved, not waived.
Full receipts under `artifacts/s05-root-continuity-20261014/full-02/full/`:

- `nikit_SURFACE-LT_2026-10-14_16_08_08_net10.0.trx`:14/0/0,
  SHA256`EA5DEC61510BF3A3EE98DAF7EBEE42929C392B84187FF26F1924E2B1F0411310`.
- `nikit_SURFACE-LT_2026-10-14_16_08_09_net10.0.trx`:105/0/0,
  SHA256`8A70D8F32109CA0452D7D137165B530529199EFE4D6897C5162E7B15C645203D`.
- `nikit_SURFACE-LT_2026-10-14_16_08_12_net10.0.trx`:2178/1/7,
  SHA256`4732BA78FA6794101F48552B315D6A033845BD31A275D1548F8009B89BEDCB54`.

Read-only diagnosis: selected PowerShell7.5.4 runs X64/.NET9.0.10, but SDK
10.0.301 is win-arm64. Its package witness cannot LoadFrom the selected ARM64
MSBuild assembly. Native ARM64 PowerShell7.6.5 does load that same assembly;
this is not permission to change the witness version or bypass package checks.
Prepare the official7.5.4 ARM64 tool, inspect its exact version/architecture and
repeat the actual package witness before any new full. A later package failure
is a separate obligation, not inferred fixed by architecture matching.

That follow-up is complete: the official7.5.4 ARM64 archive matches release
SHA256`0c0b2bf04e853917508280531cd49bba8b3049837e3c805ebc042e2741ca52b3`
and pwsh.exe has valid Microsoft Authenticode. It loaded the assembly but could
not enumerate SDK10 types because its .NET9 lacks System.Runtime10. The actual
package-only diagnostic remained0/1/0, native1; TRX SHA256
`484CDCEB3275456A934300EFE4137295FB39AFE7179AA70EB00377954E2F8F52`.
It is under `artifacts/s05-root-continuity-20261014/package-arm64-01/`.

Installed signed native7.6.5/.NET10 ran the same actual package witness, reaching
the underlying package rejection: retired MAU2 is present in assembly bytes.
Inspection found actual PMA1/AuthenticatedMau2 code and MCG2 references, not
merely a stale error message. None was renamed/waived to obtain a PASS.
`package-net10-01` remains0/1/0, native1; TRX SHA256
`BED74551CFE02FF58303F92E9A6504AC831CCF426E729C2681E8383DB5675445`.
The witness selected installed pwsh from the inherited PATH; the supplied
`C:/Program Files/PowerShell/7` directory was absent. This diagnostic is not a
canonical toolchain receipt. The next canonical invocation explicitly selected
the actual executable and recorded its real runtime/architecture.

[DR-0117](../../../docs/survival-program/decisions/DR-0117-sdk10-witness-runtime.md)
now freezes the SDK10-compatible witness contract. A type-load probe rejects
incompatible runtime/architecture before build/full, not just a version string.
The first probe command failed native quoting before run creation; UTF16LE
EncodedCommand fixes argument transport, not checks. Canonical preflight02
completed0/1581 inputs; actual witness7.6.5/.NET10.0.11/Arm64, FullAccepted=false.

Canonical full03 completed **2297/1/7**,2305 exact mappings, two declared
retirements and1581 unchanged inputs; build/preflight/qualification0, native1,
FullAccepted=false. Interval2026-10-14T11:39:16.8986459Z–11:41:57.3883018Z.
The package witness now fails for its real retired-token finding; seven original
provider skips remain. Full receipts under
`artifacts/s05-root-continuity-20261014/full-03/full/`:

- `nikit_SURFACE-LT_2026-10-14_16_40_05_net10.0.trx`:14/0/0,
  SHA256`20782375F1E9D23DE31E22A2AD89DF88D6E127BE02F9135ECCBBF24C2026DCA5`.
- `nikit_SURFACE-LT_2026-10-14_16_40_06_net10.0.trx`:105/0/0,
  SHA256`5110BE9AB856E0EF0D5544539BE5039BA4A5D8886E8291F20A8BF0873ED583F3`.
- `nikit_SURFACE-LT_2026-10-14_16_40_10_net10.0.trx`:2178/1/7,
  SHA256`B27E154076A31DA6C779C4AA6B15C70263A6BB708190F7849DEB0CFA854F2851`.

No further unchanged full is needed merely to restate this known S08 FAIL.
Root-continuity/operational source cases passed, but package shipping acceptance
and S05 retained runtime activation remain unproven. Dev/prod state was not reset.

Next: complete unfiltered source/API/package checks and supported dev renewal
preparation/activation, current issuer/node/client
recovery with retained state and certificates, then S06/device flows. No root
online, backdated time, reinitialized genesis or empty-volume substitute.
