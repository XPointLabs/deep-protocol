# S01 exact acquisition request binding — source gate

Date: 2026-10-07. Sole wire/API owner:
[DR-0102](../../../docs/survival-program/decisions/DR-0102-exact-mailbox-request-route-binding.md)
and [CONTACT-RESOLVER §3.7](../../../docs/architecture/CONTACT-RESOLVER-V1.md#37-mailbox-grant-acquisition).
Author, current issuer/result/restore and closed retained-request consumers now
agree on the holder-signed exact route. There is no old reader or conversion.
XMC2/MCG3/PMA2 framing, primitives, approved DNP1 blob and generated DNP1 type
allocations are unchanged. Rebuild/repin all downstream consumers together;
old protected requests reject, without automatic reset or reminting.

Debug solution build: terminal0, zero warnings/errors. Final focused110/0/0,
terminal0; current positive XMG2 vector has a real verified holder signature.
The three new facts cover old magic/domain, both request roles' signed exact
route intent and result route substitution. Strict registry gate0:176 anchors,
44 DNP1 allocations,245 magics,10 suites,5 carriers,4 profiles,11 aliases.
Reviewed normative hash/line repin changes no approved DNP1 bytes.

The original `dotnet test Deep.Protocol.slnx --no-build --no-restore -m:1
--logger trx --results-directory artifacts/s01-exact-request-binding/full
--verbosity quiet` completed **terminal1:2091/1/7**,2099 executions:
MembershipRoutes14/0/0, ProfileCarrier105/0/0, main1972/1/7.
The unchanged failure is
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
the actual package contains retired MAU2. ProductionProtocolGraph separately
completed1 on that same retired token. Neither assertion nor skip was weakened.

The original prelaunch manifest remains intact:2008 source/normative/executed
binary inputs, SHA256 `E8BDD6649A8AE5D7C700A8F0F983034745F2442CF96994887962C91DD4CC9E14`.
Post-terminal qualification completed0, verifying every input unchanged and all
2096 prior executions/2094 exact name-outcome multiset keys, with two explicit
current XMG case renames. Initial validator assumptions rejected normal xUnit
theory-template execution IDs and repeated display names. The corrected
validator still maps every unique result execution to its TestEntry and exact
method/test ID; it counts duplicate names rather than dropping executions.
Original validator/hash `4813247CDA471074F96C9D055A766F953AE015FB35F37AE8063C832DC8E5C647`
was not reminted. The post-terminal validator is separately pinned:
`807E0B11BED41FC0114E5B7693B262D36697CACF1CBC181101AAB3A7BDF19DCD`.

| Receipt under artifacts/s01-exact-request-binding | SHA256 |
| --- | --- |
| focused-final/focused-final.trx | `640727A511341E0BE194DB8BDB50A8999552D2D57EC2CF8A6C9130B4A987CC38` |
| full/nikit_SURFACE-LT_2026-10-07_12_59_04_net10.0.trx | `7F3C5F6873C056ECFBBB961EDE75936C4FDEA2573AEDCE449478A1DC3FE73FEA` |
| full/nikit_SURFACE-LT_2026-10-07_12_59_05_net10.0.trx | `B55999D31C27C0C448358090A5B4FC735593EF751CFF7528DF343F928F88E3F7` |
| full/nikit_SURFACE-LT_2026-10-07_12_59_09_net10.0.trx | `46C6B7C36E31082E10069BCAF2CC71F0D5859ABC5E45D0B57FACEFC19ADE00C8` |

Evidence-ownership gate0: exact314/package219/final95, mapped219/missing0,
using a mechanical projection of the existing approved executable mapping.
Static mapping is not219 executed package approvals. This is bounded source
qualification under DR-0095, not green package or S01 acceptance. Protected
retained custody, two-store retained evidence, renewed issuer/holder, node
Retrieve/ACK and object horizon remain unfinished. No production deploy/reset,
GitHub Release, main merge or physical delivery claim occurred.
