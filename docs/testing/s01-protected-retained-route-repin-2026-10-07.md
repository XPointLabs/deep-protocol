# S01 protected retained-route contract repin

Date: 2026-10-07. Native custody semantics are owned by
[CONTACT-RESOLVER §3.7.2](../../../docs/architecture/CONTACT-RESOLVER-V1.md#372-independent-retained-read-custody)
and [DR-0103](../../../docs/survival-program/decisions/DR-0103-protected-retained-route-document.md).
The Protocol change is three one-line source/manifest/generated hash updates.
No public API, wire, suite, domain, allocation or approved DNP1 blob changes.
CONTACT normalized source hash is
`2d78055ce201075da4da784f3e8deaaa4af8269073f4e3bef883269054ce2231`.
All176 normative anchors are unchanged; strict registry gate completed0.

Restore and Debug solution build completed0, zero warnings/errors.
The original `dotnet test Deep.Protocol.slnx --no-build --no-restore -m:1
--logger trx --results-directory artifacts/s01-protected-retained-route/full
--verbosity quiet` completed **terminal1:2091/1/7** (2099 executions).
MembershipRoutes14/0/0, ProfileCarrier105/0/0, Protocol1972/1/7.
The unchanged failed case is
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
actual packages retain MAU2. Assertions and skips were not weakened.

Post-terminal standalone qualification completed0: all2099 prior executions
have identical exact name/outcome multiplicities and all2012 prelaunch inputs
are unchanged. The native failure remains a failure; the qualification only
checks preservation, not package approval. The combined test/qualification
wrapper retained native exit1; the independent qualifier read-back exited0.
Original manifest SHA256:
`49ED37346A383172E19440C0C9823F5BD68C4BE4E390F0C4BD5510B3618A70F1`.

| Receipt under artifacts/s01-protected-retained-route/full | SHA256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_16_06_11_net10.0.trx | `0A8E1960DE9060AA7F26907C96FBB1EF19A98DFD35F068DE66C7B517EC07D9A8` |
| nikit_SURFACE-LT_2026-10-07_16_06_12_net10.0.trx | `073C48126522D745244C5456E3A6091C1C0C58FD2105524BEAD0F8A9868BD5FC` |
| nikit_SURFACE-LT_2026-10-07_16_06_16_net10.0.trx | `3F3AB726937750ADD7D3241B55CA59919A02DD8801C197332BDD1F0D2A99EB79` |

Production graph separately completed1 on MAU2 in
`ProductionMailboxAuthorityCodec.cs`. Evidence ownership completed0:
exact314/package219/final95, mapped219/packageMissing0, using the unchanged
approved mapping projection. Static ownership does not mean219 executed
package approvals. This mechanical repin does not close S01, activate retained
issuance, approve shipping composition or demonstrate physical delivery.

The cross-protocol CI specification checkout is repinned to exact superproject
`7ad75940fd565dbc2abfb9656391459619cd151c`, containing the qualified node and
native contract. The separately approved DNP1 snapshot remains
`a8456987efe031388ca2eb9006886fb78f31e06c`. No gate is bypassed; this pin is not
evidence that the new GitHub execution has passed.
