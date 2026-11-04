# Route history development checkpoint — 2026-11-04

Normative allocation: [DR-0178](../../docs/survival-program/decisions/DR-0178-paged-route-history-and-current-promotion.md).
This checkpoint supplies count8 framing, bounded historical facts/step/page
verification, separate current announcement qualification, typed authoring,
native-checkpoint facts restoration and parse-only original-atom bridges.
The native owner must independently authenticate actual custody and C/P/L decisions.

`artifacts/route-history-20261104-build04`: Release solution, zero warnings/errors,
source inputs unchanged. `artifacts/route-history-20261104-focused02`:123 PASS,
zero failures/skips, source and binary inputs unchanged. This consists of67 new
history framing/structural/ownership cases plus56 existing recovery/current
contact regressions. These structural fixtures do not prove signatures, durable
adoption, transport, physical devices or connected delivery. The original
focused01 receipt (96PASS/2FAIL from fixture capability bindings) is preserved.

Follow-up `build05` and `focused03` also passed with zero warnings/errors and
123 passing cases, with unchanged captured inputs. The atom now exposes defensive
copies of its already parsed original XRC/XSS bytes, so Shared can derive F7
identities without duplicating response wire offsets or inventing request data.
These parse-only getters grant no verification or route authority.

`build06` passed the Release solution with zero warnings/errors and1293 source
inputs unchanged. `focused04` passed the same123 cases with zero failures/skips
and1726 captured source/binary inputs unchanged after removing the unused public
fresh6/7 author and its result type. Existing retained6/7 parsers and verifiers
remain; fresh owned controls use count8.

`artifacts/route-history-20261104-metadata01` rebuilt normal Debug and the graph
executable from current source, then invoked that executable's actual
`CreateSnapshot`. The accepted baseline assembly SHA256 is
`FEE4396B9BF87D9144B3701DA6C7238BC136D3238935E25869BCF662ED0966BA`;
its measured snapshot exactly matches the accepted12992-row Release fingerprint.
Current decoded metadata adds183/removes9 rows, net174: the previously reviewed
`247a483`/`482a1bc` changes add104/replace3 (net101); DR-0178 adds79 rows
(initial75 plus two property/getter pairs); fresh6/7 author removal subtracts6.
New verified history/fact types have no public constructors. The two added data
constructors belong to the previously reviewed recorded-pair/recovery-wire data
types, and confer no verification, signing, route or native custody authority.

Normal Debug and Release decoded surfaces are identical
(`B588A0AFFB130721DC994530EE4F611FA4268D6E08D060F106E8ACECA2DC943E`).
Assembly references and embedded resources exactly match the accepted baseline.
Only Deep.Protocol's normal snapshot entries are repinned:

- Debug: `Deep.Protocol|13166|72E6B517E24F21C168FFD35FCCC8E7EF4053B4A44CDFA657DCC05EAFDD8BED15`
- Release: `Deep.Protocol|13166|46EDBDCC87665C622468C729691957A926AB1BA9CBEA5B233C232202C6F19A67`

Metadata01 captured1295 unchanged source inputs and1744 unchanged metadata/binary
inputs. Its initial graph invocations rejected only the obsolete Deep.Protocol
fingerprints; the fresh executable did not reproduce the stale PSR1 rejection.
The audit retains complete decoded additions/removals and `surface-review.json`.
The suggested Oct28 runtime04 assembly path currently contains the same accepted
12992-row baseline; it is not evidence of an intermediate13093-row assembly.

The BIP39 resource remains exactly13116 LF bytes, SHA256
`2F5EED53A4727B4BF8880D8F3F199EFC90E58503646D9FF8EFF3A2ED3B24DBDA`.
A single targeted `.gitattributes` rule preserves those existing bytes on future
checkouts. The detached CRLF copy is not an accepted normal-resource snapshot.
`artifacts/route-history-20261104-metadata02` rebuilt the graph executable after
the reviewed repin. Normal Release and Debug graph checks both exited0;
1295 source inputs and1744 metadata/binary inputs remained unchanged.
This diagnostic does not qualify the full source suite or package/runtime gates.

The later canonical `route-history-20261104-full02` source gate is accepted:
2640 passed, zero failed, seven explicitly declared platform/operator skips;
2647 exact required cases, build/preflight/native/qualification exits all zero,
1743 captured inputs unchanged. PowerShell5.1, SDK10.0.301 and the separate
PowerShell7.6.5/.NET10 witness interpreter were recorded by the runner.
The package ZIP/assembly/resource/API witness, including its hostile-package
checks, passed as part of this run. The six standalone native-wrapper cases
and one authenticated operator-capture case remain outside this accepted matrix.

The original full01 receipt remains unaccepted (2636 passed, four failed, seven
skipped). Three obsolete surface/codec expectations were reconciled with the
existing typed group and route-recovery contracts, retaining generic-author,
raw-key/delegate escape and nonforgeable-capability checks. The two exact case
identity substitutions are owned by the root
`docs/architecture/PROTOCOL-QUALIFICATION-BINDINGS-2026-11-04.md`.

The package witness's two dependent assembly fingerprints were reviewed against
actual retained normalized packages and their source DLLs. Public APIs/resources
match the normal assemblies and accepted runtime baseline; the sole snapshot-row
delta is `Deep.Protocol` AssemblyRef `1.0.0.0` to the witness version `0.0.0.0`.
Only those two measured witness fingerprints were added. Normal fingerprints and
validation rules are unchanged. The audit receipt is
`artifacts/route-history-20261104-package-audit01/audit.json`, SHA256
`9A75EFD37CE7102782AFB4A299B23F03C79D9441673E942E4F7FCD699F239652`.
An optional `-KeepArtifacts` preserves disposable witness outputs for direct
inspection; its default cleanup and all verification remain unchanged.

Remaining: combined Shared runtime/source qualification, same-profile CLI
catch-up and delivery measurements, and separately required native/operator and
release evidence. Source/package-witness acceptance does not establish runtime,
performance or release readiness.
