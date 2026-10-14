# S04 — exhausted-PQ recovery control, 2026-10-11

## Scope

This packet implements only the separately authorized **unverified structural
codec target**, owned by [DR-0111](../../../docs/survival-program/decisions/DR-0111-bounded-braid-recovery-control.md)
and its linked machine registry. It adds no recovery activation, MAC verifier,
raw-key author, native/private state, send/ACK API or application bypass. Existing
DPE2/DTR2 and the data exhaustion fence remain unchanged.

The codec validates the borrowed frame before creating its owned snapshot and
validates that snapshot again. Public getters and re-encoding are defensive
copies. Authentication input is a projection, not a verification capability.
Independent manual witnesses execute all four public vectors and all22 declared
negative mutations, plus identifier/boundary/projection/ownership checks.
Synthetic public payload/MAC vectors never count as cryptographic recovery.

## Qualification

`artifacts/s04-braid-recovery-20261011/codec-01`: Windows PowerShell5.1,
SDK10.0.301; Release solution build native0/wrapper0, zero warnings/errors,
2026-10-11T14:21:45.0700702Z–14:22:39.7518487Z. Focused native list declared40
codec/ownership/prerequisite cases; native1/wrapper1,39 passed/1 failed/0 skipped,
2026-10-11T14:23:27.0483822Z–14:23:29.2708837Z. TRX SHA256
`08BE9FE083C9B16CEAB22A102975718704D30F2B1BAA83AD9ABC756CD3CF4E39`.
The projection fixture incorrectly used the existing signed-record helper,
whose suite/length prefix is not DBR2's frozen domain-plus-projection grammar.
Correct only that independent expectation; do not change production bytes.
The diagnostic command also passed the test project, rather than the solution,
to binary-input inventory:1117 source/normative inputs were unchanged, but its
binary closure was incomplete. Preserve this failed diagnostic, not qualification.

`codec-02`: corrected fixture, same production codec; Windows PowerShell5.1 /
SDK10.0.301. Release solution build native0/wrapper0, zero warnings/errors,
2026-10-11T14:24:26.7548641Z–14:24:34.9924120Z. Exact native list/receipt40:
**40 passed / 0 failed / 0 skipped**, native0/wrapper0,
2026-10-11T14:24:53.7239974Z–14:24:56.0249833Z;1550 source/normative and actual
solution binary inputs unchanged. Native UTF-8 list and receipt names matched
exactly through the common runner, not counts alone. TRX SHA256
`F8484372023F1EA9B5BFB87C5EE3899CFAE04E214A5293369BCDCBFB7EB73402`.
Scope:35 structural codec cases, four existing native ownership/boundary/cadence
cases and one current-desktop provider prerequisite. This does not demonstrate
authenticated DBR2 exchange or recovery after exhaustion. The codec-01 FAIL stays
preserved; scopes are not aggregated into a full PASS.

Commands use the root `TestGate.psm1`: `Invoke-TestGateNative` for the Release
`Deep.Protocol.slnx --no-restore -m:1 -warnaserror` build and exact-list/test run
of `tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj --no-build --no-restore`;
filter `FullyQualifiedName~Deep.Protocol.Tests.MessagingWire.Dbr2CodecTests|FullyQualifiedName~Deep.Protocol.Tests.MessagingCrypto.ManagedTripleRatchetNativeOwnershipTests|FixturePreflight=true`.
`Get-TestGateInputs` inventories `Deep.Protocol.slnx`, not the filtered project;
`Read-TestGateReceipt` qualifies exact predeclared identities and unchanged inputs.
Logs/TRX are retained in the two fresh directories named above.

Both new JSON documents additionally passed their own closed JSON schemas using
`Test-Json` under available PowerShell7.6.5 (exit0). This is structural diagnostic
evidence, not the separately required PowerShell7.5.4 executable witness or full
frozen/graph/package gate.

Post-terminal hygiene: `git diff --check` exited0 for root, Protocol, Shared and
DevOps. The existing repository secret scanner checked selected changed/untracked
source files (root15, Protocol16, Shared136, DevOps3), findings0, exit0. No commit,
push, consumer reset, deployment or release was performed in this packet.

## Remaining acceptance

DR-0112 now separately freezes the purpose-separated native control KDF, internal
candidate producer/consumer and generation2 private component layout. Their
source candidate is implemented; qualification below is still pending. The
durable SQL/floor owner, bounded unknown/crash/cancel settlement, dependency/key
retirement and transport activation remain open. Preserve original ciphertext and counters through actual
two-peer exhaustion, lost prior headers, authenticated public exchange and fresh
data-key resumption. Stage acceptance additionally requires required full/frozen
and public API/package evidence and actual downstream consumer repins. The new
public parser surface requires reviewed API/graph snapshots before packaging;
this focused packet does not bless those snapshots or publish/reset consumers.
No Shared, Node, physical device or whole-S04 recovery qualification follows.

## Native component packet

Implemented native scope: connected real-native both-sided32 saturation, lost prior
Header, complete four-flight recovery, unchanged data counters during controls,
actual subsequent bidirectional fresh-data resumption and all64 pending messages
decrypted later without changing their original ciphertext. Additional cases cover
data-piggybacked Header/Ct1 (only second control slots needed), exact replay after
fresh-root installation, forgery/reflection/changed scope with valid outer MAC,
mandatory native Header/Ct2 authenticators, duplicate slots/operations, disposable
uncommitted candidates, clean-break private negatives and independent Node KDF
witnesses. The in-memory fixture re-encodes/reopens TRS1 at every control handover;
it is explicitly not production SQL/floor/transport or physical evidence.
No full/unfiltered or downstream acceptance claim is made for this packet.

`native-01` build native1/wrapper1, zero warnings/six compiler errors across the
solution targets,2026-10-11T14:49:52.8184316Z–14:50:03.5515065Z. Two source causes:
wrong HKDF span overload and an unqualified sibling nested-state error helper.
Corrected the overload to its destination-span form and qualified the existing
helper; no protocol/KDF bytes or tests were weakened. Tests were not launched
against the failed build. Both native registries/vectors and both parser documents
passed their closed schemas under available PowerShell7.6.5 (structural only).

`native-02`: Windows PowerShell5.1 / SDK10.0.301, Release solution build
native0/wrapper0, zero warnings/errors,
2026-10-11T14:51:05.4402867Z–14:51:19.2544459Z. Same native list/test filter as
codec-02 now declares exactly68 cases:35 parser,28 new internal native/KDF
recovery cases, four original native ownership/cadence/boundary cases and one
current-desktop prerequisite. **68 passed / 0 failed / 0 skipped**,
native0/wrapper0,2026-10-11T14:52:53.4206147Z–14:52:56.5020819Z.
Exact UTF-8 declared names/receipt identities matched and all1559 captured
source/normative/actual solution binary inputs remained unchanged. TRX SHA256:
`DF2F61A72B0C83923F5AD7FA896BE4E22FE0533D247B0495C2FA2E1432D5F9AE`.
Commands/runner and binary-inventory solution are the same as codec-02; fresh
run directory is `artifacts/s04-braid-recovery-20261011/native-02`.
All build/test handles are terminal. The failed native-01 build remains preserved.

This qualifies actual native component recovery through cold TRS1 handovers,
not the production durable owner: the privileged in-memory fixture, rather than
SQL/floor/transport authority, commits candidates. Public DBR2 activation remains
false. Original-message preservation is demonstrated by retaining/rechecking all64
original ciphertexts and decrypting them after fresh bidirectional data resumed;
the already received Header-carrying message remains an exact no-plaintext replay.

Post-terminal native-02 diff checks exited0. The existing scanner then found one
`sensitive-assignment` in the newly selected Braid source: its pre-existing local
`seed` is the generated **public** ML-KEM encapsulation-key seed, sent in Header,
not recovery material/private entropy or a literal credential. Rename that local
to `publicSeed` to state its role explicitly; do not weaken scanner rules or
exclude the file. No protocol/algorithm change is made. Retain this failed hygiene
run. Matching `native-03` now has zero-warning/error Release build,
native0/wrapper0,2026-10-11T14:59:21.3342210Z–14:59:36.6293730Z, and exact
**68/0/0**, native0/wrapper0,2026-10-11T15:01:51.0312984Z–15:01:53.8638120Z,
all1559 inputs unchanged, exact UTF-8 native list/receipt identities matched.
TRX SHA256 `497DDEB3494B34688E10C2A6BBA4BEDCD29E4BF8FE3C8D98F7618C26F43F6D88`.
Same commands/filter, fresh `artifacts/s04-braid-recovery-20261011/native-03`;
no build/test handle remains live. Post-terminal scanner: root20, Shared136,
Protocol22, DevOps3 selected source files, findings0, exit0. No commit, push,
consumer reset, deployment or release was performed in the native packet.

## Closed durable Protocol boundary (DR-0113)

[DR-0113](../../../docs/survival-program/decisions/DR-0113-owned-braid-durable-boundary.md)
separately freezes the control-specific public plan/prepared/authority/completion/
receipt/success API. It reuses the existing store snapshot and commit dispositions,
not ordinary DPE2/DMC2 bytes or message-key deletion evidence. The actual native
producer owns the successor; receipts bind exact plan plus callback attempt.
Prepared retries after unknown callback outcome keep the original exact frame;
receive replay needs retained durable authority and cannot come from native replay
alone. Capability constructors are internal, defensive state copies are wipeable,
and disposal during callbacks defers wiping until the callback finishes.

Sixteen new native boundary cases join the previous68: both32-saturated senders
with/without prior Header delivery, all four durable callback flights followed by
fresh bidirectional data and unchanged pending messages, unknown committed callback
retry, pre-callback cancellation, cross-plan/old-attempt receipts, single-flight/
deferred disposal, three terminal dispositions, missing durable replay history,
changed claimed replay and four invalid predecessor/checkpoint/capacity contexts.
These are privileged in-memory Protocol authority tests, not SQL/device acceptance.

`artifacts/s04-braid-recovery-20261011/durable-02`: build0 with zero warnings/errors,
exact84/0/0,native0/wrapper0,1562unchanged inputs,
TRX SHA256 `AC4211D551322FB24B3AD83CF202B100B8E0BCD3AB5DD00B6E1938E68DFD79F0`.
The later Shared mapping decision updates were followed by matching requalification:
`durable-03`, build0/zero warnings/errors at
`15:56:31.2117339Z`–`15:56:34.2516565Z`; exact84/0/0,native0/wrapper0,
`15:56:58.5841387Z`–`15:57:01.9378069Z`,1562unchanged inputs and identical
predeclared UTF-8 native case identities.
TRX SHA256 `5F5274952B98FA6A2DA33A1644330181B2CA36B0D36A79E565DBCA669463DB2F`.
Same solution/project/filter and common runner as native-03, fresh run directories.

The actual Shared SQL/floor join and preserved failed/corrected scopes are recorded
in [the Shared checkpoint](../../../deep-client-shared/docs/testing/s04-braid-durable-2026-10-11.md).
Unknown-control dependency/key retirement, control transport/admission/ACK,
API/package/frozen/full and physical activation remain open. This packet does not
qualify the complete S04 stage or release; public DBR2 activation stays false.

## Pinned data frontier and second-output ordering

The DR-0112 clarification preserves the existing wire/KDF/layout and two-link
bound. A new output rejects before link KDF/replacement if the oldest retained
link still names either current data frontier. Ordinary receive derives its
message and old skipped keys before installing the Braid output carried by that
message. Both happen in the same uncommitted cloned candidate.

The new real-native case first completes output1 with withheld epoch0 data,
then rejects the exact output2 control twice while the receive frontier is still0,
without changing the committed digest. Actual ordinary epoch1 data completes
output2 after deriving its old skipped keys; subsequent bidirectional epoch2
data and both original epoch0 envelopes decrypt after cold state handovers.
The unknown earlier DBR2 operation is not relabelled delivered by this data step.

Fresh `artifacts/s04-braid-recovery-20261011/history-01`:
build0/zero warnings/errors, `16:23:33.2520795Z`–`16:24:27.8124741Z`;
exact85/0/0, native0/wrapper0, `16:25:29.9783607Z`–`16:25:33.5071552Z`,
1562 unchanged inputs and exact predeclared UTF-8 native case identities.
TRX SHA256 `EBAFFFFA56D39F9FDA87E9E4A60F6FB1FDA0464B0DF85B95207E1467D3BDC968`.
Same native ownership/DBR2/prerequisite filter and common runner as durable-03.
This is a matching focused component/boundary run, not full/API/package or
physical qualification. The matching real SQL/protected-history scope is in
the Shared checkpoint linked above.

## DR-0114 read-only obsolete-purpose boundary and closed API

The separately allocated `TryVerifyObsoleteControl` returns a sealed immutable
public predecessor/hash capability only after actual installed SPQR output and
original-root whole-control MAC authentication. It does not call Braid.Receive,
consume a native slot, advance state, mint receive/commit success or grant ACK.
The actual Shared SQL/ACK owner rederives it under lease; see DR-0114 and the Shared
checkpoint. Retired roots return no proof rather than reconstructed keys.

Actual-native tests finish the first Braid through ordinary data without the old
DBR2 operation, authenticate the first obsolete frame twice with unchanged state,
reject changed MAC, reflection, non-Fresh/mismatched checkpoint and consumed native
replay without durable custody, then resume fresh bidirectional data. A second
actual output after both data frontiers advance removes root0 and cannot mint
that original-root proof. The assembly API surface gate now lists only DR-0113's
eight allocations and DR-0114's sealed capability, with closed constructors,
read-only properties and the producer's exact three methods. No raw-key API,
new wire/KDF/private layout or activation is introduced.

Fresh `artifacts/s04-braid-recovery-20261011/mailbox-01`:
build0/zero warnings/errors, `17:49:48.9997758Z`–`17:50:50.9092703Z`;
native1/wrapper1,86passed/1failed/0skipped out of87,
`17:53:18.1790468Z`–`17:53:23.1035007Z`,1565 unchanged inputs;
TRX SHA256 `79A6566F401226E46B78E066D8A210644710082F647CC334770A1F9D5115369E`.
Preserved harness FAIL: the new reflection assertion expected exact generic
CryptographicException, but the correct scope rejection is the concrete
MessagingCryptoException. The test now asserts that exact class; runtime rejection
was not weakened or changed.

Fresh `mailbox-02`: build0/zero warnings/errors,
`18:12:10.3299533Z`–`18:12:23.2465522Z`; exact91/0/0,native0/wrapper0,
`18:14:25.4742432Z`–`18:14:28.9702071Z`,1565 unchanged inputs;
TRX SHA256 `FAF6A6F3C185E0CB9FE8C5A3F3B36F3E3B87E42F20C7A3B6CC05E58C2E2CDE6F`.
Scope: DBR2 codec, all managed native ownership cases (including three new obsolete
cases), MessagingCryptoSurfaceTests and current prerequisites. Common native
UTF-8 predeclared case identities match the receipt exactly. No sum with earlier
receipts or full/package/downstream/physical qualification is claimed; shipping
and S04 acceptance remain gated. All processes are terminal.

## Registry producer closure (2026-10-13)

Strict generation initially rejected the current S04 source because DBR2 was
absent from the global compiled registry and manually authored in Dbr2Codec and
ManagedBraidControlProfile. The already accepted DR-0111 allocation now binds
to its exact frozen braid-recovery-v2 machine source and the human registry row.
Both producers use ProtocolMagicBytes.DBR2; framing, bytes, KDF and activation
remain unchanged. No literal exclusion, compatibility author or RELEASE_ACTIVE
allocation was introduced. The generated identifiers, resolved manifest and
graph policy were regenerated with the existing strict generator.

Reviewed normative source diffs required three source hash repins and125 existing
line/hash anchor repins. After DBR2 registration and the production inventory
update, strict -Check passes; source dry-run reports0 stale hashes and the anchor
tool validates177 anchors with0 remaining repins. Approved DNP Git blobs were not
repinned. The frozen DBR2 wire/vector files were not edited in this correction.

The shared input runner now also captures repository registry files. Its genuine
inventory fixture verifies inclusion and byte-substitution detection; all37
common runner contracts pass in Windows PowerShell5.1. This changes gate input
coverage, not outcome classification or native-exit acceptance.

The producer Release build finished0/zero warnings/errors at
2026-10-13T11:04:13.8175751Z–11:04:56.5848807Z. Matching scoped registry/DBR2/
native-control qualification, downstream rebuild and mandatory stage full are
still required. The known actual shipping graph failure remains S08 under DR-0095.

The first focused run reported76/0/0/native0, but its fixed logger filename
overwrote the two empty filtered-project receipts. Keep that orchestration
limitation visible; it is not complete multi-project qualification. The same
unchanged binaries were rerun in fresh connected-02 with distinct native TRX
files. Common Test-TestGateResults qualified76/0/0, native0/wrapper0, exact76
case/method/execution bindings and two explicitly zero-counter empty receipts,
with1573 unchanged inputs, at
2026-10-13T11:09:42.3807984Z–11:09:46.4541158Z. Receipt SHA256 values:

- `EA111A70FE399012CC91214354A77BA1861BE3A7B2D306B919347784831A161B`;
- `EEA1937364DE1CFD805008BE870F23BC98006730D03D062ABC9A948AB99F0B39`;
- `885E8598AC52FA3CBD9DD047CC0C80B9412E39CC1F30341AA1C9A6FFDEBC5EB5`.

Scope is generated registry, DBR2 frozen positive/negative vectors, native Braid
recovery/private custody and independent KDF witnesses, plus approved provider
preflight. The returned focused FullAccepted flag covers only those76 cases;
it is not an unfiltered source or shipping qualification. Current mandatory
full/API/consumer review, separate commits/push and physical gates remain open.

Canonical full preparation01/02 stopped before the runner because a display-name
comparison against --list-tests was not valid for four deferred/nonserializable
frozen-vector theory families. Their runtime rows and two display-name collisions
require the existing stable case/method/execution mapping, not guessed discovery
names. No frozen vectors or historical receipts were changed. Reference-main-01
captured2167/1/6,2174 actual cases and two empty receipts; its wrapper1 remains:
the declaration prefix omitted Deep.Protocol.DeepNative and the filtered scope
does not contain the separate operator-only capture test. It is reference
preparation, not full acceptance. Comparing actual old/current TRX proves that
all original main-project cases remain, except that excluded operator case.

The exact union of three prior full receipts and three current captured receipts
declares2294 stable case keys. Preparation03 stopped before runner launch because
the default bundled pwsh is7.6.5. The already present portable PowerShell7.5.4
was verified and passed explicitly as WitnessPowerShellPath; no interpreter was
installed and no version condition relaxed.

Canonical full04 completed at
2026-10-13T11:36:18.1972148Z–11:38:56.3216408Z with build/preflight0,
native1/qualification0:2286 PASS/1 original package FAIL/7 original named skips,
exact2294 method/case/execution mappings and1579 unchanged captured inputs.
Witness PowerShell7.5.4, runner Windows PowerShell5.1.26100.9457, SDK10.0.301.
No new failure or skip was allowed. Source MatrixQualified=true but
FullAccepted=false remains because actual shipping closure is still red under
DR-0095. Full receipt SHA256 values:

- `831AFAE2C679FE482EAA10A2C64DE700E1CD2F85FD7F3E57F1F31F22DC289CAD`;
- `AF3F792F306802C3C5E35FA4BAC7ABFC039DC3A11E04E76E7FD335DBC47BA1B7`;
- `2A026C186C66EA692BA40A4DE9FF31D3D9DA333388F60199ED6EF8CA975C462B`.

This qualifies the stated current source matrix without waiving the package or
platform/operator gates. Downstream current Shared full/MAUI requalification,
review, commits/push and installed production/device evidence remain required.
