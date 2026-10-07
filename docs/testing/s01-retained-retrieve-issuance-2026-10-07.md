# S01 current retained Retrieve Protocol producer

Date: 2026-10-07. Sole semantics:
[CONTACT-RESOLVER §3.7.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md#373-current-retained-retrieve-issuance)
and [DR-0104](../../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
This is a source checkpoint, not S01/runtime/package/device acceptance.

Closed host APIs now verify two independent current ContactResolve descriptor
signatures over the exact retained request/route/capability/horizon transcript,
issue a short current Retrieve grant with the original protected-history PMT2
selection, and verify an exact current issuer result. Author/restore APIs only
create holder-signed request intent; they do not manufacture native owner custody.
Cold winner verification past the request envelope expiry requires a still-current
grant and current host. It never renews a grant or authorizes Store/reranking.

The four new machine inputs are independently hash-bound in the source registry.
No new public magic, suite, grant version or journal generation; approved DNP1
snapshot remains unchanged. Private RPC18 avoids the already occupied12..17.
Root guards test actual Node enum collisions and closed-schema rejection.

Restore and Debug solution build: terminal0, zero warnings/errors.
Final focused solution run: **207/0/0**, including41 new cases. Actual root/PMA2,
signed history, distinct current node keys and issuer/holder signatures are used.
The canonical historical route fixture is deliberately an opaque graph, not
native XPA publication/read-back evidence; coupled Node tests must prove that.
Coverage includes domain/role/key/route/horizon substitution, missing history,
removed original nodes, input capture, callbacks, cancellation and cold winners.

Final full command:

```powershell
dotnet test Deep.Protocol.slnx --no-build --no-restore -m:1 --logger trx --results-directory artifacts/s01-retained-issuance-final/full --verbosity quiet
```

Observed terminal1: **2132/1/7** (2140 executions). MembershipRoutes14/0/0,
ProfileCarrier105/0/0, Protocol2013/1/7. Original MAU2 actual-package failure and
seven existing skips remain unchanged. Standalone post-terminal qualification0
preserves all2099 prior/all207 focused exact name/outcome/execution mappings,
with3023 unchanged immutable prelaunch inputs. The reader excludes only null
rows in two genuinely empty filtered-project TRXs; this correction was frozen
before capture and does not waive counters, definitions or execution IDs.
Final capture SHA256:
`5080B432F227BC0BD4CF958F977548F7AC2A4274CF637D25F9631BF4B7147CBB`.

| Final full receipt | SHA256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_16_53_16_net10.0.trx | `FA6FF92840DD6FC00A568862E0081A84C24C176D3183BBC377A59841AFB54F50` |
| nikit_SURFACE-LT_2026-10-07_16_53_16_net10.0[1].trx | `770CFCAC8D72F221C86D8BEF83950529B0CCD51FD23EDEA5120C87648121F78F` |
| nikit_SURFACE-LT_2026-10-07_16_53_21_net10.0.trx | `B4A3914B57207447E8D9DB12911A693EC870D0AD536611AB42E007B0491B0D55` |

Retained earlier candidate receipts: focused34/0/0; expanded205/2/0 had two
test defects (freshness expired before the target branch; exact format exception
mistyped). Corrected207/0/0 and first full2132/1/7 qualified0 are retained.
Uncommitted RPC12 allocation was then corrected against the actual Node enum;
the separately frozen final run above verifies RPC18 inputs. Root governance
first24/1 and27/1 were fixture-input/diagnostic-expectation defects; final28/0.
No assertions or filters were weakened.

Strict registry gate0; evidence ownership0 (mapped219/packageMissing0) is mapping,
not executed package approval. Separate production graph1 still rejects MAU2 in
ProductionMailboxAuthorityCodec.cs. Root documentation174 checks0, contact
machine check0 and final selected-source scan21 files0. Broad initial scan also
encountered existing raw device screenshots; they remain private, are not part
of this source upload, and were neither deleted nor declared publishable.

After terminal qualification, CI-only cross-protocol checkout is repinned to
root `9f6d123f95583763d3fe99c266fd4ab83ae37cc5`. This post-terminal workflow edit
is not one of the unchanged execution-input claims and does not assert CI pass.
No Node/Registry/Shared runtime changes, Docker topology/data reset, deployment,
GitHub Release or main merge occurred. Actual two protected stores over HTTP,
private issuer replay, owned installation, typed Retrieve/ACK and object horizon
remain the same unfinished S01 batch; physical E2E remains unverified.
