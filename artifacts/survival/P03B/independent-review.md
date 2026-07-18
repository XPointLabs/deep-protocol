# P03B initial independent review and correction map

Reviewer role: independent protocol/security reviewer. Initial verdict: **NO-GO**.
Counts: P0=0, P1=3, P2=1.

| Severity | Initial finding | Corrective evidence |
| --- | --- | --- |
| P1 | Equivocation compared full wire bytes, so alternate valid signatures over one signing statement could become false evidence. | `AlternateValidSignatureOfSameStatement_IsNotEquivocation`; verifier now compares coordinator signing bytes. |
| P1 | Free-admission validity was shape-only and could be returned outside its own window. | `FreeAdmission_MustBeCurrentAndNestedInsideCapabilityWindow`; encode nests and decode checks current bucket before replay evaluation. |
| P1 | Boolean replay API could not distinguish new, exact retry, conflict or stale replay and could not return a cached result. | Explicit four-state evaluation, exact canonical presentation in scope, bounded cached outcome and fail-closed inconsistent evaluations. |
| P2 | Internally valid quorum was not bound to caller-expected request context. | Required `MailboxDurableQuorumExpectation` and substitution tests for operation/generation/payload/tombstone. |

Corrective red commit:
`4150a8d2b5e10e10a57e1784dc05dd030462cd87`.

Corrected source commit:
`6e2c709a378ffac40c441e97e2e4da40aac9a104`.

Post-correction verification: Release build 0 warnings/errors; full 133/133; focused 34/34.
The corrected tree requires an independent rereview before P03B can receive GO. Runtime remains
blocked regardless of review outcome.

## Corrective rereview

Final verdict: **GO**. Counts: P0=0, P1=0, P2=0, P3=0 in corrective scope.

The reviewer independently confirmed:

- all four initial findings are closed by code and regression tests;
- focused rerun passes 34/34;
- recorded full 133/133, focused 34/34, coverage counters and evidence hashes match;
- all three package sizes/SHA-256 values and nuspec source commit
  `6e2c709a378ffac40c441e97e2e4da40aac9a104` match;
- ADR/vector hashes match and the worktree is clean;
- no production crypto, replay persistence, registration, default, deployment or publication was
  introduced.

Residual production risks remain the declared blockers: producer/lifecycle persistence, durable
guard implementation, approved crypto/key distribution, storage/client E2E, cross-language
vectors and external review.
