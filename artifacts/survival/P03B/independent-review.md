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
