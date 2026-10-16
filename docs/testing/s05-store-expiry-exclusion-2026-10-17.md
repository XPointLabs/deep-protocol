# S05 original Store expiry verification — source candidate

Owner: Mr. X. Branch: release-candidate/prod-20260909.
Contract: [DR-0134](../../../docs/survival-program/decisions/DR-0134-original-store-expiry-exclusion.md),
semantic owner [XPOINT-NETWORK §9.1](../../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).

The closed host now authenticates permanent expiry of the exact original Store
permission. Common original-request crypto validation is shared with existing
past-settlement verification; quorum validation remains mandatory for settlement.
The new API takes only original bytes and cancellation, returns ValueTask, and
does not admit, reserve, mutate, dispatch, settle or prove noncommit.

Windows PowerShell5.1 / SDK10.0.301 / root Invoke-TestGateNative:

| Ignored receipt | Native exit | Passed / failed / skipped | Scope |
| --- | --- | --- | --- |
| artifacts/s05-store-expiry-20261017/focused-01 | 0 | 124 / 0 / 0 | Initial host/peer-codec affected union |
| artifacts/s05-store-expiry-20261017/focused-02 | 0 | 125 / 0 / 0 | Final union including absent-history refusal |

Both builds have no compiler diagnostics. Coverage includes lower/upper overlap,
exact lower equality, forged expiry/issuer/sender/body/network/writer order,
caller-buffer mutation, missing authenticated history, bounds before clock,
current-host expiry/rollback/boot loss and cancellation. Original expired grant
admission still rejects after successful historical exclusion. These are signed
local fixtures, not a deployed node, device, full-source or package qualification.

Matching native consumers, retained-runtime activation, physical Windows/Android,
canonical full reference qualification and production graph/package checks remain
open. No wire, suite, domain, journal generation, reset or native-provider change.
