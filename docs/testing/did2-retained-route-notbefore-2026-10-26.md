# Exact retained route threshold scheduling — 2026-10-26

Implementation of the accepted bounded scheduling clarification in root
[DR-0078](../../../docs/survival-program/decisions/DR-0078-did2-owned-publication-renewal.md).
The existing wire/journal formats and `VerifyRetainedThresholdAsync` signature
are unchanged. No publication, profile upgrade or connected acceptance is granted.

## Closed validation boundary

`DeepIdV2RouteNotBeforeException` has no public constructor. Its only added public
property is the read-only `RequiredDelaySeconds`, a checked relative whole-second
duration. It exposes no trusted lower/upper, request, threshold or verification
context. Catching it grants scheduling only; a caller must repeat full verification
of the same exact request/response under its original deadline.

Only retained-threshold verification may defer a PMS2/XRC1/XSS1 future start that
lies at/below the current trusted upper. Invalid intervals, expiry and future
starts beyond upper reject immediately. Every threshold record is checked, so an
earlier future start cannot hide a later expiry. The verifier still authenticates
the exact request, issuance ADH1, scope, predecessor ancestry, selection graph and
all threshold signatures. XRA, device, delegation, network, head and authority
currentness remain strict. No generic cryptographic-error catch or message match
creates the hint.

Both actual-clock contexts undergo full validation. A private accumulator for
the FINAL context computes `max(futureStart) - trustedLower`; the first context's
duration is discarded. If time converges before final validation, ordinary success
returns without a hint. Signature, boot, cancellation, currentness or other failure
returns no hint. Other route verifiers and authoring retain the strict original
`start <= lower && upper < expiry` predicate.

The Shared owner owns any cancellable bounded wait and actual post-wait protected
root/key/floor/revocation/time rejoin. Protocol neither waits nor extends a lease,
changes clocks, remints a request or preserves admission across a callback.

## Evidence status

Focused Protocol boundary tests cover the three eligible artifacts, mixed expiry,
beyond-upper and inverted intervals, latest-start/final-context recalculation,
integer overflow and the closed public surface. Existing strict coverage tests
remain unchanged. Genuine signed-response and retry-loop validation belongs to
the coordinated Shared fixture and must cover invalid signatures, expiry, exact
request/response retention, deadline/cancellation and post-wait custody changes.

The fresh `focused-02/` PS5.1 Release gate passed: build native0 with zero
warnings/errors, required production graph native0, and 34 tests PASS / zero FAIL /
zero SKIP (test native0). The filter contains only `DeepIdV2RouteNotBeforeTests`
and the existing `DeepIdV2RouteTimeCoverageTests`. All 1,695 captured source,
binary, normative and tooling inputs remained unchanged; source also remained
unchanged during the build. This is boundary-unit/strict-API evidence, not genuine
full signed-verifier, integrated retry or connected acceptance. New public
exception adoption requires rebuilding/repinning affected consumers; no automatic
package publication or live upgrade is performed.

The first focused attempt built Release with zero warnings/errors (native0),
then stopped before tests at the positive production API snapshot (graph native1).
That failure is preserved in `artifacts/did2-retained-route-notbefore-20261026/focused-01/`.
Approved snapshot adoption inspected decoded metadata against the previously
accepted Debug assembly: exactly three added rows (sealed exception, UInt32
getter and readonly property), zero removed rows, no public constructor, resource
or assembly-reference change. The exact current Debug/Release raw snapshots
replace both predecessor hashes; no gate or broad allowlist is disabled.
Inspection and the bounded zero-warning Debug production build are retained in
`api-adoption/` under the same artifact prefix.
